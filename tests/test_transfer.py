import socket
import struct
import threading
import time
from pathlib import Path

import pytest

from lancast.transfer import (
    FILENAME_LEN_FMT,
    PAYLOAD_LEN_FMT,
    STATUS_BAD_FRAME,
    STATUS_FMT,
    STATUS_TOO_LARGE,
    STATUS_WRITE_FAILED,
    ProtocolError,
    TransferRefused,
    _recv_exact,
    receive_file,
    send_file,
)


def _socket_pair() -> tuple[socket.socket, socket.socket]:
    """Create a connected pair of TCP sockets over loopback for testing."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", port))
    server, _ = listener.accept()
    listener.close()
    return client, server


def test_send_and_receive_round_trip(tmp_path: Path) -> None:
    src_file = tmp_path / "hello.txt"
    src_file.write_text("hello over TCP")

    client, server = _socket_pair()
    try:
        sender_thread = threading.Thread(target=send_file, args=(client, src_file))
        sender_thread.start()

        dest_dir = tmp_path / "received"
        received_path = receive_file(server, dest_dir)
        sender_thread.join(timeout=2)

        assert received_path.name == "hello.txt"
        assert received_path.read_text() == "hello over TCP"
    finally:
        client.close()
        server.close()


def test_receive_file_strips_path_components(tmp_path: Path) -> None:
    """A malicious/buggy peer sending '../../etc/passwd' as a filename
    must not escape dest_dir -- only the basename should be used."""
    src_file = tmp_path / "payload.bin"
    src_file.write_bytes(b"binary data")

    client, server = _socket_pair()
    try:
        name_bytes = b"../../evil.txt"
        header = struct.pack(FILENAME_LEN_FMT, len(name_bytes)) + name_bytes
        payload = b"binary data"
        header += struct.pack(PAYLOAD_LEN_FMT, len(payload))

        def _send_raw():
            client.sendall(header)
            client.sendall(payload)

        sender_thread = threading.Thread(target=_send_raw)
        sender_thread.start()

        dest_dir = tmp_path / "received"
        received_path = receive_file(server, dest_dir)
        sender_thread.join(timeout=2)

        assert received_path.parent == dest_dir
        assert received_path.name == "evil.txt"
        assert not (tmp_path / "evil.txt").exists()
    finally:
        client.close()
        server.close()


def test_receive_file_raises_on_early_close(tmp_path: Path) -> None:
    client, server = _socket_pair()
    try:
        # Send a header promising more bytes than we actually send, then close.
        name_bytes = b"partial.txt"
        header = struct.pack(FILENAME_LEN_FMT, len(name_bytes)) + name_bytes
        header += struct.pack(PAYLOAD_LEN_FMT, 1000)
        client.sendall(header)
        client.sendall(b"only a few bytes")
        client.close()

        with pytest.raises(ProtocolError):
            receive_file(server, tmp_path / "received")
    finally:
        server.close()


def test_receive_file_rejects_suspicious_filename_length(tmp_path: Path) -> None:
    client, server = _socket_pair()
    try:
        header = struct.pack(FILENAME_LEN_FMT, 10_000_000)  # absurdly large
        client.sendall(header)

        with pytest.raises(ProtocolError):
            receive_file(server, tmp_path / "received")
    finally:
        client.close()
        server.close()


def test_recv_exact_across_multiple_packets(tmp_path: Path) -> None:
    """Simulate TCP delivering data in small fragments across several
    recv() calls -- _recv_exact must still assemble the full payload."""
    client, server = _socket_pair()
    try:
        payload = b"x" * 500

        def _send_in_chunks():
            for i in range(0, len(payload), 50):
                client.sendall(payload[i : i + 50])

        sender_thread = threading.Thread(target=_send_in_chunks)
        sender_thread.start()

        result = _recv_exact(server, len(payload))
        sender_thread.join(timeout=2)

        assert result == payload
    finally:
        client.close()
        server.close()


# ---------- regression tests for receiver hardening ----------

def _send_header(client: socket.socket, name_bytes: bytes, payload_len: int) -> None:
    header = struct.pack(FILENAME_LEN_FMT, len(name_bytes)) + name_bytes
    header += struct.pack(PAYLOAD_LEN_FMT, payload_len)
    client.sendall(header)


def _read_status(client: socket.socket) -> int:
    client.settimeout(2)
    return struct.unpack(STATUS_FMT, client.recv(1))[0]


def test_oversized_payload_is_refused_before_any_payload_is_read(tmp_path: Path) -> None:
    """Before: payload length was unbounded, so a peer could claim 2^60 bytes
    and stream until the receiver's disk or memory ran out."""
    client, server = _socket_pair()
    try:
        _send_header(client, b"huge.bin", 2**60)
        with pytest.raises(TransferRefused):
            receive_file(server, tmp_path / "received", max_payload_bytes=1024)
        assert _read_status(client) == STATUS_TOO_LARGE
        assert not (tmp_path / "received").exists() or list((tmp_path / "received").iterdir()) == []
    finally:
        client.close()
        server.close()


@pytest.mark.parametrize("bad_name", [".", "..", "some/dir/..", "..\\..", "evil\x00.txt"])
def test_dot_and_nul_filenames_are_rejected(tmp_path: Path, bad_name: str) -> None:
    """Before: Path('..').name is '..', so it slipped past the basename strip
    and raised an unhandled IsADirectoryError when written."""
    client, server = _socket_pair()
    try:
        _send_header(client, bad_name.encode("utf-8"), 5)
        with pytest.raises(ProtocolError):
            receive_file(server, tmp_path / "received")
        assert _read_status(client) == STATUS_BAD_FRAME
    finally:
        client.close()
        server.close()


def test_backslash_path_components_are_stripped(tmp_path: Path) -> None:
    """Windows-style separators must be stripped too, whatever OS receives."""
    client, server = _socket_pair()
    try:
        _send_header(client, b"..\\..\\evil.txt", 4)
        client.sendall(b"data")
        received_path = receive_file(server, tmp_path / "received")
        assert received_path == tmp_path / "received" / "evil.txt"
    finally:
        client.close()
        server.close()


def test_invalid_utf8_filename_raises_protocol_error(tmp_path: Path) -> None:
    """Before: a UnicodeDecodeError escaped, which the server didn't catch."""
    client, server = _socket_pair()
    try:
        _send_header(client, b"\xff\xfe\xfd", 5)
        with pytest.raises(ProtocolError):
            receive_file(server, tmp_path / "received")
    finally:
        client.close()
        server.close()


def test_existing_file_is_never_overwritten(tmp_path: Path) -> None:
    """Before: a second file with the same name silently replaced the first."""
    dest_dir = tmp_path / "received"
    dest_dir.mkdir()
    (dest_dir / "report.txt").write_text("original")

    client, server = _socket_pair()
    try:
        _send_header(client, b"report.txt", 3)
        client.sendall(b"new")
        received_path = receive_file(server, dest_dir)
        assert received_path.name == "report (1).txt"
        assert (dest_dir / "report.txt").read_text() == "original"
    finally:
        client.close()
        server.close()


def test_interrupted_transfer_leaves_no_partial_file(tmp_path: Path) -> None:
    client, server = _socket_pair()
    try:
        _send_header(client, b"partial.bin", 1000)
        client.sendall(b"only a few bytes")
        client.close()
        with pytest.raises(ProtocolError):
            receive_file(server, tmp_path / "received")
        assert not (tmp_path / "received" / "partial.bin").exists()
    finally:
        server.close()


def test_stalled_connection_times_out(make_device, running_server) -> None:
    """Before: no timeout, so a client that connected and sent nothing held
    a server thread forever."""
    receiver = make_device("receiver")
    receiver.trust_store.trust(make_device("friend").cert_pem, name="friend")
    server = running_server(receiver, connection_timeout=0.3)

    stalled_client = socket.create_connection(("127.0.0.1", server.port))
    try:
        deadline = time.time() + 3
        while not server.rejected and time.time() < deadline:
            time.sleep(0.05)
        assert server.rejected, "server never gave up on the stalled connection"
    finally:
        stalled_client.close()


def test_connections_beyond_concurrency_cap_are_dropped(make_device, running_server) -> None:
    """Before: one thread per connection with no limit, so opening many
    connections could exhaust the receiver's threads."""
    receiver = make_device("receiver")
    receiver.trust_store.trust(make_device("friend").cert_pem, name="friend")
    server = running_server(receiver, max_concurrent=1, connection_timeout=5)

    first_client = socket.create_connection(("127.0.0.1", server.port))
    second_client = socket.create_connection(("127.0.0.1", server.port))
    try:
        second_client.settimeout(2)
        assert second_client.recv(1) == b""  # server closed it right away
        assert any("Too many concurrent" in str(error) for error in server.rejected)
    finally:
        first_client.close()
        second_client.close()


# ---------- the file or the destination changes under us ----------

class _ShrinkingFile:
    """Stands in for a file that a sender stat()s at N bytes, but which some
    other process truncates before all N bytes are read."""

    def __init__(self, real_path: Path, readable_bytes: int) -> None:
        self._handle = open(real_path, "rb")
        self._left = readable_bytes

    def read(self, size: int) -> bytes:
        data = self._handle.read(min(size, self._left))
        self._left -= len(data)
        return data

    def __enter__(self):
        return self

    def __exit__(self, *exc_info) -> None:
        self._handle.close()


def test_sender_stops_at_declared_size_when_file_grows(tmp_path: Path, monkeypatch) -> None:
    """Before: send_file streamed until EOF, so bytes appended after the
    header was sent spilled past the frame and the receiver saved a file that
    didn't match the length it was promised."""
    src_file = tmp_path / "growing.log"
    src_file.write_bytes(b"a" * 10)
    real_stat = Path.stat

    def stat_before_growth(path: Path, *args, **kwargs):
        result = real_stat(path, *args, **kwargs)
        if path == src_file:
            # Header goes out claiming 10 bytes; then the file grows to 20.
            src_file.write_bytes(b"a" * 10 + b"b" * 10)
        return result

    monkeypatch.setattr(Path, "stat", stat_before_growth)

    client, server = _socket_pair()
    server.settimeout(2)
    try:
        sender_thread = threading.Thread(target=send_file, args=(client, src_file))
        sender_thread.start()
        received_path = receive_file(server, tmp_path / "received")
        sender_thread.join(timeout=2)

        assert received_path.read_bytes() == b"a" * 10
        # Nothing extra is left in the stream after the frame.
        client.shutdown(socket.SHUT_WR)
        server.settimeout(2)
        assert server.recv(1) == b""
    finally:
        client.close()
        server.close()


def test_sender_reports_file_that_shrinks_mid_send(tmp_path: Path, monkeypatch) -> None:
    """Before: the sender hit EOF early, then waited for a final status the
    receiver would never send (it was still waiting for payload), and the
    user saw a timeout instead of the real cause."""
    src_file = tmp_path / "shrinking.bin"
    src_file.write_bytes(b"x" * 100)
    real_open = open

    def open_shrinking(path, mode="r", *args, **kwargs):
        # Only the sender's read is affected; the receiver writes normally.
        if Path(path) == src_file and mode == "rb":
            return _ShrinkingFile(path, readable_bytes=40)
        return real_open(path, mode, *args, **kwargs)

    monkeypatch.setattr("lancast.transfer.open", open_shrinking, raising=False)

    client, server = _socket_pair()
    server.settimeout(2)  # so the old behaviour fails the test instead of hanging it
    client.settimeout(2)
    receiver_errors: list[Exception] = []

    def _receive() -> None:
        try:
            receive_file(server, tmp_path / "received")
        except ProtocolError as error:
            receiver_errors.append(error)

    receiver_thread = threading.Thread(target=_receive)
    receiver_thread.start()
    try:
        with pytest.raises(ProtocolError, match="shrank"):
            send_file(client, src_file)
        client.close()  # what send_file_to_peer's `with` block does on error
        receiver_thread.join(timeout=2)
        assert receiver_errors, "receiver should see the connection drop"
        assert not (tmp_path / "received" / "shrinking.bin").exists()
    finally:
        client.close()
        server.close()


def test_receiver_reports_unwritable_destination(tmp_path: Path) -> None:
    """Before: if dest_dir couldn't be created, receive_file raised a raw
    OSError without a status byte. The sender just saw the connection close
    and was told the receiver 'may not trust this device yet'."""
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("a file where the destination directory should be")

    client, server = _socket_pair()
    try:
        _send_header(client, b"notes.txt", 5)
        with pytest.raises(ProtocolError, match="Could not create"):
            receive_file(server, blocker / "received")
        assert _read_status(client) == STATUS_WRITE_FAILED
    finally:
        client.close()
        server.close()


def test_sender_gets_protocol_error_when_receiver_drops_mid_payload(tmp_path: Path) -> None:
    """A receiver that accepts and then vanishes must surface as ProtocolError
    (which the CLI reports), not a raw BrokenPipeError or ssl error."""
    src_file = tmp_path / "big.bin"
    src_file.write_bytes(b"z" * (4 * 1024 * 1024))

    client, server = _socket_pair()
    try:
        def _accept_then_vanish() -> None:
            _recv_exact(server, struct.calcsize(FILENAME_LEN_FMT) + len(b"big.bin") + struct.calcsize(PAYLOAD_LEN_FMT))
            server.sendall(struct.pack(STATUS_FMT, 0))
            server.close()

        receiver_thread = threading.Thread(target=_accept_then_vanish)
        receiver_thread.start()
        client.settimeout(5)
        with pytest.raises(ProtocolError):
            send_file(client, src_file)
        receiver_thread.join(timeout=2)
    finally:
        client.close()
