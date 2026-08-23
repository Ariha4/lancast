import socket
import struct
import threading
from pathlib import Path

import pytest

from lancast.transfer import (
    FILENAME_LEN_FMT,
    PAYLOAD_LEN_FMT,
    ProtocolError,
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
        name_bytes = "../../evil.txt".encode("utf-8")
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
