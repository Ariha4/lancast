"""
TCP-based file transfer with a hand-rolled length-prefixed framing protocol.

TCP gives us a reliable, ordered byte stream but no concept of "messages" --
it's just a stream. If you write two files back to back into the socket,
the receiving side has no built-in way to know where the first ends and the
second begins. This module defines a minimal framing protocol on top of raw
sockets to solve that:

    [4 bytes: filename length N] [N bytes: filename, utf-8]
    [8 bytes: payload length M]  [M bytes: file contents]

All integers are big-endian, matching network byte order (RFC 1700). This
is the same class of problem TCP-based application protocols (HTTP/1.1
chunked transfer, protobuf-over-TCP, etc.) all have to solve.
"""

from __future__ import annotations

import socket
import struct
from pathlib import Path

DEFAULT_TCP_PORT = 51000
RECV_CHUNK_SIZE = 65536
FILENAME_LEN_FMT = "!I"   # unsigned 4-byte big-endian
PAYLOAD_LEN_FMT = "!Q"    # unsigned 8-byte big-endian


class ProtocolError(Exception):
    """Raised when a peer sends a malformed frame."""


def _recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
    """Read exactly num_bytes from a TCP stream, or raise on early close.

    Necessary because sock.recv(n) is only a *maximum*: TCP is a byte
    stream, not a message stream, so a single recv() call can return
    fewer bytes than requested even if the sender wrote them all at once.
    """
    chunks = []
    remaining = num_bytes
    while remaining > 0:
        chunk = sock.recv(min(remaining, RECV_CHUNK_SIZE))
        if not chunk:
            raise ProtocolError("Connection closed before expected bytes were received")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_file(sock: socket.socket, file_path: Path) -> None:
    """Frame and send a single file over an already-connected TCP socket."""
    data = file_path.read_bytes()
    name_bytes = file_path.name.encode("utf-8")

    header = struct.pack(FILENAME_LEN_FMT, len(name_bytes))
    header += name_bytes
    header += struct.pack(PAYLOAD_LEN_FMT, len(data))

    sock.sendall(header)
    sock.sendall(data)


def receive_file(sock: socket.socket, dest_dir: Path) -> Path:
    """Block until one framed file arrives, then write it to dest_dir."""
    name_len_bytes = _recv_exact(sock, struct.calcsize(FILENAME_LEN_FMT))
    (name_len,) = struct.unpack(FILENAME_LEN_FMT, name_len_bytes)
    if name_len == 0 or name_len > 4096:
        raise ProtocolError(f"Suspicious filename length: {name_len}")

    name_bytes = _recv_exact(sock, name_len)
    filename = name_bytes.decode("utf-8")

    payload_len_bytes = _recv_exact(sock, struct.calcsize(PAYLOAD_LEN_FMT))
    (payload_len,) = struct.unpack(PAYLOAD_LEN_FMT, payload_len_bytes)

    payload = _recv_exact(sock, payload_len)

    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_path = dest_dir / Path(filename).name  # strip any path components
    dest_path.write_bytes(payload)
    return dest_path


def send_file_to_peer(host: str, port: int, file_path: Path, timeout: float = 5.0) -> None:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        send_file(sock, file_path)


class FileReceiverServer:
    """Threaded TCP server: accepts connections, receives one file each."""

    def __init__(self, dest_dir: Path, port: int = DEFAULT_TCP_PORT, on_received=None) -> None:
        self.dest_dir = dest_dir
        self.port = port
        self.on_received = on_received
        self._server_sock: socket.socket | None = None
        self._running = False

    def serve_forever(self) -> None:
        import threading

        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind(("", self.port))
        self._server_sock.listen(5)
        self._running = True

        while self._running:
            try:
                conn, addr = self._server_sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()

    def _handle_client(self, conn: socket.socket, addr) -> None:
        with conn:
            try:
                dest_path = receive_file(conn, self.dest_dir)
                if self.on_received:
                    self.on_received(dest_path, addr)
            except ProtocolError:
                pass  # malformed frame from a misbehaving/partial client; drop connection

    def stop(self) -> None:
        self._running = False
        if self._server_sock is not None:
            self._server_sock.close()
