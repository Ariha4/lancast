"""
TCP file transfer with a hand-rolled length-prefixed framing protocol,
running inside mutual TLS.

TCP gives us a reliable, ordered byte stream but no concept of "messages" --
it's just a stream. If you write two files back to back into the socket,
the receiving side has no built-in way to know where the first ends and the
second begins. This module defines a minimal framing protocol on top of the
stream to solve that:

    sender   -> [4 bytes: filename length N] [N bytes: filename, utf-8]
                [8 bytes: payload length M]
    receiver -> [1 byte: status]           accept, or why it refused
    sender   -> [M bytes: file contents]   only if accepted
    receiver -> [1 byte: status]           written to disk, or failed

All integers are big-endian, matching network byte order (RFC 1700).

The status byte after the header exists so the receiver can refuse a
transfer (not allowed, too large, bad filename) before the sender streams
gigabytes it was never going to accept. The final status byte tells the
sender the file actually landed, rather than assuming it did because
sendall() returned.
"""

from __future__ import annotations

import os
import socket
import ssl
import struct
import threading
from pathlib import Path
from typing import Callable

from lancast.identity import Identity, IdentityError, normalize_fingerprint
from lancast.tls import make_client_context, make_server_context, peer_fingerprint
from lancast.trust import DEFAULT_MAX_FILE_BYTES, TrustedPeer, TrustStore

DEFAULT_TCP_PORT = 51000
RECV_CHUNK_SIZE = 65536
FILENAME_LEN_FMT = "!I"   # unsigned 4-byte big-endian
PAYLOAD_LEN_FMT = "!Q"    # unsigned 8-byte big-endian
STATUS_FMT = "!B"         # unsigned 1-byte status code
MAX_FILENAME_BYTES = 4096
CONNECTION_TIMEOUT_SEC = 30.0  # per blocking read/write, so a stalled peer can't hold a thread forever
MAX_CONCURRENT_TRANSFERS = 8
MAX_DUPLICATE_NAME_ATTEMPTS = 1000
ACCEPT_RETRY_DELAY_SEC = 0.1
FORBIDDEN_FILENAMES = {"", ".", ".."}

STATUS_OK = 0
STATUS_SEND_NOT_ALLOWED = 1
STATUS_TOO_LARGE = 2
STATUS_BAD_FRAME = 3
STATUS_WRITE_FAILED = 4

STATUS_MESSAGES = {
    STATUS_OK: "ok",
    STATUS_SEND_NOT_ALLOWED: "this device is not allowed to send to the receiver",
    STATUS_TOO_LARGE: "file is larger than the receiver allows from this device",
    STATUS_BAD_FRAME: "receiver rejected the filename or frame",
    STATUS_WRITE_FAILED: "receiver could not write the file",
}


class ProtocolError(Exception):
    """Raised when a peer sends a malformed frame or the connection breaks mid-transfer."""


class TransferRefused(ProtocolError):
    """The receiver understood the request and said no."""

    def __init__(self, status: int) -> None:
        self.status = status
        super().__init__(STATUS_MESSAGES.get(status, f"unknown status {status}"))


# ---------- low-level helpers ----------

def _recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
    """Read exactly num_bytes from a TCP stream, or raise on early close.

    Necessary because sock.recv(n) is only a *maximum*: TCP is a byte
    stream, not a message stream, so a single recv() call can return
    fewer bytes than requested even if the sender wrote them all at once.
    """
    chunks = []
    remaining = num_bytes
    while remaining > 0:
        try:
            chunk = sock.recv(min(remaining, RECV_CHUNK_SIZE))
        except (socket.timeout, ssl.SSLError, ConnectionError) as error:
            raise ProtocolError(f"Connection failed while reading: {error}") from error
        if not chunk:
            raise ProtocolError("Connection closed before expected bytes were received")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _send_status(sock: socket.socket, status: int) -> None:
    try:
        sock.sendall(struct.pack(STATUS_FMT, status))
    except OSError as error:
        raise ProtocolError(f"Could not send status to peer: {error}") from error


def _recv_status(sock: socket.socket) -> int:
    (status,) = struct.unpack(STATUS_FMT, _recv_exact(sock, struct.calcsize(STATUS_FMT)))
    return status


def safe_filename(raw_filename: str) -> str:
    """Reduce a peer-supplied filename to a bare name that stays inside dest_dir.

    Splits on both / and \\ so the result doesn't depend on the receiver's
    OS, then rejects the names that still point somewhere other than a new
    file: '' (dest_dir itself), '.' and '..'.
    """
    if "\x00" in raw_filename:
        raise ProtocolError("Filename contains a NUL byte")
    base_name = raw_filename.replace("\\", "/").split("/")[-1]
    if base_name in FORBIDDEN_FILENAMES:
        raise ProtocolError(f"Refusing filename {raw_filename!r}")
    return base_name


def _open_unique(dest_dir: Path, filename: str) -> tuple[Path, object]:
    """Open a brand-new file, never overwriting one that already exists.

    'x' mode is create-exclusive: the OS fails the open if the name is
    taken, so there's no gap between "check it doesn't exist" and "create
    it" for another transfer to slip into.
    """
    stem = Path(filename).stem
    suffix = Path(filename).suffix
    for attempt in range(MAX_DUPLICATE_NAME_ATTEMPTS):
        candidate_name = filename if attempt == 0 else f"{stem} ({attempt}){suffix}"
        candidate_path = dest_dir / candidate_name
        try:
            return candidate_path, open(candidate_path, "xb")
        except FileExistsError:
            continue
    raise ProtocolError(f"Too many existing files named like {filename!r}")


# ---------- framing ----------

def send_file(sock: socket.socket, file_path: Path) -> None:
    """Frame and send a single file over an already-connected socket."""
    name_bytes = file_path.name.encode("utf-8")
    file_size = file_path.stat().st_size

    header = struct.pack(FILENAME_LEN_FMT, len(name_bytes))
    header += name_bytes
    header += struct.pack(PAYLOAD_LEN_FMT, file_size)
    try:
        sock.sendall(header)
    except OSError as error:
        raise ProtocolError(f"Could not send header: {error}") from error

    accept_status = _recv_status(sock)
    if accept_status != STATUS_OK:
        raise TransferRefused(accept_status)

    # Stream from disk in chunks instead of reading the whole file into memory.
    # Send exactly the size promised in the header, never "until EOF": if the
    # file is appended to mid-send, extra bytes would land where the receiver
    # expects the next frame; if it is truncated, the receiver would sit
    # waiting for bytes that never come until its timeout fires.
    with open(file_path, "rb") as file_handle:
        remaining = file_size
        while remaining > 0:
            chunk = file_handle.read(min(remaining, RECV_CHUNK_SIZE))
            if not chunk:
                raise ProtocolError(
                    f"{file_path.name} shrank while it was being sent "
                    f"({file_size - remaining} of {file_size} bytes sent)"
                )
            try:
                sock.sendall(chunk)
            except OSError as error:
                raise ProtocolError(f"Connection failed while sending: {error}") from error
            remaining -= len(chunk)

    final_status = _recv_status(sock)
    if final_status != STATUS_OK:
        raise TransferRefused(final_status)


def receive_file(
    sock: socket.socket,
    dest_dir: Path,
    max_payload_bytes: int = DEFAULT_MAX_FILE_BYTES,
    allowed_to_send: bool = True,
) -> Path:
    """Block until one framed file arrives, then write it to dest_dir."""
    name_len_bytes = _recv_exact(sock, struct.calcsize(FILENAME_LEN_FMT))
    (name_len,) = struct.unpack(FILENAME_LEN_FMT, name_len_bytes)
    if name_len == 0 or name_len > MAX_FILENAME_BYTES:
        raise ProtocolError(f"Suspicious filename length: {name_len}")

    name_bytes = _recv_exact(sock, name_len)
    try:
        raw_filename = name_bytes.decode("utf-8")
        filename = safe_filename(raw_filename)
    except (UnicodeDecodeError, ProtocolError) as error:
        _send_status(sock, STATUS_BAD_FRAME)
        raise ProtocolError(f"Bad filename: {error}") from error

    payload_len_bytes = _recv_exact(sock, struct.calcsize(PAYLOAD_LEN_FMT))
    (payload_len,) = struct.unpack(PAYLOAD_LEN_FMT, payload_len_bytes)

    # Every check happens here, before we read a single payload byte.
    if not allowed_to_send:
        _send_status(sock, STATUS_SEND_NOT_ALLOWED)
        raise TransferRefused(STATUS_SEND_NOT_ALLOWED)
    if payload_len > max_payload_bytes:
        _send_status(sock, STATUS_TOO_LARGE)
        raise TransferRefused(STATUS_TOO_LARGE)

    # The sender is blocked waiting for the accept status. If we can't create
    # the file, say so, rather than dropping the connection and leaving the
    # sender to guess (it would otherwise blame a trust problem).
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_path, file_handle = _open_unique(dest_dir, filename)
    except (OSError, ProtocolError) as error:
        _send_status(sock, STATUS_WRITE_FAILED)
        raise ProtocolError(f"Could not create {filename!r} in {dest_dir}: {error}") from error

    finished = False
    try:
        with file_handle:
            _send_status(sock, STATUS_OK)
            remaining = payload_len
            while remaining > 0:
                chunk = _recv_exact(sock, min(remaining, RECV_CHUNK_SIZE))
                try:
                    file_handle.write(chunk)
                except OSError as error:  # disk full, permissions, etc.
                    _send_status(sock, STATUS_WRITE_FAILED)
                    raise ProtocolError(f"Could not write {dest_path.name}: {error}") from error
                remaining -= len(chunk)
        finished = True
    finally:
        if not finished:
            dest_path.unlink(missing_ok=True)  # never leave a truncated file behind

    _send_status(sock, STATUS_OK)
    return dest_path


# ---------- client ----------

def send_file_to_peer(
    host: str,
    port: int,
    file_path: Path,
    identity: Identity,
    trust_store: TrustStore,
    expected_fingerprint: str | None = None,
    timeout: float = CONNECTION_TIMEOUT_SEC,
) -> TrustedPeer:
    """Connect over mutual TLS, confirm who we reached, then send one file."""
    context = make_client_context(identity, trust_store)
    with socket.create_connection((host, port), timeout=timeout) as raw_socket:
        with context.wrap_socket(raw_socket) as tls_socket:
            receiver_fingerprint = peer_fingerprint(tls_socket)
            receiver = trust_store.lookup(receiver_fingerprint)
            if receiver is None:
                raise IdentityError("Receiver's certificate is not in the trust store")
            if expected_fingerprint is not None and normalize_fingerprint(expected_fingerprint) != receiver_fingerprint:
                raise IdentityError(f"Connected to {receiver.name}, not the peer you asked for")
            try:
                send_file(tls_socket, file_path)
            except ProtocolError as error:
                if isinstance(error, TransferRefused):
                    raise
                # In TLS 1.3 the client finishes its side of the handshake before
                # the server has checked the client certificate, so an untrusted
                # sender only finds out when its first read fails.
                raise ProtocolError(
                    f"Receiver closed the connection ({error}). It may not trust this device yet."
                ) from error
    return receiver


# ---------- server ----------

class FileReceiverServer:
    """Threaded mutual-TLS server: accepts connections, receives one file each."""

    def __init__(
        self,
        dest_dir: Path,
        identity: Identity,
        trust_store: TrustStore,
        port: int = DEFAULT_TCP_PORT,
        bind_host: str = "",
        on_received: Callable[[Path, tuple, TrustedPeer], None] | None = None,
        on_rejected: Callable[[tuple, Exception], None] | None = None,
        max_concurrent: int = MAX_CONCURRENT_TRANSFERS,
        connection_timeout: float = CONNECTION_TIMEOUT_SEC,
    ) -> None:
        self.dest_dir = dest_dir
        self.identity = identity
        self.trust_store = trust_store
        self.port = port
        self.bind_host = bind_host
        self.on_received = on_received
        self.on_rejected = on_rejected
        self.connection_timeout = connection_timeout
        self._transfer_slots = threading.BoundedSemaphore(max_concurrent)
        self._server_sock: socket.socket | None = None
        self._stopping = threading.Event()
        self.ready = threading.Event()

    def serve_forever(self) -> None:
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.bind_host, self.port))
        self._server_sock.listen(5)
        self.port = self._server_sock.getsockname()[1]  # resolves port 0 to the real port
        self.ready.set()

        try:
            while not self._stopping.is_set():
                try:
                    conn, addr = self._server_sock.accept()
                except OSError:
                    if self._stopping.is_set():
                        break  # stop() shut the socket down under us
                    # Anything else (ECONNABORTED when a client gives up mid-
                    # handshake, EMFILE when out of file descriptors) is about one
                    # connection or is temporary. Don't let it end the server;
                    # pause briefly so a persistent error can't spin the CPU.
                    self._stopping.wait(ACCEPT_RETRY_DELAY_SEC)
                    continue
                # Cap concurrent transfers. Past the cap, drop the connection
                # instead of spawning yet another thread.
                if not self._transfer_slots.acquire(blocking=False):
                    self._report_rejection(addr, ProtocolError("Too many concurrent transfers"))
                    conn.close()
                    continue
                threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()
        finally:
            self._server_sock.close()

    def _report_rejection(self, addr: tuple, error: Exception) -> None:
        if self.on_rejected:
            self.on_rejected(addr, error)

    def _handle_client(self, conn: socket.socket, addr: tuple) -> None:
        try:
            with conn:
                conn.settimeout(self.connection_timeout)  # also bounds the TLS handshake
                context = make_server_context(self.identity, self.trust_store)
                with context.wrap_socket(conn, server_side=True) as tls_socket:
                    sender = self.trust_store.lookup(peer_fingerprint(tls_socket))
                    if sender is None:
                        # Possible if the peer was revoked between building the
                        # context and finishing the handshake.
                        raise IdentityError("Sender is not trusted")
                    dest_path = receive_file(
                        tls_socket,
                        self.dest_dir,
                        max_payload_bytes=sender.max_file_bytes,
                        allowed_to_send=sender.can_send,
                    )
                    if self.on_received:
                        self.on_received(dest_path, addr, sender)
        except (ProtocolError, IdentityError, ssl.SSLError, OSError) as error:
            self._report_rejection(addr, error)
        finally:
            self._transfer_slots.release()

    def stop(self) -> None:
        self._stopping.set()
        if self._server_sock is not None:
            # close() alone doesn't wake a thread blocked in accept() on Linux:
            # the kernel keeps the listening socket alive until accept returns,
            # so serve_forever would hang (and keep the port bound) until the
            # next client connected. shutdown() makes accept() fail right away.
            try:
                self._server_sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # e.g. ENOTCONN on platforms that don't allow it on listeners
            self._server_sock.close()
