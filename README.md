# LANCast

A LAN peer discovery and file-transfer tool built directly on raw TCP and UDP
sockets — no HTTP framework, no message-queue library. Built to understand
what those tools abstract away: connection handling, message framing over a
byte stream, and the tradeoffs between connection-oriented and connectionless
transport.

## Why two protocols

| Concern | Protocol | Why |
|---|---|---|
| Peer discovery | UDP broadcast | Connectionless — one send reaches every host on the subnet without per-host handshakes. Occasional packet loss is fine since beacons repeat every 2s. |
| File transfer | TCP | Reliable, ordered delivery required — a corrupted or reordered file is useless. |

## Protocol design

TCP is a byte stream, not a message stream, so this project defines a minimal
framing protocol on top of raw sockets:

```
[4 bytes: filename length N (big-endian)] [N bytes: filename, utf-8]
[8 bytes: payload length M (big-endian)]  [M bytes: file contents]
```

`_recv_exact()` handles the fact that a single `socket.recv()` call is only
a *maximum* read size — TCP can (and does, under load) deliver a sender's
single `write()` across multiple `recv()` calls on the receiving end.

Discovery beacons are sent as JSON over UDP broadcast on port `50999`, tagged
with a magic string so non-LANCast UDP traffic on the same port is ignored.

## Usage

```bash
# On the receiving machine
lancast serve --dest ./received --port 51000

# On another machine on the same LAN, find peers
lancast discover --seconds 5

# Send a file directly
lancast send 192.168.1.42 ./photo.jpg --port 51000
```

## Security note

This is a learning/demo project, not hardened for untrusted networks:
peer identity isn't authenticated and transfers aren't encrypted. Filenames
from incoming frames are stripped to their basename before being written to
disk (see `tests/test_transfer.py::test_receive_file_strips_path_components`)
to prevent path traversal, but that's the extent of the hardening.

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## License

MIT
