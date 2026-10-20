# LANCast

A LAN peer discovery and file-transfer tool built directly on raw TCP and UDP
sockets — no HTTP framework, no message-queue library. Built to understand
what those tools abstract away: connection handling, message framing over a
byte stream, and the tradeoffs between connection-oriented and connectionless
transport.

Transfers run over mutual TLS between devices that have explicitly trusted
each other, with per-peer permissions. See [THREAT_MODEL.md](THREAT_MODEL.md)
for what that defends against and what it doesn't.

## Why two protocols

| Concern | Protocol | Why |
|---|---|---|
| Peer discovery | UDP broadcast | Connectionless — one send reaches every host on the subnet without per-host handshakes. Occasional packet loss is fine since beacons repeat every 2s. |
| File transfer | TCP | Reliable, ordered delivery required — a corrupted or reordered file is useless. |
| Transfer security | Mutual TLS 1.3 | Both sides prove who they are with a pinned certificate. Encrypted on the wire. |

## Protocol design

TCP is a byte stream, not a message stream, so this project defines a minimal
framing protocol on top of raw sockets (inside the TLS session):

```
sender   -> [4 bytes: filename length N] [N bytes: filename, utf-8]
            [8 bytes: payload length M]
receiver -> [1 byte: status]          accept, or why it refused
sender   -> [M bytes: file contents]  only if accepted
receiver -> [1 byte: status]          written to disk, or failed
```

The status byte after the header lets the receiver refuse a transfer (not
allowed, too large, bad filename) before the sender streams any of the file.

`_recv_exact()` handles the fact that a single `socket.recv()` call is only
a *maximum* read size — TCP can (and does, under load) deliver a sender's
single `write()` across multiple `recv()` calls on the receiving end.

Discovery beacons are sent as JSON over UDP broadcast on port `50999`, tagged
with a magic string so non-LANCast UDP traffic on the same port is ignored.
Each beacon carries the device's certificate fingerprint. Beacons are
unauthenticated hints: nothing is trusted because of a beacon.

## Identity and trust

Each device generates an ECDSA P-256 keypair and a self-signed certificate on
first run (stored in `~/.lancast`, or `$LANCAST_HOME`). A device is identified
by the SHA-256 fingerprint of its certificate, the same idea as SSH host keys.
There's no certificate authority.

Trust is deny-by-default. To let two devices talk, each one trusts the other:
exchange certificate files, then confirm the fingerprint out of band (read it
aloud, or send it over a channel you already trust). Each trusted peer has
permissions:

- `can_send`: whether it may push files to you (`--receive-only` turns this off)
- `max_file_bytes`: the largest single file you'll accept from it (`--max-mb`)

The receiver rebuilds its TLS context from the trust store on every
connection, so `lancast revoke` takes effect without restarting.

## Usage

```bash
# On each machine: create an identity and see its fingerprint
lancast whoami
lancast export --out my-laptop.pem     # share this file with the other device

# Trust the other device (prompts you to confirm its fingerprint)
lancast trust their-laptop.pem --name their-laptop --max-mb 500
lancast peers                          # list trusted peers and permissions

# On the receiving machine
lancast serve --dest ./received --port 51000

# On another machine on the same LAN, find peers
lancast discover --seconds 5

# Send a file (optionally pin the receiver's fingerprint)
lancast send 192.168.1.42 ./photo.jpg --port 51000 --fingerprint <their fingerprint>

# Stop trusting a device
lancast revoke <fingerprint>
```

## Security

[THREAT_MODEL.md](THREAT_MODEL.md) lists the attacker, each threat, the
control that stops it, and the test that proves it. In short: mutual TLS
with pinned certificates, deny-by-default per-peer permissions, size limits
checked before any payload is read, timeouts and a concurrency cap on the
receiver, path traversal and overwrite protection, and validation of every
beacon field. It also lists what LANCast does *not* defend against.

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## License

MIT
