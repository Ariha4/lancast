"""Command-line interface for LANCast."""

from __future__ import annotations

import argparse
import socket
import sys
import time
from pathlib import Path

from lancast.discovery import BeaconListener, BeaconSender, PeerRegistry
from lancast.identity import (
    IdentityError,
    default_home,
    fingerprint_from_pem,
    format_fingerprint,
    load_or_create_identity,
)
from lancast.transfer import DEFAULT_TCP_PORT, FileReceiverServer, ProtocolError, send_file_to_peer
from lancast.trust import DEFAULT_MAX_FILE_BYTES, TrustStore

BYTES_PER_MB = 1024 * 1024


def _local_hostname() -> str:
    return socket.gethostname()


def _home(args: argparse.Namespace) -> Path:
    return Path(args.home) if args.home else default_home()


def cmd_whoami(args: argparse.Namespace) -> None:
    identity = load_or_create_identity(_home(args), _local_hostname())
    print(f"Fingerprint: {format_fingerprint(identity.fingerprint)}")
    print(f"Certificate: {identity.cert_path}")
    print("Share the certificate file with a peer and read them this fingerprint so they can confirm it.")


def cmd_export(args: argparse.Namespace) -> None:
    identity = load_or_create_identity(_home(args), _local_hostname())
    cert_text = identity.cert_path.read_text()
    if args.out:
        Path(args.out).write_text(cert_text)
        print(f"Wrote certificate to {args.out}")
    else:
        sys.stdout.write(cert_text)


def cmd_trust(args: argparse.Namespace) -> None:
    cert_pem = Path(args.cert).read_text()
    fingerprint = fingerprint_from_pem(cert_pem)

    if args.fingerprint is None:
        # Make the user compare against what the peer told them out of band.
        # Trusting a certificate file without checking it is how you end up
        # trusting whoever handed you the file.
        print(f"Certificate fingerprint: {format_fingerprint(fingerprint)}")
        answer = input("Does this match the fingerprint the peer read to you? [y/N] ")
        if answer.strip().lower() != "y":
            print("Not trusted.")
            sys.exit(1)

    trust_store = TrustStore(_home(args))
    peer = trust_store.trust(
        cert_pem,
        name=args.name,
        can_send=not args.receive_only,
        max_file_bytes=int(args.max_mb * BYTES_PER_MB),
        expected_fingerprint=args.fingerprint,
    )
    sending_rule = "may send to you" if peer.can_send else "may NOT send to you"
    print(f"Trusted {peer.name} ({format_fingerprint(peer.fingerprint)[:23]}...): {sending_rule}, max {args.max_mb:g} MB per file")


def cmd_revoke(args: argparse.Namespace) -> None:
    trust_store = TrustStore(_home(args))
    if trust_store.revoke(args.fingerprint):
        print("Revoked. New connections from that peer will be refused.")
    else:
        print("That fingerprint was not trusted.")
        sys.exit(1)


def cmd_peers(args: argparse.Namespace) -> None:
    trusted_peers = TrustStore(_home(args)).all_peers()
    if not trusted_peers:
        print("No trusted peers. Add one with `lancast trust <cert.pem> --name <name>`.")
        return
    for peer in trusted_peers:
        sending_rule = "can send" if peer.can_send else "receive-only"
        max_mb = peer.max_file_bytes / BYTES_PER_MB
        print(f"  {peer.name}\t{format_fingerprint(peer.fingerprint)}\t{sending_rule}, max {max_mb:g} MB")


def cmd_serve(args: argparse.Namespace) -> None:
    home_dir = _home(args)
    identity = load_or_create_identity(home_dir, _local_hostname())
    trust_store = TrustStore(home_dir)
    if not trust_store.all_peers():
        print("warning: no trusted peers yet, so every incoming connection will be refused.", file=sys.stderr)

    dest_dir = Path(args.dest)
    registry = PeerRegistry()
    beacon_sender = BeaconSender(name=_local_hostname(), tcp_port=args.port, fingerprint=identity.fingerprint)
    beacon_listener = BeaconListener(registry=registry, self_tcp_port=args.port)
    beacon_sender.start()
    beacon_listener.start()

    def on_received(dest_path: Path, addr, sender) -> None:
        print(f"[received] {dest_path.name} from {sender.name} ({addr[0]}) -> {dest_path}")

    def on_rejected(addr, error: Exception) -> None:
        print(f"[refused] {addr[0]}: {error}", file=sys.stderr)

    server = FileReceiverServer(
        dest_dir=dest_dir,
        identity=identity,
        trust_store=trust_store,
        port=args.port,
        on_received=on_received,
        on_rejected=on_rejected,
    )
    print(f"LANCast serving on TCP:{args.port}, saving files to {dest_dir.resolve()}")
    print(f"This device: {format_fingerprint(identity.fingerprint)}")
    print("Broadcasting presence over UDP; press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
        beacon_sender.stop()
        beacon_listener.stop()


def cmd_discover(args: argparse.Namespace) -> None:
    trust_store = TrustStore(_home(args))
    registry = PeerRegistry()
    listener = BeaconListener(registry=registry, self_tcp_port=-1)
    listener.start()
    print(f"Listening for peers for {args.seconds}s...")
    try:
        time.sleep(args.seconds)
    finally:
        listener.stop()

    peers = registry.active_peers()
    if not peers:
        print("No peers found.")
        return
    for peer in peers:
        trusted_entry = trust_store.lookup(peer.fingerprint) if peer.fingerprint else None
        if trusted_entry is not None:
            status = f"trusted as {trusted_entry.name}"
        else:
            status = "NOT trusted"
        short_fingerprint = format_fingerprint(peer.fingerprint)[:23] if peer.fingerprint else "no fingerprint"
        print(f"  {peer.name}\t{peer.host}:{peer.tcp_port}\t{short_fingerprint}\t{status}")
    print("Names in beacons are self-reported. Only the fingerprint, checked during the TLS handshake, identifies a peer.")


def cmd_send(args: argparse.Namespace) -> None:
    file_path = Path(args.file)
    if not file_path.is_file():
        print(f"error: {file_path} is not a file", file=sys.stderr)
        sys.exit(1)

    home_dir = _home(args)
    identity = load_or_create_identity(home_dir, _local_hostname())
    trust_store = TrustStore(home_dir)
    try:
        receiver = send_file_to_peer(
            args.host,
            args.port,
            file_path,
            identity=identity,
            trust_store=trust_store,
            expected_fingerprint=args.fingerprint,
        )
    except (IdentityError, ProtocolError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
    print(f"Sent {file_path.name} to {receiver.name} ({args.host}:{args.port})")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lancast", description="LAN peer discovery + authenticated file transfer.")
    parser.add_argument("--home", default=None, help="Identity and trust store directory (default: ~/.lancast or $LANCAST_HOME).")
    subparsers = parser.add_subparsers(dest="command", required=True)

    whoami_parser = subparsers.add_parser("whoami", help="Show this device's fingerprint (creates an identity on first run).")
    whoami_parser.set_defaults(func=cmd_whoami)

    export_parser = subparsers.add_parser("export", help="Print or save this device's certificate to share with a peer.")
    export_parser.add_argument("--out", default=None, help="File to write the certificate to (default: stdout).")
    export_parser.set_defaults(func=cmd_export)

    trust_parser = subparsers.add_parser("trust", help="Trust a peer's certificate.")
    trust_parser.add_argument("cert", help="Path to the peer's exported certificate (.pem).")
    trust_parser.add_argument("--name", required=True, help="Your label for this peer.")
    trust_parser.add_argument("--fingerprint", default=None, help="Expected fingerprint; skips the confirmation prompt if it matches.")
    trust_parser.add_argument("--max-mb", type=float, default=DEFAULT_MAX_FILE_BYTES / BYTES_PER_MB, help="Largest file to accept from this peer, in MB.")
    trust_parser.add_argument("--receive-only", action="store_true", help="Trust this peer as a receiver only; it may not send to you.")
    trust_parser.set_defaults(func=cmd_trust)

    revoke_parser = subparsers.add_parser("revoke", help="Stop trusting a peer.")
    revoke_parser.add_argument("fingerprint")
    revoke_parser.set_defaults(func=cmd_revoke)

    peers_parser = subparsers.add_parser("peers", help="List trusted peers and their permissions.")
    peers_parser.set_defaults(func=cmd_peers)

    serve_parser = subparsers.add_parser("serve", help="Run a discoverable receiver.")
    serve_parser.add_argument("--dest", default="./received", help="Directory to save incoming files.")
    serve_parser.add_argument("--port", type=int, default=DEFAULT_TCP_PORT)
    serve_parser.set_defaults(func=cmd_serve)

    discover_parser = subparsers.add_parser("discover", help="Listen for peers on the LAN.")
    discover_parser.add_argument("--seconds", type=float, default=5.0)
    discover_parser.set_defaults(func=cmd_discover)

    send_parser = subparsers.add_parser("send", help="Send a file to a trusted peer.")
    send_parser.add_argument("host")
    send_parser.add_argument("file")
    send_parser.add_argument("--port", type=int, default=DEFAULT_TCP_PORT)
    send_parser.add_argument("--fingerprint", default=None, help="Refuse to send unless the receiver has this fingerprint.")
    send_parser.set_defaults(func=cmd_send)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except (IdentityError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
