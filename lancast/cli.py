"""Command-line interface for LANCast."""

from __future__ import annotations

import argparse
import socket
import sys
import time
from pathlib import Path

from lancast.discovery import BeaconListener, BeaconSender, PeerRegistry
from lancast.transfer import DEFAULT_TCP_PORT, FileReceiverServer, send_file_to_peer


def _local_hostname() -> str:
    return socket.gethostname()


def cmd_serve(args: argparse.Namespace) -> None:
    dest_dir = Path(args.dest)
    registry = PeerRegistry()

    beacon_sender = BeaconSender(name=_local_hostname(), tcp_port=args.port)
    beacon_listener = BeaconListener(registry=registry, self_tcp_port=args.port)
    beacon_sender.start()
    beacon_listener.start()

    def on_received(dest_path: Path, addr) -> None:
        print(f"[received] {dest_path.name} from {addr[0]} -> {dest_path}")

    server = FileReceiverServer(dest_dir=dest_dir, port=args.port, on_received=on_received)
    print(f"LANCast serving on TCP:{args.port}, saving files to {dest_dir.resolve()}")
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
        print(f"  {peer.name}\t{peer.host}:{peer.tcp_port}")


def cmd_send(args: argparse.Namespace) -> None:
    file_path = Path(args.file)
    if not file_path.is_file():
        print(f"error: {file_path} is not a file", file=sys.stderr)
        sys.exit(1)
    send_file_to_peer(args.host, args.port, file_path)
    print(f"Sent {file_path.name} to {args.host}:{args.port}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lancast", description="LAN peer discovery + file transfer.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve_parser = subparsers.add_parser("serve", help="Run a discoverable receiver.")
    serve_parser.add_argument("--dest", default="./received", help="Directory to save incoming files.")
    serve_parser.add_argument("--port", type=int, default=DEFAULT_TCP_PORT)
    serve_parser.set_defaults(func=cmd_serve)

    discover_parser = subparsers.add_parser("discover", help="Listen for peers on the LAN.")
    discover_parser.add_argument("--seconds", type=float, default=5.0)
    discover_parser.set_defaults(func=cmd_discover)

    send_parser = subparsers.add_parser("send", help="Send a file directly to a known host:port.")
    send_parser.add_argument("host")
    send_parser.add_argument("file")
    send_parser.add_argument("--port", type=int, default=DEFAULT_TCP_PORT)
    send_parser.set_defaults(func=cmd_send)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
