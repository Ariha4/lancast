"""
UDP-based peer discovery.

Why UDP here and not TCP: discovery is connectionless by nature -- a host
broadcasts "I exist" to everyone on the subnet without knowing who (or how
many) peers are listening. Establishing a TCP connection per potential peer
before you even know who's out there would mean N handshakes for N possible
hosts on the subnet. A single UDP broadcast reaches everyone in one send,
and occasional packet loss is acceptable since discovery is periodic --
a missed beacon just means you get the next one a few seconds later.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from dataclasses import dataclass, field

DISCOVERY_PORT = 50999
BROADCAST_ADDR = "255.255.255.255"
BEACON_INTERVAL_SEC = 2.0
PEER_TIMEOUT_SEC = 6.0
MAGIC = "LANCAST_BEACON_V1"


@dataclass
class Peer:
    name: str
    host: str
    tcp_port: int
    last_seen: float = field(default_factory=time.time)


class PeerRegistry:
    """Thread-safe table of recently-seen peers, pruned by last_seen."""

    def __init__(self, timeout_sec: float = PEER_TIMEOUT_SEC) -> None:
        self._peers: dict[str, Peer] = {}
        self._lock = threading.Lock()
        self._timeout = timeout_sec

    def upsert(self, peer: Peer) -> None:
        with self._lock:
            self._peers[f"{peer.host}:{peer.tcp_port}"] = peer

    def active_peers(self) -> list[Peer]:
        now = time.time()
        with self._lock:
            self._prune(now)
            return list(self._peers.values())

    def _prune(self, now: float) -> None:
        stale = [
            key
            for key, peer in self._peers.items()
            if now - peer.last_seen > self._timeout
        ]
        for key in stale:
            del self._peers[key]


class BeaconSender:
    """Periodically broadcasts this host's identity over UDP."""

    def __init__(self, name: str, tcp_port: int, interval: float = BEACON_INTERVAL_SEC) -> None:
        self.name = name
        self.tcp_port = tcp_port
        self.interval = interval
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def _payload(self) -> bytes:
        message = {"magic": MAGIC, "name": self.name, "tcp_port": self.tcp_port}
        return json.dumps(message).encode("utf-8")

    def _run(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            while not self._stop_event.is_set():
                sock.sendto(self._payload(), (BROADCAST_ADDR, DISCOVERY_PORT))
                self._stop_event.wait(self.interval)
        finally:
            sock.close()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=1)


class BeaconListener:
    """Listens for UDP beacons and records peers into a PeerRegistry."""

    def __init__(self, registry: PeerRegistry, self_tcp_port: int) -> None:
        self.registry = registry
        self.self_tcp_port = self_tcp_port
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def _run(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", DISCOVERY_PORT))
        sock.settimeout(0.5)
        try:
            while not self._stop_event.is_set():
                try:
                    data, addr = sock.recvfrom(2048)
                except socket.timeout:
                    continue
                self._handle_packet(data, addr)
        finally:
            sock.close()

    def _handle_packet(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            message = json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return
        if message.get("magic") != MAGIC:
            return
        host, _ = addr
        tcp_port = message.get("tcp_port")
        if tcp_port == self.self_tcp_port:
            return  # ignore our own beacon
        self.registry.upsert(Peer(name=message.get("name", "unknown"), host=host, tcp_port=tcp_port))

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=1)
