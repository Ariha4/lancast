import time

from lancast.discovery import Peer, PeerRegistry


def test_registry_upsert_and_active_peers() -> None:
    registry = PeerRegistry(timeout_sec=5.0)
    peer = Peer(name="alice-laptop", host="10.0.0.5", tcp_port=51000)

    registry.upsert(peer)
    active = registry.active_peers()

    assert len(active) == 1
    assert active[0].name == "alice-laptop"
    assert active[0].host == "10.0.0.5"


def test_registry_deduplicates_same_peer() -> None:
    registry = PeerRegistry(timeout_sec=5.0)
    registry.upsert(Peer(name="alice-laptop", host="10.0.0.5", tcp_port=51000))
    registry.upsert(Peer(name="alice-laptop", host="10.0.0.5", tcp_port=51000))

    assert len(registry.active_peers()) == 1


def test_registry_prunes_stale_peers() -> None:
    registry = PeerRegistry(timeout_sec=0.05)
    registry.upsert(Peer(name="ghost", host="10.0.0.9", tcp_port=51000))

    time.sleep(0.1)
    active = registry.active_peers()

    assert active == []


def test_registry_tracks_multiple_distinct_peers() -> None:
    registry = PeerRegistry(timeout_sec=5.0)
    registry.upsert(Peer(name="peer-a", host="10.0.0.1", tcp_port=51000))
    registry.upsert(Peer(name="peer-b", host="10.0.0.2", tcp_port=51000))

    names = {peer.name for peer in registry.active_peers()}
    assert names == {"peer-a", "peer-b"}


# ---------- regression tests for beacon validation ----------

import json

import pytest

from lancast.discovery import MAGIC, parse_beacon

SENDER_ADDR = ("10.0.0.7", 50999)


def _beacon(**fields) -> bytes:
    message = {"magic": MAGIC, "name": "peer", "tcp_port": 51000, "fingerprint": "ab" * 32}
    message.update(fields)
    return json.dumps(message).encode("utf-8")


def test_valid_beacon_parses_with_fingerprint() -> None:
    peer = parse_beacon(_beacon(), SENDER_ADDR)
    assert peer is not None
    assert peer.fingerprint == "ab" * 32
    assert peer.host == "10.0.0.7"


@pytest.mark.parametrize("bad_port", ["51000", True, 0, 70000, None, 3.5])
def test_beacon_with_invalid_port_is_dropped(bad_port) -> None:
    """Before: tcp_port went into the registry unchecked, whatever its type."""
    assert parse_beacon(_beacon(tcp_port=bad_port), SENDER_ADDR) is None


def test_beacon_name_cannot_inject_terminal_escape_codes() -> None:
    """Before: the beacon name was printed as-is, so a peer could send ANSI
    escape sequences to rewrite what `lancast discover` shows."""
    peer = parse_beacon(_beacon(name="\x1b[2Jtrusted-laptop\x07" + "x" * 500), SENDER_ADDR)
    assert peer is not None
    assert "\x1b" not in peer.name and "\x07" not in peer.name
    assert len(peer.name) <= 64


def test_beacon_with_malformed_fingerprint_keeps_peer_but_drops_fingerprint() -> None:
    peer = parse_beacon(_beacon(fingerprint="not-a-fingerprint"), SENDER_ADDR)
    assert peer is not None
    assert peer.fingerprint == ""


@pytest.mark.parametrize("garbage", [b"\xff\xfe", b"[]", b"null", json.dumps({"magic": "OTHER"}).encode()])
def test_non_lancast_packets_are_ignored(garbage: bytes) -> None:
    assert parse_beacon(garbage, SENDER_ADDR) is None
