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
