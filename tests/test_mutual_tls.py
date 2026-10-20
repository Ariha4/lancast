"""End-to-end tests: two simulated devices talking over real mutual TLS."""

import ssl
from pathlib import Path

import pytest

from lancast.identity import IdentityError
from lancast.tls import NoTrustedPeersError
from lancast.transfer import (
    STATUS_SEND_NOT_ALLOWED,
    STATUS_TOO_LARGE,
    ProtocolError,
    TransferRefused,
    send_file_to_peer,
)


def _trust_each_other(first, second, **permissions_for_second) -> None:
    first.trust_store.trust(second.cert_pem, name=second.home.name, **permissions_for_second)
    second.trust_store.trust(first.cert_pem, name=first.home.name)


def _make_file(tmp_path: Path, name: str, size: int) -> Path:
    path = tmp_path / name
    path.write_bytes(b"a" * size)
    return path


def test_trusted_peers_transfer_a_file(tmp_path, make_device, running_server) -> None:
    receiver = make_device("receiver")
    sender = make_device("sender")
    _trust_each_other(receiver, sender)
    server = running_server(receiver)

    source_file = _make_file(tmp_path, "notes.txt", 2000)
    reached = send_file_to_peer("127.0.0.1", server.port, source_file, sender.identity, sender.trust_store)

    assert reached.fingerprint == receiver.identity.fingerprint
    received_path, sender_entry = server.wait_for_received(1)[0]
    assert received_path.read_bytes() == source_file.read_bytes()
    assert sender_entry.fingerprint == sender.identity.fingerprint


def test_untrusted_sender_is_rejected_during_handshake(tmp_path, make_device, running_server) -> None:
    receiver = make_device("receiver")
    trusted_friend = make_device("friend")
    stranger = make_device("stranger")
    receiver.trust_store.trust(trusted_friend.cert_pem, name="friend")
    stranger.trust_store.trust(receiver.cert_pem, name="receiver")  # stranger trusts receiver, not vice versa
    server = running_server(receiver)

    with pytest.raises(ProtocolError):
        send_file_to_peer("127.0.0.1", server.port, _make_file(tmp_path, "x.txt", 10), stranger.identity, stranger.trust_store)
    assert not (tmp_path / "received" / "x.txt").exists()


def test_sender_refuses_an_untrusted_receiver(tmp_path, make_device, running_server) -> None:
    """Impostor receiver: the sender must not hand a file to a server whose
    certificate it never trusted, even if the address is right."""
    impostor = make_device("impostor")
    sender = make_device("sender")
    unrelated = make_device("unrelated")
    impostor.trust_store.trust(sender.cert_pem, name="sender")
    sender.trust_store.trust(unrelated.cert_pem, name="unrelated")
    server = running_server(impostor)

    with pytest.raises(ssl.SSLCertVerificationError):
        send_file_to_peer("127.0.0.1", server.port, _make_file(tmp_path, "secret.txt", 10), sender.identity, sender.trust_store)
    assert server.received == []


def test_sender_checks_expected_fingerprint(tmp_path, make_device, running_server) -> None:
    receiver = make_device("receiver")
    sender = make_device("sender")
    someone_else = make_device("someone-else")
    _trust_each_other(receiver, sender)
    sender.trust_store.trust(someone_else.cert_pem, name="someone-else")
    server = running_server(receiver)

    with pytest.raises(IdentityError):
        send_file_to_peer(
            "127.0.0.1", server.port, _make_file(tmp_path, "x.txt", 10),
            sender.identity, sender.trust_store,
            expected_fingerprint=someone_else.identity.fingerprint,
        )


def test_revoked_peer_is_rejected_without_restarting_server(tmp_path, make_device, running_server) -> None:
    receiver = make_device("receiver")
    sender = make_device("sender")
    _trust_each_other(receiver, sender)
    server = running_server(receiver)
    send_file_to_peer("127.0.0.1", server.port, _make_file(tmp_path, "before.txt", 10), sender.identity, sender.trust_store)
    server.wait_for_received(1)

    receiver.trust_store.trust(make_device("other").cert_pem, name="other")  # keep store non-empty
    receiver.trust_store.revoke(sender.identity.fingerprint)

    with pytest.raises(ProtocolError):
        send_file_to_peer("127.0.0.1", server.port, _make_file(tmp_path, "after.txt", 10), sender.identity, sender.trust_store)
    assert len(server.received) == 1


def test_receive_only_peer_cannot_send(tmp_path, make_device, running_server) -> None:
    receiver = make_device("receiver")
    sender = make_device("sender")
    _trust_each_other(receiver, sender, can_send=False)
    server = running_server(receiver)

    with pytest.raises(TransferRefused) as refusal:
        send_file_to_peer("127.0.0.1", server.port, _make_file(tmp_path, "x.txt", 10), sender.identity, sender.trust_store)
    assert refusal.value.status == STATUS_SEND_NOT_ALLOWED
    assert not (tmp_path / "received" / "x.txt").exists()


def test_per_peer_size_limit_is_enforced_before_payload(tmp_path, make_device, running_server) -> None:
    receiver = make_device("receiver")
    sender = make_device("sender")
    _trust_each_other(receiver, sender, max_file_bytes=100)
    server = running_server(receiver)

    with pytest.raises(TransferRefused) as refusal:
        send_file_to_peer("127.0.0.1", server.port, _make_file(tmp_path, "big.bin", 101), sender.identity, sender.trust_store)
    assert refusal.value.status == STATUS_TOO_LARGE

    send_file_to_peer("127.0.0.1", server.port, _make_file(tmp_path, "small.bin", 100), sender.identity, sender.trust_store)
    assert len(server.wait_for_received(1)) == 1


def test_empty_trust_store_refuses_to_build_a_context(tmp_path, make_device) -> None:
    lonely = make_device("lonely")
    with pytest.raises(NoTrustedPeersError):
        send_file_to_peer("127.0.0.1", 1, _make_file(tmp_path, "x.txt", 1), lonely.identity, lonely.trust_store)
