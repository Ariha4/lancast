import pytest

from lancast.identity import IdentityError
from lancast.trust import HARD_MAX_FILE_BYTES, TrustStore


def test_empty_store_trusts_no_one(make_device) -> None:
    alice = make_device("alice")
    bob = make_device("bob")

    assert alice.trust_store.lookup(bob.identity.fingerprint) is None


def test_trust_then_lookup_returns_permissions(make_device) -> None:
    alice = make_device("alice")
    bob = make_device("bob")

    alice.trust_store.trust(bob.cert_pem, name="bob", can_send=False, max_file_bytes=1024)
    entry = alice.trust_store.lookup(bob.identity.fingerprint)

    assert entry is not None
    assert entry.name == "bob"
    assert entry.can_send is False
    assert entry.max_file_bytes == 1024


def test_trust_persists_across_store_instances(make_device) -> None:
    alice = make_device("alice")
    bob = make_device("bob")
    alice.trust_store.trust(bob.cert_pem, name="bob")

    reopened_store = TrustStore(alice.home)
    assert reopened_store.lookup(bob.identity.fingerprint) is not None


def test_revoke_removes_peer(make_device) -> None:
    alice = make_device("alice")
    bob = make_device("bob")
    alice.trust_store.trust(bob.cert_pem, name="bob")

    assert alice.trust_store.revoke(bob.identity.fingerprint) is True
    assert alice.trust_store.lookup(bob.identity.fingerprint) is None
    assert alice.trust_store.revoke(bob.identity.fingerprint) is False


def test_trust_refuses_cert_that_does_not_match_expected_fingerprint(make_device) -> None:
    """Someone hands you a cert claiming to be Bob's. Bob read you his real
    fingerprint. The mismatch must stop the trust from being recorded."""
    alice = make_device("alice")
    bob = make_device("bob")
    mallory = make_device("mallory")

    with pytest.raises(IdentityError):
        alice.trust_store.trust(mallory.cert_pem, name="bob", expected_fingerprint=bob.identity.fingerprint)
    assert alice.trust_store.all_peers() == []


@pytest.mark.parametrize("bad_limit", [0, -1, HARD_MAX_FILE_BYTES + 1])
def test_trust_rejects_out_of_range_size_limits(make_device, bad_limit: int) -> None:
    alice = make_device("alice")
    bob = make_device("bob")

    with pytest.raises(ValueError):
        alice.trust_store.trust(bob.cert_pem, name="bob", max_file_bytes=bad_limit)
