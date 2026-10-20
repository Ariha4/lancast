import os
import stat
from pathlib import Path

import pytest

from lancast.identity import (
    KEY_FILENAME,
    IdentityError,
    format_fingerprint,
    load_or_create_identity,
    normalize_fingerprint,
)


def test_identity_is_stable_across_loads(tmp_path: Path) -> None:
    first_load = load_or_create_identity(tmp_path, "alice")
    second_load = load_or_create_identity(tmp_path, "alice")

    assert first_load.fingerprint == second_load.fingerprint
    assert len(first_load.fingerprint) == 64


def test_different_devices_get_different_fingerprints(tmp_path: Path) -> None:
    alice = load_or_create_identity(tmp_path / "alice", "alice")
    bob = load_or_create_identity(tmp_path / "bob", "bob")

    assert alice.fingerprint != bob.fingerprint


def test_private_key_is_readable_only_by_owner(tmp_path: Path) -> None:
    load_or_create_identity(tmp_path, "alice")

    key_mode = stat.S_IMODE(os.stat(tmp_path / KEY_FILENAME).st_mode)
    assert key_mode == 0o600


def test_half_an_identity_is_not_silently_replaced(tmp_path: Path) -> None:
    """If only the cert survives, regenerating would change this device's
    fingerprint and break every peer that trusts it. Fail loudly instead."""
    load_or_create_identity(tmp_path, "alice")
    (tmp_path / KEY_FILENAME).unlink()

    with pytest.raises(IdentityError):
        load_or_create_identity(tmp_path, "alice")


def test_fingerprint_formats_round_trip() -> None:
    raw = "ab" * 32
    assert normalize_fingerprint(format_fingerprint(raw)) == raw


@pytest.mark.parametrize("bad_fingerprint", ["abc", "zz" * 32, ""])
def test_normalize_rejects_malformed_fingerprints(bad_fingerprint: str) -> None:
    with pytest.raises(IdentityError):
        normalize_fingerprint(bad_fingerprint)
