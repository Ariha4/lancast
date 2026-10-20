"""
Trust store: which peers this device accepts, and what each one may do.

Deny by default. A peer that isn't listed here can't complete a TLS
handshake with us at all, and a listed peer can only do what its entry
allows. Each entry keeps the peer's full certificate (TLS needs it to
verify the handshake) plus its permissions:

    can_send        may this peer push files to me?
    max_file_bytes  largest single file I'll accept from this peer

The store is a JSON file. Every load re-reads it from disk, so `lancast
revoke` takes effect on the next connection without restarting the server.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from lancast.identity import IdentityError, fingerprint_from_pem, normalize_fingerprint

TRUST_FILENAME = "trusted_peers.json"
DEFAULT_MAX_FILE_BYTES = 100 * 1024 * 1024  # 100 MiB
HARD_MAX_FILE_BYTES = 10 * 1024 * 1024 * 1024  # 10 GiB ceiling no entry can exceed
MAX_PEER_NAME_LENGTH = 64


@dataclass
class TrustedPeer:
    fingerprint: str
    name: str
    cert_pem: str
    can_send: bool = True
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES


class TrustStore:
    def __init__(self, home_dir: Path) -> None:
        self.path = home_dir / TRUST_FILENAME

    def _load(self) -> dict[str, TrustedPeer]:
        if not self.path.exists():
            return {}
        raw_entries = json.loads(self.path.read_text())
        peers_by_fingerprint: dict[str, TrustedPeer] = {}
        for fingerprint, entry in raw_entries.items():
            peers_by_fingerprint[fingerprint] = TrustedPeer(**entry)
        return peers_by_fingerprint

    def _save(self, peers_by_fingerprint: dict[str, TrustedPeer]) -> None:
        serializable = {}
        for fingerprint, peer in peers_by_fingerprint.items():
            serializable[fingerprint] = asdict(peer)

        # Write to a temp file and rename over the original, so a crash
        # mid-write can never leave a half-written (unparseable) trust store.
        self.path.parent.mkdir(parents=True, exist_ok=True)
        file_descriptor, temp_path = tempfile.mkstemp(dir=self.path.parent, prefix=".trust-")
        try:
            with os.fdopen(file_descriptor, "w") as file_handle:
                json.dump(serializable, file_handle, indent=2)
            os.chmod(temp_path, 0o600)
            os.replace(temp_path, self.path)
        except BaseException:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise

    def trust(
        self,
        cert_pem: str,
        name: str,
        can_send: bool = True,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        expected_fingerprint: str | None = None,
    ) -> TrustedPeer:
        """Add (or update) a peer. Returns the stored entry."""
        fingerprint = fingerprint_from_pem(cert_pem)
        if expected_fingerprint is not None and normalize_fingerprint(expected_fingerprint) != fingerprint:
            raise IdentityError("Certificate fingerprint does not match the fingerprint you expected; not trusting it")
        if max_file_bytes <= 0 or max_file_bytes > HARD_MAX_FILE_BYTES:
            raise ValueError(f"max_file_bytes must be between 1 and {HARD_MAX_FILE_BYTES}")

        peer = TrustedPeer(
            fingerprint=fingerprint,
            name=name[:MAX_PEER_NAME_LENGTH],
            cert_pem=cert_pem,
            can_send=can_send,
            max_file_bytes=max_file_bytes,
        )
        peers_by_fingerprint = self._load()
        peers_by_fingerprint[fingerprint] = peer
        self._save(peers_by_fingerprint)
        return peer

    def revoke(self, raw_fingerprint: str) -> bool:
        """Remove a peer. Returns False if it wasn't trusted in the first place."""
        fingerprint = normalize_fingerprint(raw_fingerprint)
        peers_by_fingerprint = self._load()
        if fingerprint not in peers_by_fingerprint:
            return False
        del peers_by_fingerprint[fingerprint]
        self._save(peers_by_fingerprint)
        return True

    def lookup(self, fingerprint: str) -> TrustedPeer | None:
        """The permission check. None means 'not trusted' -- the caller must deny."""
        return self._load().get(fingerprint)

    def all_peers(self) -> list[TrustedPeer]:
        return list(self._load().values())

    def trusted_certs_pem(self) -> str:
        """All trusted certificates concatenated, for SSLContext.load_verify_locations."""
        pem_blocks = []
        for peer in self._load().values():
            pem_blocks.append(peer.cert_pem)
        return "".join(pem_blocks)
