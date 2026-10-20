"""
Device identity: one keypair and self-signed certificate per machine.

Why certificates instead of the name in the beacon: anyone on the LAN can
broadcast a beacon claiming to be "alice-laptop". A name proves nothing. A
private key does -- during the TLS handshake each side signs with its key,
so it can only succeed if the peer actually holds the key that matches the
certificate it presented.

We don't use a certificate authority. Each device's certificate is
self-signed, and peers are identified by the SHA-256 fingerprint of that
certificate (the same idea as SSH host keys). Two people confirm each
other's fingerprints out of band -- reading them aloud, a chat message --
and from then on the fingerprint is the identity.
"""

from __future__ import annotations

import datetime
import hashlib
import os
import ssl
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

KEY_FILENAME = "identity_key.pem"
CERT_FILENAME = "identity_cert.pem"
CERT_VALID_DAYS = 3650
FINGERPRINT_HEX_LENGTH = 64  # SHA-256 -> 32 bytes -> 64 hex characters


class IdentityError(Exception):
    """Raised when an identity or fingerprint is missing or malformed."""


@dataclass
class Identity:
    key_path: Path
    cert_path: Path
    fingerprint: str


def default_home() -> Path:
    """Where LANCast keeps its identity and trust store (~/.lancast by default)."""
    configured_home = os.environ.get("LANCAST_HOME")
    if configured_home:
        return Path(configured_home)
    return Path.home() / ".lancast"


def fingerprint_from_der(der_bytes: bytes) -> str:
    """SHA-256 over the DER-encoded certificate, as lowercase hex."""
    return hashlib.sha256(der_bytes).hexdigest()


def fingerprint_from_pem(pem_text: str) -> str:
    der_bytes = ssl.PEM_cert_to_DER_cert(pem_text)
    return fingerprint_from_der(der_bytes)


def normalize_fingerprint(raw_fingerprint: str) -> str:
    """Accept 'AB:CD:...' or 'abcd...' and return 64 lowercase hex characters."""
    cleaned = raw_fingerprint.strip().lower().replace(":", "").replace(" ", "")
    if len(cleaned) != FINGERPRINT_HEX_LENGTH:
        raise IdentityError(f"Fingerprint must be {FINGERPRINT_HEX_LENGTH} hex characters, got {len(cleaned)}")
    for character in cleaned:
        if character not in "0123456789abcdef":
            raise IdentityError(f"Fingerprint contains a non-hex character: {character!r}")
    return cleaned


def format_fingerprint(fingerprint: str) -> str:
    """Group into colon-separated pairs so it is easier to read aloud."""
    pairs = []
    for index in range(0, len(fingerprint), 2):
        pairs.append(fingerprint[index : index + 2].upper())
    return ":".join(pairs)


def _write_private_file(path: Path, data: bytes) -> None:
    """Create a file readable only by the owner (0600) before any bytes land in it."""
    file_descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(file_descriptor, "wb") as file_handle:
        file_handle.write(data)


def _generate_identity(home_dir: Path, device_name: str) -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device_name[:64] or "lancast-device")])

    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)  # self-signed: issuer is the device itself
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=CERT_VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    _write_private_file(home_dir / KEY_FILENAME, key_bytes)
    (home_dir / CERT_FILENAME).write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


def load_or_create_identity(home_dir: Path, device_name: str) -> Identity:
    """Load this device's identity, generating a new keypair the first time."""
    home_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(home_dir, 0o700)

    key_path = home_dir / KEY_FILENAME
    cert_path = home_dir / CERT_FILENAME
    key_exists = key_path.exists()
    cert_exists = cert_path.exists()

    if key_exists != cert_exists:
        # Half an identity is a broken state. Regenerating silently would
        # change this device's fingerprint behind the user's back.
        raise IdentityError(f"Found only one of {KEY_FILENAME} / {CERT_FILENAME} in {home_dir}; refusing to guess")
    if not key_exists:
        _generate_identity(home_dir, device_name)

    fingerprint = fingerprint_from_pem(cert_path.read_text())
    return Identity(key_path=key_path, cert_path=cert_path, fingerprint=fingerprint)
