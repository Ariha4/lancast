"""
Mutual TLS contexts built from this device's identity and its trust store.

"Mutual" means both sides present a certificate and both sides verify the
other's. A normal HTTPS site only proves the server's identity; here the
receiver also needs to know who is sending, because that is what decides
whether the transfer is allowed.

The trusted certificates are loaded as the only verification anchors, so
OpenSSL rejects any peer whose certificate isn't in our trust store during
the handshake itself, before a single byte of application data is read.
Hostname checking is off on purpose: on a LAN, IP addresses change and
names in beacons are unauthenticated. The fingerprint is the identity.
"""

from __future__ import annotations

import ssl

from lancast.identity import Identity, IdentityError, fingerprint_from_der
from lancast.trust import TrustStore


class NoTrustedPeersError(IdentityError):
    """Raised when the trust store is empty, so every peer would be rejected."""


def _base_context(protocol: int, identity: Identity, trust_store: TrustStore) -> ssl.SSLContext:
    trusted_certs = trust_store.trusted_certs_pem()
    if not trusted_certs:
        raise NoTrustedPeersError("No trusted peers yet. Add one with `lancast trust <cert.pem>`.")

    context = ssl.SSLContext(protocol)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile=str(identity.cert_path), keyfile=str(identity.key_path))
    context.load_verify_locations(cadata=trusted_certs)
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def make_server_context(identity: Identity, trust_store: TrustStore) -> ssl.SSLContext:
    """Built fresh per connection so a revoke takes effect immediately."""
    return _base_context(ssl.PROTOCOL_TLS_SERVER, identity, trust_store)


def make_client_context(identity: Identity, trust_store: TrustStore) -> ssl.SSLContext:
    context = _base_context(ssl.PROTOCOL_TLS_CLIENT, identity, trust_store)
    context.check_hostname = False  # identity is the pinned certificate, not a hostname
    context.verify_mode = ssl.CERT_REQUIRED  # still verify the certificate itself
    return context


def peer_fingerprint(tls_socket: ssl.SSLSocket) -> str:
    der_bytes = tls_socket.getpeercert(binary_form=True)
    if der_bytes is None:
        raise IdentityError("Peer did not present a certificate")
    return fingerprint_from_der(der_bytes)
