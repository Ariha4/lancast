# LANCast Threat Model

What LANCast defends against, what it doesn't, and which piece of code does
the defending. Every "Control" below has a test; the test name is listed so
the claim can be checked.

## What we're protecting

1. **The receiver's disk.** Only peers the user chose to trust should be able
   to write files, and only inside the destination folder.
2. **The receiver's availability.** One bad peer shouldn't be able to exhaust
   its memory, disk, or threads.
3. **The sender's files.** A file should only go to the device the sender
   meant, not to whoever answers on that IP and port.

## Who the attacker is

Someone on the same LAN (coffee-shop Wi-Fi, a shared office network). They can:

- send any UDP packet, including fake discovery beacons
- open TCP connections to the receiver and send arbitrary bytes
- run their own LANCast with their own keypair
- be on the network path between two peers (ARP spoofing), so they can
  intercept, modify, or redirect traffic

They do **not** have a trusted device's private key. If they do (a stolen
laptop), see "Out of scope."

## Trust boundary

A peer crosses from untrusted to trusted in one place: the mutual TLS
handshake, which succeeds only if the peer proves it holds the private key
for a certificate in the trust store. Everything a peer sends before that
handshake, and everything in a beacon, is untrusted input.

Trust itself is created by a human: `lancast trust` shows the certificate's
fingerprint and asks the user to confirm it matches what the peer told them
out of band (read aloud, sent in a chat they already trust). This is the same
model as SSH host keys.

## Threats and controls

| # | Threat | Control | Code | Test |
|---|---|---|---|---|
| 1 | A stranger sends files to my machine | Mutual TLS; only trusted certificates are verification anchors, so the handshake fails for anyone else. Deny by default: an empty trust store refuses everyone | `tls.py`, `trust.py` | `test_untrusted_sender_is_rejected_during_handshake`, `test_empty_trust_store_refuses_to_build_a_context` |
| 2 | An impostor answers at my friend's IP and receives my file | The sender also verifies the receiver's certificate, and can pin the exact fingerprint with `send --fingerprint` | `transfer.py: send_file_to_peer` | `test_sender_refuses_an_untrusted_receiver`, `test_sender_checks_expected_fingerprint` |
| 3 | Someone on the path reads or alters a transfer | TLS 1.3 encrypts and authenticates all traffic | `tls.py` | (covered by the TLS library; the handshake tests show TLS is actually in use) |
| 4 | A fake beacon claims to be "alice-laptop" | Beacon names are labels, not identity. `discover` shows the fingerprint and whether it's trusted; the handshake is what proves identity | `discovery.py`, `cli.py: cmd_discover` | `test_valid_beacon_parses_with_fingerprint` |
| 5 | A trusted peer does more than I allowed | Per-peer permissions checked before any payload is read: `can_send`, `max_file_bytes` | `trust.py`, `transfer.py: receive_file` | `test_receive_only_peer_cannot_send`, `test_per_peer_size_limit_is_enforced_before_payload` |
| 6 | A peer I used to trust keeps access | `lancast revoke`; the server rebuilds its TLS context from the trust store on every connection, so it takes effect without a restart | `transfer.py: _handle_client` | `test_revoked_peer_is_rejected_without_restarting_server` |
| 7 | I trust a certificate someone swapped | `trust` requires the user to confirm the fingerprint, or pass `--fingerprint`, and refuses on mismatch | `trust.py: trust` | `test_trust_refuses_cert_that_does_not_match_expected_fingerprint` |
| 8 | Path traversal: a filename like `../../.bashrc` | Strip everything before the last `/` or `\`, then reject `''`, `.`, `..` and NUL bytes | `transfer.py: safe_filename` | `test_receive_file_strips_path_components`, `test_backslash_path_components_are_stripped`, `test_dot_and_nul_filenames_are_rejected` |
| 9 | Overwriting an existing file | Files are opened create-exclusive (`"xb"`); a name clash becomes `name (1).ext` | `transfer.py: _open_unique` | `test_existing_file_is_never_overwritten` |
| 10 | Disk or memory exhaustion: claim a 2^60-byte payload | Size checked against the peer's limit before reading the payload; payload streamed to disk in 64 KiB chunks, never held in memory | `transfer.py: receive_file` | `test_oversized_payload_is_refused_before_any_payload_is_read` |
| 11 | Slow-loris: connect and send nothing | Timeout on every blocking read, including the TLS handshake | `transfer.py: FileReceiverServer` | `test_stalled_connection_times_out` |
| 12 | Thread exhaustion: open hundreds of connections | At most 8 concurrent transfers; extra connections are closed immediately | `transfer.py: serve_forever` | `test_connections_beyond_concurrency_cap_are_dropped` |
| 13 | Crashing the handler with bad bytes | Invalid UTF-8 filenames become a `ProtocolError`, which the server handles | `transfer.py: receive_file` | `test_invalid_utf8_filename_raises_protocol_error` |
| 14 | Half-written files left after a dropped connection | Partial files are deleted when a transfer fails | `transfer.py: receive_file` | `test_interrupted_transfer_leaves_no_partial_file` |
| 15 | Malformed beacons poisoning the peer list or the terminal | Port must be an int in 1-65535; names stripped of non-printable characters (no ANSI escape injection) and capped at 64 chars; bad fingerprints dropped | `discovery.py: parse_beacon` | `test_beacon_with_invalid_port_is_dropped`, `test_beacon_name_cannot_inject_terminal_escape_codes` |
| 16 | Another local user reads my private key | Key file created with mode `0600` before any bytes are written; `~/.lancast` is `0700` | `identity.py` | `test_private_key_is_readable_only_by_owner` |

## Out of scope (known limits)

- **A stolen private key.** Whoever holds a trusted key *is* that peer until
  it's revoked on every device that trusts it. There's no central revocation,
  because there's no central authority.
- **Discovery is still unauthenticated.** A flood of fake beacons can fill the
  `discover` list. They can't be trusted or sent to without passing the
  handshake, but they are noise.
- **A malicious trusted peer** can still send any file type within its size
  limit. LANCast doesn't scan content.
- **Rate limiting per peer.** The concurrency cap is global, so one trusted
  peer can use all 8 slots.
- **The key isn't encrypted at rest.** It relies on file permissions, like an
  unencrypted SSH key.
