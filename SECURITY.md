# Security policy

## Audit status

rustun has not undergone independent security review or cryptographic audit.
The protocol composition — handshake structure, key-derivation ordering,
replay rules — is original work. Cryptographic primitives are supplied by
widely reviewed libraries (`x25519-dalek`, `chacha20poly1305`, `blake2`).

Deployment decisions should account for this status. For high-assurance
requirements, prefer audited protocols (WireGuard, OpenVPN) until this
implementation receives external review.

## Reporting a vulnerability

Please open a GitHub issue marked `[security]`, or contact the maintainer via
the GitHub profile listed on this repository. Include a reproduction or the
relevant code path. The protocol surface is deliberately small — the entire
handshake and session implementation resides in `src/proto.rs`.

## Design rationale

- **Silent-drop policy.** Unauthenticated or malformed datagrams receive no
  response; the service is indistinguishable from a closed port to scanners.
- **Post-authentication replay marking.** The sliding window advances only
  after AEAD verification succeeds, preventing forged counters from evicting
  legitimate sequence slots.
- **Session-indexed transport.** DATA datagrams carry a session index,
  allowing bounded overlap of old and new sessions during rekey without
  key-confusion.
- **Counter-reset safety.** Counters reset per session, but session keys are
  derived from fresh ephemeral material per handshake, so (key, nonce) reuse
  cannot occur.
- **Kill switch scope.** The nftables `inet` family covers IPv4 and IPv6
  simultaneously; activation blocks all non-tunnel egress, including IPv6
  and DNS paths.
- **No logging.** Neither endpoint records packet contents, peer addresses,
  or session metadata beyond single-line lifecycle events on stderr.

## Known limitations

- Client static public keys are transmitted unencrypted in handshake
  initiation datagrams. An observer can learn *which* key is connecting,
  though not the corresponding private key or traffic contents.
- The handshake MAC uses a prefix-keyed BLAKE2s construction rather than a
  dedicated keyed-MAC mode. BLAKE2's structure resists length extension, but
  this is a documented deviation from the most conventional construction.
- Responder-initiated rekey is not implemented; all rekeying is
  initiator-driven.

## Threat model

| Addressed | Out of scope |
|---|---|
| On-path observation or tampering between client and server | Correlation of flows across both ends by a global passive adversary |
| Destination hosts learning the client source address | Traffic inspection by the relay operator at the exit point |
| Active port scanning and protocol fingerprinting | Compromise of endpoint private keys or of either host |
| Replay, forgery, and injection of datagrams | Traffic-analysis side channels inherent to packet timing/size |
| IPv6, DNS, and non-tunnel egress leaks (kill switch) | Application-layer leaks that disclose identifiers other than the underlay IP |

## Supported versions

Only the latest commit on `master` receives fixes; there are no maintained
release branches.
