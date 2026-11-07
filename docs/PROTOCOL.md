# rustun/1 — wire protocol specification

All messages are single UDP datagrams. Multi-byte integers are little-endian.
The first byte is the message type. Any datagram that fails authentication is
discarded without a response.

## Message types

| Type | Name | Purpose |
|---|---|---|
| `0x01` | INIT | initiator handshake request |
| `0x02` | RESP | responder handshake reply |
| `0x04` | DATA | encrypted transport datagram |

## Handshake

### INIT (113 bytes)

```
[0x01][nonce:16][eph_pub:32][static_pub:32][mac:32]
```

- `nonce` — 16 random bytes, echoed in RESP to bind the exchange
- `eph_pub` — initiator's ephemeral X25519 public key (forward secrecy)
- `static_pub` — initiator's static public key (peer identity)
- `mac` — `blake2s256(DH(c_static, s_static) || nonce || eph_pub || static_pub)`

The MAC proves the sender possesses the static private key corresponding to
`static_pub`. A datagram with an unrecognized `static_pub` or an invalid MAC
is dropped silently, giving the port scanner-invisibility property.

### RESP (85 bytes)

```
[0x02][idx:4][nonce:16][eph_pub:32][mac:32]
```

- `idx` — session index chosen by the responder; tags subsequent DATA packets
- `mac` — `blake2s256(DH(s_static, c_static) || idx || nonce || eph_pub)`

## Key schedule

Both sides compute three Diffie–Hellman values and concatenate them **in role
order**, not self order:

```
keymat = DH(e_i, e_r) || DH(s_i, e_r) || DH(e_i, s_r)        (96 bytes)
k1     = blake2s256(keymat || 0x01)
k2     = blake2s256(keymat || 0x02)
```

| Role | tx key | rx key |
|---|---|---|
| initiator | `k1` | `k2` |
| responder | `k2` | `k1` |

The ephemeral×ephemeral DH provides forward secrecy; the two static×ephemeral
DHs provide mutual authentication.

## Transport — DATA

```
[0x04][idx:4][ctr:8][ciphertext][poly1305 tag:16]
```

- AEAD: ChaCha20-Poly1305
- Nonce: `0x00000000 || ctr` (12 bytes), counter unique per (key, direction)
- `idx` selects the receiving session, permitting overlap during rekey

## Replay protection

2048-bit sliding window keyed by counter. The window is advanced **only after
successful AEAD verification**, so forged counters cannot slide the window
past legitimate packets. A datagram that verifies but carries an already-seen
or out-of-window counter is rejected as a replay.

## Timers

| Constant | Value | Effect |
|---|---|---|
| `REKEY_AFTER_SECS` | 120 | initiator runs a fresh handshake (new ephemeral keys) |
| `KEEPALIVE_SECS` | 25 | empty DATA datagram preserves NAT mapping |
| `DEAD_PEER_SECS` | 10 | payload sent with no valid inbound → re-handshake |
| init retransmit | 5 | pending INIT resent until RESP arrives |

## Notes and limitations

- `static_pub` is transmitted in the clear; identity hiding is out of scope
  for v1 (see SECURITY.md).
- The keyed MAC uses a prefix-key BLAKE2s construction; BLAKE2's HAIFA
  structure resists length extension.
- Only the initiator drives rekey. Responder-initiated rekey is not
  implemented in v1.
