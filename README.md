# rustun

A self-contained virtual private network implementation in Rust, built around
a custom encrypted UDP transport protocol. A single statically-linked binary
provides both server and client modes — no external services, no accounts,
no telemetry, no logs.

## Overview

rustun establishes an authenticated, encrypted point-to-point tunnel over UDP.
It is designed for self-hosted deployments: one instance runs on a public
host as a relay/exit node, the other on the client machine. All traffic
between the two endpoints is encrypted and integrity-protected, and observers
on the client side of the path see only opaque UDP datagrams to a single port.

## Features

- Custom authenticated handshake (X25519 — ephemeral + static Diffie–Hellman)
- Forward secrecy via ephemeral key exchange, automatic rekey every 120 s
- ChaCha20-Poly1305 authenticated encryption per datagram
- Sliding-window replay protection (2048 entries), applied post-authentication
- nftables kill switch covering IPv4 **and** IPv6
- NAT-traversal keepalives, dead-peer detection with automatic re-handshake
- Endpoint roaming — peer address re-learned from authenticated packets
- Multi-peer server mode with per-peer tunnel addressing
- Silent-drop policy: malformed or unauthenticated datagrams receive no reply

## Protocol

See [docs/PROTOCOL.md](docs/PROTOCOL.md) for the wire format, handshake
construction, and key schedule.

## Requirements

- Linux with `/dev/net/tun`, `iproute2`, and `nftables`
- Rust stable toolchain (build time only)

## Building

```sh
cargo build --release
```

Produces a single ~600 KB static executable at `target/release/rustun`.

## Usage

```sh
# Generate a keypair (run on each side)
rustun genkey

# Server — public relay host
rustun server --key <server-private-key> --listen 0.0.0.0:51820 \
    --addr 10.99.0.1/24 --peer <client-public-key>=10.99.0.2 --nat <out-iface>

# Client
rustun client --key <client-private-key> --server-pub <server-public-key> \
    --endpoint <server-address>:51820 --addr 10.99.0.2/24 \
    --route all --killswitch
```

`--route all` directs all outbound traffic through the tunnel interface.
`--killswitch` installs nftables rules permitting only tunnel egress and the
endpoint socket; the rules are removed on clean shutdown.

## Testing

```sh
cargo test          # protocol unit tests
sudo tests/e2e.sh   # integration suite (requires root; iproute2, tcpdump,
                    # nmap, python3)
```

The integration suite provisions isolated kernel network namespaces joined by
veth pairs and verifies, with live packet capture on the wire:

- Encrypted connectivity through the tunnel
- Absence of non-tunnel IP traffic on the client interface
- Kill-switch enforcement of direct-egress attempts
- Resilience under malformed datagram floods (1,200 packets)
- Source-address masking — egress hosts observe only the server address
- Absence of plaintext DNS traffic on the underlay interface
- Automatic session re-establishment after server restart
- Silent operation under UDP port scanning

## Security

This project has not undergone independent security review. The protocol
composition is original; cryptographic primitives are provided by the audited
RustCrypto/dalek libraries (`x25519-dalek`, `chacha20poly1305`, `blake2`).
See [SECURITY.md](SECURITY.md) for the threat model, design rationale, and
known limitations before relying on rustun in high-assurance contexts.

## Repository layout

    src/keys.rs       key generation and base64 encoding
    src/proto.rs      wire format, handshake, session keys, replay window
    src/node.rs       packet pump: TUN <-> session <-> UDP
    src/syslinux.rs   TUN device (ioctl), routes, nftables, NAT
    src/main.rs       CLI entry point and signal handling
    tests/e2e.sh      namespace-based integration scenarios

## License

MIT — see [LICENSE-MIT](LICENSE-MIT).
