# DSM — Decentralized State Machine

[![CI](https://github.com/deterministicstatemachine/dsm/actions/workflows/ci.yml/badge.svg)](https://github.com/deterministicstatemachine/dsm/actions/workflows/ci.yml)
[![Security](https://github.com/deterministicstatemachine/dsm/actions/workflows/security.yml/badge.svg)](https://github.com/deterministicstatemachine/dsm/actions/workflows/security.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A decentralized state machine with cryptographic verification. DSM enables deterministic, verifiable state transitions across distributed participants without requiring trust in any single party.

## Key Properties

- **Deterministic** — identical inputs always produce identical state transitions
- **Cryptographically verifiable** — every state transition is signed and hash-chained
- **Decentralized** — no single point of failure or trust
- **Auditable** — full transition history with Merkle proofs

## Architecture

```
┌─────────┐
│ dsm-cli │  CLI interface & API server
└────┬────┘
     │
┌────┴──────────┐
│ dsm-consensus │  Agreement protocols
└────┬──────────┘
     │
┌────┴────────┬──────────────┐
│ dsm-network │ dsm-storage  │  P2P layer & persistence
└────┬────────┴──────┬───────┘
     │               │
     └──────┬────────┘
      ┌─────┴─────┐
      │  dsm-core  │  State machine logic
      └─────┬──────┘
      ┌─────┴──────┐
      │ dsm-crypto │  Cryptographic primitives
      └────────────┘
```

| Crate | Description |
|-------|-------------|
| [`dsm-crypto`](crates/dsm-crypto) | Hashing (SHA-256), digital signatures (Ed25519), key exchange (X25519) |
| [`dsm-core`](crates/dsm-core) | State types, transition rules, validation, `StateMachine` trait |
| [`dsm-network`](crates/dsm-network) | P2P peer discovery, message protocols, state synchronization |
| [`dsm-storage`](crates/dsm-storage) | State persistence, snapshots, Merkle tree proofs |
| [`dsm-consensus`](crates/dsm-consensus) | Multi-party agreement protocols, consensus finality |
| [`dsm-cli`](crates/dsm-cli) | Command-line interface and API server |

## Getting Started

### Prerequisites

- [Rust](https://rustup.rs/) 1.85.0 or later (stable)

### Build

```bash
git clone https://github.com/deterministicstatemachine/dsm.git
cd dsm
cargo build --workspace
```

### Test

```bash
cargo test --workspace
```

### Lint

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Contributing

We welcome contributions! Please read our [Contributing Guide](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md) before submitting a pull request.

For security vulnerabilities, please see our [Security Policy](SECURITY.md). **Do not file public issues for security vulnerabilities.**

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
