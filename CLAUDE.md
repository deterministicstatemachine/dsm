# DSM - Decentralized State Machine

## Project Overview

DSM is a decentralized state machine with cryptographic verification. It enables deterministic, verifiable state transitions across distributed participants.

## Build Commands

```bash
cargo build --workspace              # Build all crates
cargo test --workspace               # Run all tests
cargo clippy --workspace --all-targets -- -D warnings  # Lint check
cargo fmt --all -- --check           # Format check
cargo deny check                     # License + advisory check
cargo doc --workspace --no-deps      # Build documentation
```

## Architecture

Cargo workspace with 6 domain crates in `crates/`:

| Crate | Type | Purpose |
|-------|------|---------|
| `dsm-crypto` | lib | Hashing, signatures, key exchange, commitments |
| `dsm-core` | lib | State types, transition rules, validation, StateMachine trait |
| `dsm-network` | lib | P2P layer, peer discovery, message protocols |
| `dsm-storage` | lib | State persistence, Merkle trees, snapshot management |
| `dsm-consensus` | lib | Agreement protocols, multi-party transition validation |
| `dsm-cli` | bin | CLI interface and API server |

**Dependency flow:** `dsm-crypto` <- `dsm-core` <- `dsm-storage`, `dsm-network` <- `dsm-consensus` <- `dsm-cli`

## Key Conventions

- **No panics in library code** — `unwrap` is denied, `panic` is denied via clippy lints
- **All errors use `thiserror`** — typed error enums per crate
- **Async runtime is Tokio** — used in network, consensus, and CLI crates
- **Unsafe code is denied** workspace-wide
- **Edition 2024** — latest stable Rust
- **Conventional Commits** — `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`

## Testing

- Unit tests in each crate's `src/` modules
- Integration tests in each crate's `tests/` directory
- All new code requires tests
- CI runs tests on both Ubuntu and macOS

## Style

- Follow `rustfmt.toml` — 100 char line width, crate-level import granularity
- Satisfy clippy (pedantic + nursery) with zero warnings
- `missing_docs` warning enabled — document public items
