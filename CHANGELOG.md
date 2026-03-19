# Changelog

All notable changes to DSM Protocol will be documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)  
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

---

## [0.1.0-beta.1] — 2026-02-19

### Added
- **Bilateral BLE offline transfer** — two-device token transfers over Bluetooth LE with no internet connection required; full state-machine handshake with cryptographic verification on both ends
- **Deterministic state machine core** — hash-chained transaction history with no server-side state; each state transition is irreversible and cryptographically bound to the previous
- **DSM SDK (Rust)** — JNI-exposed library for Android providing wallet management, token operations, BLE transport, and storage-node communication
- **Local storage nodes** — five-node SQLite-backed storage layer with deterministic hashing-based assignment and configurable replication
- **Android client** — React Native/WebView hybrid app with hardware-backed key storage, BLE pairing flow, and integrated diagnostics overlay
- **local Bitcoin test tooling** — deterministic test-faucet utilities enabled only in early test/debug builds
- **16 KB page-size support** — native libs built with `-Wl,-z,max-page-size=16384` for Android 15+ high-RAM device compatibility
- **`make` build system** — single Makefile entrypoint for all developer tasks (`make help` for full list)

### Changed
- All storage-node endpoints default to `127.0.0.1` (loopback via `adb reverse`) instead of a LAN IP
- Version bumped from `0.1.0` to `0.1.0-beta.1` across all crates, Android app, and frontend

### Security
- Removed hardcoded RSA public key from `storage_node_config.toml`; replaced with placeholder
- `.cargo/config.toml` (machine-local NDK paths) is now gitignored; use `make setup` to generate from template
- `.so` build artifacts are gitignored and must be built locally via `make android-libs`

---

## [Unreleased]

_Changes on `master` not yet tagged._
