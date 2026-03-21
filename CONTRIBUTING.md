# Contributing to DSM Protocol

Thank you for taking part in the beta. This document covers how to report issues, suggest improvements, and (if you'd like) contribute code.

---

## Before You Start

- Follow the [Code of Conduct](CODE_OF_CONDUCT.md).
- Use [SUPPORT.md](SUPPORT.md) for general help and [SECURITY.md](SECURITY.md) for private vulnerability reports.
- If your change touches DLV specs, policy specs, or generated clients, read [dsm-gen/README.md](dsm-gen/README.md) and [Chapter 16 of the developer handbook](docs/book/16-code-generation.md) first.

---

## Beta Testing

### Reporting Bugs

1. Open an issue at **Issues → New Issue**
2. Use the **Bug Report** template if available, otherwise include:
   - Device model and Android version
   - DSM Protocol app version (visible in Settings → About)
   - Steps to reproduce
   - What you expected vs. what happened
   - Attach the diagnostics file: in-app **Settings → Export Diagnostics**
   - Attach `adb logcat` output if you have it: `adb logcat -d > logcat.txt`

### Reporting Security Issues

Do **not** open a public issue for security vulnerabilities. Follow [SECURITY.md](SECURITY.md) and email **team@irrefutablelabs.org** with details. We will respond within 48 hours.

### Feature Requests

Open an issue with the **Enhancement** label. Describe the use case, not just the feature.

---

## Development

### Prerequisites

See [Chapter 3 — Development Setup](docs/book/03-development-setup.md) for the full environment setup guide.

```
Base development: Rust stable (rustup), Node.js 20+ (via nvm recommended), protoc
Android work only: cargo-ndk, Android NDK 27.x, Android SDK with platform-tools (adb), Java 17+, ANDROID_NDK_HOME
```

### Branching

| Branch | Purpose |
|---|---|
| `main` | Stable; all PRs target this |
| `release/x.y.z` | Release preparation; created from `main` |
| `fix/short-description` | Bug fixes |
| `feat/short-description` | New features |

### Making Changes

```bash
git checkout -b fix/your-description
# make changes
make lint
make build
make typecheck
# then run the targeted tests for the area you changed
git push origin fix/your-description
# open a PR against main
```

Targeted validation examples:
- Rust / SDK / storage work: `make test-rust` or focused `cargo test --package ...`
- Frontend work: `make test-frontend`
- Android / JNI work: `make android`

If you are changing vault or policy specifications, validate and regenerate through `dsm-gen` instead of hand-editing generated clients:

```bash
cargo run -p dsm-gen -- validate path/to/spec.yaml
cargo run -p dsm-gen -- client path/to/spec.yaml --lang ts
```

### Primitive Changes

Treat the DSM primitive as closed by default.

- Do not expand the primitive for convenience, flexibility, or future-proofing.
- New capabilities should be modeled above the primitive as composed protocols.
- Primitive changes are reserved for soundness fixes, ambiguity removal, simplification without
  expanding acceptance, or replacement of a broken assumption.

If your change touches acceptance, ordering, proof verification, identity binding, or fork
exclusion, read [Chapter 17 — DSM Primitive](docs/book/17-dsm-primitive.md) first.

### PR Checklist

- [ ] `make lint` passes (no clippy warnings, fmt clean)
- [ ] `make build` passes
- [ ] `make typecheck` passes for frontend-affecting changes
- [ ] Relevant targeted tests ran for the surfaces touched (`make test-rust`, `make test-frontend`, focused package tests, or Android build/install checks)
- [ ] `make android` produces a working APK if Android or JNI surfaces changed
- [ ] No personal paths, keys, or credentials in any file
- [ ] `git grep -r "TODO\|FIXME\|HACK\|XXX"` returns zero results (these are banned — no exceptions)

### Commit Style

Use conventional commits:
```
fix: bluetooth pairing state not reset on disconnect
feat: add diagnostics export button to settings screen
chore: bump cargo dependencies
docs: update SETUP.md with Linux NDK path example
```

---

## License

This project is dual-licensed under [MIT](LICENSE-MIT) and [Apache 2.0](LICENSE-APACHE). By submitting a pull request, you agree that your contribution will be dual-licensed under these same terms, without any additional conditions.

---

## Contact

- Issues: GitHub Issues on this repo
- Security: info@irrefutablelabs.org
- General: see [SUPPORT.md](SUPPORT.md)
- Telegram Dev Group: https://t.me/+nQsx8Or2YQo1MDcx
