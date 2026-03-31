# Chapter 14 — Contributing

How to report issues, submit code, and contribute to DSM.

---

## Reporting Bugs

1. Open an issue using the **Bug Report** template
2. Include:
   - Device model and Android version
   - DSM Wallet app version (Settings → About)
   - Steps to reproduce
   - Expected vs. actual behavior
   - Diagnostics file: in-app **Settings → Export Diagnostics**
   - `adb logcat` output: `adb logcat -d > logcat.txt`

## Reporting Security Issues

Do **not** open a public issue. Follow [SECURITY.md](../../SECURITY.md) and email **team@irrefutablelabs.org** with details. Response within 48 hours.

## Feature Requests

Open an issue with the **Enhancement** label. Describe the use case, not just the feature.

## Project Policies

- Follow the [Code of Conduct](../../CODE_OF_CONDUCT.md).
- Use [SUPPORT.md](../../SUPPORT.md) for general help and contributor support.
- If your change touches DLV specs, policy specs, or generated clients, read [Chapter 16 — Code Generation](16-code-generation.md) and [dsm-gen/README.md](../../dsm-gen/README.md).

---

## Development Prerequisites

See [Chapter 3 — Development Setup](03-development-setup.md) for the full guide.

```
Base development: Rust stable (rustup), Node.js 20+ (via nvm recommended), protoc, PostgreSQL
Android work only: cargo-ndk, Android NDK 27.x, Android SDK with platform-tools (adb), Java 17+, ANDROID_NDK_HOME
```

---

## Branching

| Branch | Purpose |
|--------|---------|
| `master` | Stable; all PRs target this |
| `release/x.y.z` | Release preparation; created from `master` |
| `fix/short-description` | Bug fixes |
| `feat/short-description` | New features |

---

## Making Changes

```bash
git checkout -b fix/your-description
# make changes
make lint
make build
make typecheck
# then run the targeted tests for the area you changed
git push origin fix/your-description
# open a PR against master
```

Targeted validation examples:
- Rust / SDK / storage work: `make test-rust` or focused `cargo test --package ...`
- Frontend work: `make test-frontend`
- Android / JNI work: `make android`

---

## PR Checklist

- [ ] `make lint` passes (no clippy warnings, fmt clean)
- [ ] `make build` passes
- [ ] `make typecheck` passes for frontend-affecting changes
- [ ] Relevant targeted tests ran for the surfaces touched (`make test-rust`, `make test-frontend`, focused package tests, or Android build/install checks)
- [ ] `make android` produces a working APK if Android or JNI surfaces changed
- [ ] No personal paths, keys, or credentials in any file
- [ ] `git grep -r "TODO\|FIXME\|HACK\|XXX"` returns zero results (banned)
- [ ] Protobuf types regenerated if `proto/dsm_app.proto` was changed
- [ ] No JSON in protocol code
- [ ] No wall-clock time in protocol logic
- [ ] No hex encoding in core code

---

## Commit Style

Use conventional commits:

```
fix: bluetooth pairing state not reset on disconnect
feat: add diagnostics export button to settings screen
chore: bump cargo dependencies
docs: update storage node API endpoint reference
```

---

## Code Standards

### Hard Invariants

All contributions must respect the [12 hard invariants](01-introduction.md#the-12-hard-invariants). CI gates enforce these automatically.

### Spec-First

Before modifying protocol code, read the public authoritative material for that feature area in the handbook, appendices, papers, and `proto/dsm_app.proto`. Start with [Appendix C — Spec Index](appendix-c-spec-index.md). If docs and code disagree, fix the code or update the public docs in the same change.

### Primitive Is Closed

Treat the DSM primitive as closed by default.

- Do not propose primitive expansion for feature growth or future flexibility.
- Build new capabilities as composed protocols above the primitive whenever possible.
- Primitive-layer changes require a much higher bar: soundness fix, ambiguity removal, simplification
  without acceptance expansion, or replacement of a broken assumption.

Read [Chapter 17 — DSM Primitive](17-dsm-primitive.md) before proposing any change that touches
acceptance, ordering, identity binding, proofs, or fork exclusion.

### No Legacy Code

When replacing a system, fully remove the old path. Don't leave deprecated code alongside the new implementation. Remove old imports, functions, bridge routes, etc.

### Proto Types

Always regenerate proto types after changing `proto/dsm_app.proto`:

```bash
cd dsm_client/frontend && npm run proto:gen
```

Never use inline type casts or duck-typed interfaces.

### Spec-Driven Client Code

When changing DLV or policy specs, validate and regenerate through `dsm-gen` instead of hand-editing generated output:

```bash
cargo run -p dsm-gen -- validate path/to/spec.yaml
cargo run -p dsm-gen -- client path/to/spec.yaml --lang ts
```

---

## License

This project is dual-licensed under [MIT](../../LICENSE-MIT) and [Apache 2.0](../../LICENSE-APACHE). By submitting a pull request, you agree that your contribution will be dual-licensed under these same terms, without any additional conditions.

---

## Contact

- Issues: GitHub Issues on this repo
- Security: team@irrefutablelabs.org

---

Next: [Chapter 15 — Security Model](15-security-model.md)
