# Contributing to DSM

Thank you for your interest in contributing to DSM! This document provides guidelines and instructions for contributing.

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How to Contribute

### Finding Issues

- Look for issues labeled [`good-first-issue`](https://github.com/deterministicstatemachine/dsm/labels/good-first-issue) if you're new
- Issues labeled [`help-wanted`](https://github.com/deterministicstatemachine/dsm/labels/help-wanted) are ready for contribution
- Comment on an issue before starting work to avoid duplicate effort

### Development Setup

1. Fork and clone the repository:

   ```bash
   git clone https://github.com/YOUR_USERNAME/dsm.git
   cd dsm
   ```

2. Ensure you have Rust 1.85.0+ installed:

   ```bash
   rustup update stable
   ```

   The `rust-toolchain.toml` will automatically install required components (rustfmt, clippy, rust-analyzer).

3. Build and test:

   ```bash
   cargo build --workspace
   cargo test --workspace
   ```

4. Install additional tools for local checks:

   ```bash
   cargo install cargo-deny
   cargo install cargo-audit
   ```

### Making Changes

1. Create a branch from `main`:

   ```bash
   git checkout -b feat/your-feature-name
   ```

2. Make your changes, following the [code style](#code-style) guidelines.

3. Add or update tests for your changes.

4. Ensure all checks pass locally:

   ```bash
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   cargo deny check
   ```

5. Commit your changes using [Conventional Commits](#commit-messages).

6. Push and open a pull request against `main`.

## Code Style

- **Formatting**: All code must pass `cargo fmt`. Configuration is in `rustfmt.toml`.
- **Linting**: All code must pass `cargo clippy` with zero warnings. Pedantic and nursery lints are enabled.
- **No panics**: `unwrap()` is denied in library code. Use proper error handling with `thiserror`.
- **No unsafe code**: `unsafe` is denied workspace-wide.
- **Documentation**: All public items should have doc comments.
- **Line width**: 100 characters maximum.
- **Imports**: Group by std, external, then crate. Use crate-level granularity.

## Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

Types: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `ci`, `perf`

Examples:
- `feat(core): add state transition validation`
- `fix(crypto): handle empty input in hash function`
- `docs: update architecture overview`

## Developer Certificate of Origin (DCO)

All commits must be signed off, certifying that you wrote the code or have the right to submit it under the project's license.

Add `Signed-off-by` to your commits:

```bash
git commit -s -m "feat: your feature description"
```

Or configure git to always sign off:

```bash
git config --local commit.signoff true
```

## Pull Request Process

1. Fill out the pull request template completely.
2. Ensure all CI checks pass.
3. At least **2 reviewers** must approve before merging.
4. Keep PRs focused — one logical change per PR.
5. Rebase on `main` before requesting review (linear history required).
6. For security-sensitive changes, tag `@deterministicstatemachine/security-team` in the PR description.

## Testing Requirements

- All new code must include tests.
- Unit tests go in the same file as the code (`#[cfg(test)]` module).
- Integration tests go in the crate's `tests/` directory.
- Tests must pass on both Ubuntu and macOS (CI matrix).
- Maintain or improve test coverage.

## Security

**Do not file public issues for security vulnerabilities.** See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## Questions?

Open a [discussion](https://github.com/deterministicstatemachine/dsm/discussions) or reach out to the maintainers.
