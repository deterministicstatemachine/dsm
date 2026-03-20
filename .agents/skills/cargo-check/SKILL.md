---
name: cargo-check
description: Run cargo check and cargo test for DSM core and SDK crates
disable-model-invocation: true
---

# Rust Check & Test

Run `cargo check` and `cargo test` for both the core `dsm` crate and the `dsm_sdk` crate.

## Steps

### 1. Check core library (dsm)

```bash
cd /Users/cryptskii/Desktop/claude_workspace/dsm/dsm_client/deterministic_state_machine && \
cargo check --package dsm 2>&1 | tail -20
```

### 2. Check SDK (dsm_sdk)

```bash
cd /Users/cryptskii/Desktop/claude_workspace/dsm/dsm_client/deterministic_state_machine && \
cargo check --package dsm_sdk 2>&1 | tail -20
```

Note: Cannot check with `--features=jni,bluetooth` on host (requires Android NDK target). Host check validates core logic.

### 3. Run core tests

```bash
cd /Users/cryptskii/Desktop/claude_workspace/dsm/dsm_client/deterministic_state_machine && \
cargo test --package dsm 2>&1 | tail -30
```

### 4. Run SDK tests (host-compatible)

```bash
cd /Users/cryptskii/Desktop/claude_workspace/dsm/dsm_client/deterministic_state_machine && \
cargo test --package dsm_sdk 2>&1 | tail -30
```

### 5. Report summary

Report:
- cargo check results for both crates (pass/fail + error count)
- cargo test results (pass/fail/skip counts)
- Any compilation errors or test failures
