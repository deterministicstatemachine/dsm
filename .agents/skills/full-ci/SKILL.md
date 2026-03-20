---
name: full-ci
description: Run all CI gates — TypeScript type-check + lint + test, Rust check + test, invariant scan
disable-model-invocation: true
---

# Full CI Gate Check

Run the complete CI pipeline across all layers. Stops and reports on first failure in each layer.

## Steps

### 1. TypeScript type-check

```bash
cd /Users/cryptskii/Desktop/claude_workspace/dsm/dsm_client/new_frontend && \
npm run type-check 2>&1 | tail -20
```

### 2. TypeScript lint (production config)

```bash
cd /Users/cryptskii/Desktop/claude_workspace/dsm/dsm_client/new_frontend && \
npm run lint 2>&1 | tail -20
```

### 3. TypeScript tests (Jest)

```bash
cd /Users/cryptskii/Desktop/claude_workspace/dsm/dsm_client/new_frontend && \
npm test -- --ci --passWithNoTests 2>&1 | tail -30
```

### 4. Rust check (core + SDK)

```bash
cd /Users/cryptskii/Desktop/claude_workspace/dsm/dsm_client/deterministic_state_machine && \
cargo check --package dsm 2>&1 | tail -10 && \
cargo check --package dsm_sdk 2>&1 | tail -10
```

### 5. Rust tests

```bash
cd /Users/cryptskii/Desktop/claude_workspace/dsm/dsm_client/deterministic_state_machine && \
cargo test --package dsm 2>&1 | tail -20
```

### 6. Invariant scan — banned patterns

Scan for protocol violations across the codebase:

```bash
cd /Users/cryptskii/Desktop/claude_workspace/dsm

echo "=== Checking for JSON in protocol ==="
rg -n 'JSON\.(stringify|parse)' dsm_client/new_frontend/src/ --glob '!**/__tests__/**' --glob '!**/test*' --glob '!**/*.test.*' --glob '!**/proto/dsm_app_pb*' 2>/dev/null | head -5 && echo "FAIL: JSON found" || echo "PASS"

echo "=== Checking for wall-clock time ==="
rg -n 'Date\.now\(\)|new Date\(\)|System\.currentTimeMillis|chrono::Utc' dsm_client/ --glob '!**/node_modules/**' --glob '!**/target/**' --glob '!**/__tests__/**' --glob '!**/*.test.*' 2>/dev/null | head -5 && echo "FAIL: Wall-clock found" || echo "PASS"

echo "=== Checking for TODO/FIXME ==="
rg -n '// *TODO|// *FIXME|// *HACK|// *XXX' dsm_client/ --glob '!**/node_modules/**' --glob '!**/target/**' --glob '!**/build/**' 2>/dev/null | head -5 && echo "FAIL: TODO/FIXME found" || echo "PASS"

echo "=== Checking for hex in Core/SDK ==="
rg -n 'hex::(encode|decode)' dsm_client/deterministic_state_machine/dsm/src/ dsm_client/deterministic_state_machine/dsm_sdk/src/jni/ dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/ 2>/dev/null | grep -v 'log::\|debug!\|info!\|warn!\|error!' | head -5 && echo "FAIL: hex in Core/SDK" || echo "PASS"
```

### 7. Report summary

Compile a summary table:

| Gate | Status |
|------|--------|
| TS type-check | PASS/FAIL |
| TS lint | PASS/FAIL |
| TS tests | PASS/FAIL (X passed, Y failed) |
| Rust check | PASS/FAIL |
| Rust tests | PASS/FAIL (X passed, Y failed) |
| Invariant scan | PASS/FAIL (details) |

Report any failures with specific error messages.
