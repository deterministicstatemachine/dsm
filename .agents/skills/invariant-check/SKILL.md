---
name: invariant-check
description: Deep verification of DSM protocol invariants after code changes. Checks all 12 hard invariants, banned patterns, spec compliance, and cross-layer consistency. Use after any significant code change to catch violations before they hit CI.
---

# DSM Invariant Checker

You are a protocol invariant enforcement specialist. After code changes, you verify compliance with ALL 12 hard invariants, banned patterns, and spec requirements.

## The 12 Hard Invariants

Violating ANY of these is build-blocking.

### 1. Envelope v3 Only
- Sole wire container, `0x03` framing byte prefix
- No v2, no fallback
- **Check**: `rg 'version.*=.*2|envelope_v2|v2.*envelope' --type rust --type ts --type kotlin`

### 2. No JSON
- `JSON.stringify`, `JSON.parse`, `serde_json`, `Gson`, `Moshi`, `JSONObject` are banned
- Protobuf-only transport
- **Check**: `rg 'JSON\.(stringify|parse)|serde_json::(to_|from_)|Gson|Moshi|JSONObject' dsm_client/ --glob '!**/node_modules/**' --glob '!**/target/**' --glob '!**/build/**' --glob '!**/proto/dsm_app_pb*'`

### 3. No Hex in Protocol
- `hex::encode/decode` banned in Core/SDK/JNI
- Display-only in UI
- Raw bytes internally, Base32 Crockford at string boundaries
- **Check**: `rg 'hex::(encode|decode)' dsm_client/deterministic_state_machine/dsm/src/ dsm_client/deterministic_state_machine/dsm_sdk/src/`

### 4. No Wall-Clock Time in Protocol
- Logical ticks from hash chain adjacency only
- Wall-clock ONLY for: BLE staleness, transport DoS, UI display
- Clock values NEVER in hash preimages, ReceiptCommit, or ordering decisions
- **Check**: `rg 'Date\.now\(\)|new Date\(\)|System\.currentTimeMillis|Instant::now|SystemTime::now|chrono::Utc' dsm_client/ --glob '!**/node_modules/**' --glob '!**/target/**'`

### 5. No TODO/FIXME/HACK/XXX
- Production-quality mandate
- No mocks, stubs, placeholders, fallbacks, deprecated paths
- **Check**: `rg '// *TODO|// *FIXME|// *HACK|// *XXX' dsm_client/ --glob '!**/node_modules/**' --glob '!**/target/**' --glob '!**/build/**'`

### 6. No Legacy Code
- When replacing a system, fully remove the old path
- No side-by-side deprecated code
- **Check**: `rg 'deprecated|legacy|old_|_old|DEPRECATED' dsm_client/ --glob '!**/node_modules/**' --glob '!**/target/**'`

### 7. Single Authoritative Path
- `UI/WebView → MessagePort → Kotlin Bridge → JNI → SDK → Core`
- No side channels
- **Check**: Look for alternative bridge paths, direct JNI calls bypassing SinglePathWebViewBridge

### 8. Core is Pure
- `dsm` crate: no network, no OS time, no UI, no global state
- SDK mediates all I/O
- **Check**: `rg 'std::net|reqwest|tokio::net|std::time::SystemTime|std::time::Instant|println!|eprintln!' dsm_client/deterministic_state_machine/dsm/src/`

### 9. BLAKE3 Domain Separation
- All hashing uses `BLAKE3-256("DSM/<domain>\0" || data)`
- **Check**: Look for raw BLAKE3 calls without domain prefix in `dsm/src/crypto/`

### 10. Tripwire Fork-Exclusion
- No two valid successors from same parent tip
- SPHINCS+ EUF-CMA + BLAKE3 collision resistance
- **Check**: Structural — verify parent tip consumption tracking in state machine

### 11. Token Conservation
- `B_{n+1} = B_n + Delta, B >= 0`
- Balances never go negative
- **Check**: Look for balance mutations without conservation check in `dsm/src/core/token/`

### 12. Storage Nodes Index-Only
- Never sign, never gate acceptance, never affect unlock predicates
- **Check**: `rg 'sign|signature|verify_sig|validate_state' dsm_client/deterministic_state_machine/dsm_storage_node/src/`

## Banned Pattern Scan

Run this comprehensive scan after any code change:

```bash
cd /Users/cryptskii/Desktop/claude_workspace/dsm

echo "=== 1. JSON in protocol ==="
rg -n 'JSON\.(stringify|parse)' dsm_client/new_frontend/src/ --glob '!**/__tests__/**' --glob '!**/proto/dsm_app_pb*' 2>/dev/null | head -5

echo "=== 2. serde_json in Rust ==="
rg -n 'serde_json' dsm_client/deterministic_state_machine/ --glob '!**/target/**' 2>/dev/null | head -5

echo "=== 3. Wall-clock time ==="
rg -n 'Date\.now\(\)|System\.currentTimeMillis|Instant::now\(\)|SystemTime::now|chrono::Utc' dsm_client/ --glob '!**/node_modules/**' --glob '!**/target/**' --glob '!**/build/**' 2>/dev/null | head -10

echo "=== 4. TODO/FIXME ==="
rg -n '// *TODO|// *FIXME|// *HACK|// *XXX' dsm_client/ --glob '!**/node_modules/**' --glob '!**/target/**' --glob '!**/build/**' 2>/dev/null | head -5

echo "=== 5. hex in Core/SDK ==="
rg -n 'hex::(encode|decode)' dsm_client/deterministic_state_machine/dsm/src/ dsm_client/deterministic_state_machine/dsm_sdk/src/ 2>/dev/null | grep -v 'log::\|debug!\|info!\|warn!\|error!\|Display' | head -5

echo "=== 6. Envelope v2 ==="
rg -n 'envelope.*v2|version.*=.*2' dsm_client/ --glob '!**/node_modules/**' --glob '!**/target/**' -i 2>/dev/null | grep -iv 'schema\|semver\|2\.4' | head -5

echo "=== 7. unsafe in Core ==="
rg -n 'unsafe\s*\{' dsm_client/deterministic_state_machine/dsm/src/ 2>/dev/null | head -5

echo "=== 8. Gson/Moshi/JSONObject ==="
rg -n 'Gson|Moshi|JSONObject|JSONArray' dsm_client/android/ --glob '!**/build/**' 2>/dev/null | head -5
```

## Post-Change Verification

After any code change:

1. Run the banned pattern scan above
2. If Rust changed: `cargo check --package dsm && cargo check --package dsm_sdk`
3. If TypeScript changed: `npm run type-check && npm run lint`
4. If proto changed: `npm run proto:gen` then re-check
5. Cross-reference the change against the spec (use Feature → Spec map from AGENTS.md)

## Spec Reference

- Invariant definitions: Root `AGENTS.md` "Hard Invariants" section
- Ban list: `.github/instructions/rules.instructions.md`
- CI enforcement: `ci_scan.sh`, `canonical_bilateral_gates.sh`, `production_safety_checks.sh`
