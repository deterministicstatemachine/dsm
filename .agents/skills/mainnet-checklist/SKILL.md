---
name: mainnet-checklist
description: Track DSM mainnet readiness — known gaps, implemented features, remaining work, CI status, and blockers. Use to check overall project status or plan next steps toward mainnet.
---

# DSM Mainnet Readiness Checklist

You track mainnet readiness. When invoked, you scan the codebase for current status of all known gaps, check CI health, and report what remains.

## Feature Completion Status

### Implemented (Verified)

- [x] Straight hash chains, per-device SMT, Device Trees
- [x] Envelope v3 protobuf-only wire format
- [x] BLAKE3 domain-separated hashing
- [x] SPHINCS+ signatures
- [x] ML-KEM-768 key exchange
- [x] DBRW anti-cloning (hardware + environment binding)
- [x] Tripwire fork-exclusion
- [x] Bilateral transfers (BLE + online), 3-phase commit
- [x] DJTE emissions (JAP, winner selection, ShardCountSMT)
- [x] CPTA token policies, PaidK spend-gate
- [x] DLV (Limbo Vaults) with fulfillment mechanisms
- [x] dBTC Bitcoin bridge (HTLC, deep-anchor, regtest E2E)
- [x] Smart Commitments, External Commitments
- [x] Storage node cluster (index-only, replica placement)
- [x] b0x unilateral transport
- [x] NFC transport, QR transport
- [x] Recovery (capsule, tombstone, rollup)
- [x] Android app with JNI (87+ symbols), WebView + React frontend
- [x] dBTC balance doubling bug (FIXED — SQLite-authoritative)
- [x] Telemetry/observability (FIXED — diagnostics.metrics)
- [x] Automated bilateral reconciliation (FIXED — bilateral.reconcile)
- [x] CI enforcement (FIXED — ci_scan.sh, canonical_bilateral_gates.sh)
- [x] DBRW duplication (RESOLVED — pbi.rs delegates to dsm::crypto::cdbrw_binding)

### Known Gaps (Remaining)

1. **DBRW thermal feedback** — `dbrw_health.rs` has Healthy/Degraded/MeasurementAnomaly states, but NOT surfaced to frontend UI. Users see generic failure when CPU throttles.
   - Fix: Subscribe in `UXContext.tsx`, show toast/banner, disable send button during anomaly
   - Files: `dsm/src/crypto/dbrw_health.rs`, `new_frontend/src/contexts/UXContext.tsx`

2. **DeTFi routing service** — Vault discovery via storage nodes exists, but off-chain Dijkstra routing not implemented.
   - Files: `dsm_sdk/src/sdk/dlv_sdk.rs`, `dsm/src/vault/`

## Verification Steps

When invoked, run these checks:

### 1. Check JNI symbol count
```bash
nm -gU dsm_client/android/app/src/main/jniLibs/arm64-v8a/libdsm_sdk.so 2>/dev/null | grep -c Java_
```
Expected: 87+

### 2. Check CI scripts exist
```bash
ls -la .github/workflows/ci.yml
ls -la scripts/ci_scan.sh scripts/canonical_bilateral_gates.sh scripts/production_safety_checks.sh 2>/dev/null
```

### 3. Run invariant scan
```bash
cd /Users/cryptskii/Desktop/claude_workspace/dsm
rg -c 'JSON\.(stringify|parse)' dsm_client/new_frontend/src/ --glob '!**/proto/dsm_app_pb*' --glob '!**/node_modules/**' 2>/dev/null || echo "0 JSON violations"
rg -c 'Date\.now\(\)|System\.currentTimeMillis' dsm_client/ --glob '!**/node_modules/**' --glob '!**/target/**' --glob '!**/build/**' 2>/dev/null || echo "0 clock violations"
rg -c '// *TODO|// *FIXME' dsm_client/ --glob '!**/node_modules/**' --glob '!**/target/**' --glob '!**/build/**' 2>/dev/null || echo "0 TODO violations"
```

### 4. Check DBRW thermal feedback gap
```bash
rg -n 'MeasurementAnomaly|Degraded|dbrw.*health|thermal.*feedback' dsm_client/new_frontend/src/ 2>/dev/null || echo "DBRW thermal feedback NOT in frontend"
```

### 5. Check DeTFi routing gap
```bash
rg -n 'dijkstra|route_set|RouteSet|routing_service' dsm_client/deterministic_state_machine/ --glob '!**/target/**' 2>/dev/null || echo "DeTFi routing NOT implemented"
```

## Report Format

Produce a summary table:

| Area | Status | Notes |
|------|--------|-------|
| Core crypto | ... | ... |
| Bilateral (BLE+online) | ... | ... |
| Wire format (Envelope v3) | ... | ... |
| JNI bridge (87+ symbols) | ... | ... |
| dBTC bridge | ... | ... |
| DLV/DeTFi | ... | ... |
| DJTE emissions | ... | ... |
| Storage nodes | ... | ... |
| Recovery | ... | ... |
| CI/invariant enforcement | ... | ... |
| DBRW thermal (Known Gap #1) | ... | ... |
| DeTFi routing (Known Gap #2) | ... | ... |

## Spec Reference

Root AGENTS.md "Mainnet Roadmap" section
`.github/instructions/new.instructions.md` (beta readiness critique)
