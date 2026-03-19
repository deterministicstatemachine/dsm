# Appendix B — Hard Invariants

The 12 inviolable rules of the DSM protocol. Violating any one is build-blocking.

---

## 1. Envelope v3 Only

The sole wire container is Envelope v3 with a `0x03` framing byte prefix. No other envelope versions exist, are supported, or will be added. Every wire message must be wrapped in Envelope v3.

**Enforcement:** CI scans for any reference to v2 envelopes or non-v3 framing.

---

## 2. No JSON

`JSON.stringify`, `JSON.parse`, `serde_json` (in protocol code), `Gson`, `Moshi`, and `JSONObject` are banned from all protocol-layer code. All transport uses Protocol Buffers.

JSON is permitted only in:
- Storage-node observability or admin endpoints outside the protocol data path
- Build configuration files (`package.json`, `tsconfig.json`, etc.)
- Non-protocol logging and diagnostics

**Enforcement:** `ci_scan.sh` greps for banned JSON patterns in protocol directories.

---

## 3. No Hex in Protocol

`hex::encode` and `hex::decode` are banned in Core, SDK, and JNI code. The protocol uses raw bytes internally. At string boundaries (UI display, QR codes, BLE packet dumps), Base32 Crockford encoding is used.

Hex is permitted only for UI display and I/O edge formatting.

**Enforcement:** CI scans for hex encode/decode calls in core/SDK sources.

---

## 4. No Wall-Clock Time in Protocol

All state transitions, acceptance predicates, rate limits, and expiry logic use **logical ticks** derived from hash chain adjacency — commit heights and BLAKE3 iteration counters.

Wall-clock time (`Instant::now()`, `Date.now()`, `SystemTime::now()`, `System.currentTimeMillis`) is permitted only for:
- BLE session staleness detection (transport layer)
- Transport-layer DoS rate limiting
- UI display metadata

Clock values must **never** appear in hash preimages, `ReceiptCommit` fields, or ordering decisions.

**Enforcement:** CI scans for time function calls in core protocol files.

---

## 5. No TODO/FIXME/HACK/XXX

Production-quality mandate. No mocks, stubs, placeholders, fallbacks, or deprecated paths. Every piece of code must be complete and production-ready.

**Enforcement:** `git grep -r "TODO\|FIXME\|HACK\|XXX"` must return zero results. CI gate blocks the build on any match.

---

## 6. No Legacy Code

When replacing a system, fully remove the old path. Don't leave deprecated code alongside the new implementation. Remove old imports, references, functions, bridge routes, and any other artifacts of the replaced system.

**Rationale:** Side-by-side legacy code creates confusion about which path is authoritative, invites bugs from partial updates, and bloats the codebase.

---

## 7. Single Authoritative Path

The only valid data path is:

```
UI/WebView → MessagePort → Kotlin Bridge → JNI → SDK → Core
```

No side channels, no alternative bridges, no direct Core access from the UI.

**Enforcement:** `flow_assertions.sh` verifies that no alternative paths exist.

---

## 8. Core is Pure

The `dsm` crate has:
- No network calls
- No OS time access
- No UI dependencies
- No global mutable state

The SDK mediates all I/O between the Core and the outside world.

**Rationale:** Purity ensures determinism — given the same inputs, the Core always produces the same outputs. This is essential for independent verification by any party.

---

## 9. BLAKE3 Domain Separation

All hashing uses the format:

```
BLAKE3-256("DSM/<domain>\0" || data)
```

The null byte terminates the domain tag to prevent prefix collisions between domains.

**Enforcement:** Grepping for raw `blake3::Hasher::new()` without domain prefix in core code should return zero results.

---

## 10. Tripwire Fork-Exclusion

No two valid successors may exist from the same parent commit tip. This relies on:
- **SPHINCS+ EUF-CMA** — cannot forge two signatures for different messages
- **BLAKE3 collision resistance** — cannot find two different states with the same hash

**Implication:** Double-spending is cryptographically impossible without breaking either primitive.

---

## 11. Token Conservation

At every state transition:

```
B_{n+1} = B_n + Delta
B_{n+1} >= 0
```

Balances never go negative. The sender's loss equals the receiver's gain. Total token supply is preserved.

**Enforcement:** The Core crate validates conservation at every transition. This check cannot be bypassed by the SDK or UI.

---

## 12. Storage Nodes are Index-Only

Storage nodes:
- **Never sign** protocol messages
- **Never validate** balances or protocol rules
- **Never gate acceptance** of state transitions
- **Never affect** unlock predicates

They are pure persistence/index services. Compromising a storage node cannot compromise the protocol.

**Rationale:** This ensures that the security model depends only on device-local cryptography, not on trusted third parties.

---

## Summary Table

| # | Invariant | Scope | Enforcement |
|---|-----------|-------|-------------|
| 1 | Envelope v3 only | Wire format | CI scan |
| 2 | No JSON | Protocol transport | CI scan |
| 3 | No hex in protocol | Core/SDK/JNI | CI scan |
| 4 | No wall-clock time | Protocol logic | CI scan |
| 5 | No TODO/FIXME/HACK/XXX | All code | CI gate (`git grep`) |
| 6 | No legacy code | All code | Code review |
| 7 | Single authoritative path | Architecture | Flow assertions |
| 8 | Core is pure | `dsm` crate | Architecture review |
| 9 | BLAKE3 domain separation | All hashing | Code review |
| 10 | Tripwire Fork-Exclusion | State transitions | Formal argument |
| 11 | Token conservation | State transitions | Core validation |
| 12 | Storage nodes index-only | Storage layer | Architecture review |

---

Back to [Table of Contents](README.md)
