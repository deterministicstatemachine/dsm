# Chapter 15 — Security Model

Threat model, post-quantum rationale, anti-cloning, fork prevention, and security guarantees.

---

## Threat Model

### Adversary Capabilities

DSM assumes an adversary who can:

- **Intercept network traffic** between devices and storage nodes
- **Compromise storage nodes** (read/modify stored data)
- **Possess a quantum computer** capable of breaking classical crypto (RSA, ECDSA, Diffie-Hellman)
- **Physically access a device** (but not clone its silicon fingerprint)
- **Operate rogue storage nodes** that return false or stale data

### What the Adversary Cannot Do

- **Clone hardware** — DBRW binds identity to specific silicon
- **Break hash functions** — BLAKE3 provides 128-bit post-quantum security
- **Forge signatures** — SPHINCS+ is EUF-CMA secure against quantum adversaries
- **Create valid forks** — Tripwire Fork-Exclusion prevents double successors
- **Influence protocol logic via storage** — nodes are index-only, never sign or validate

---

## Post-Quantum Rationale

Classical cryptographic algorithms (RSA, ECDSA, Diffie-Hellman) are vulnerable to Shor's algorithm on a sufficiently large quantum computer. DSM uses post-quantum primitives throughout:

| Classical | Vulnerability | DSM Replacement |
|-----------|-------------|-----------------|
| RSA/ECDSA signatures | Shor's algorithm | SPHINCS+ (hash-based, EUF-CMA) |
| ECDH key exchange | Shor's algorithm | ML-KEM-768 (lattice-based) |
| SHA-256 | Grover's algorithm (halves security) | BLAKE3-256 (128-bit post-quantum) |

### Why SPHINCS+?

- **Stateless** — no tracking of used one-time keys (critical for mobile devices)
- **Conservative** — security relies only on hash function properties
- **Standardized** — NIST PQC standard
- **Tradeoff** — larger signatures (~8-40 KB) but quantum-safe

### Why ML-KEM-768?

- **NIST standard** — formerly Kyber, selected for standardization
- **Efficient** — fast key generation, encapsulation, decapsulation
- **Level 3 security** — comparable to AES-192

---

## Anti-Cloning (DBRW)

Device-Bound Random Walk prevents an adversary from copying device state to another device and operating two "copies" of the same identity.

### Two-Factor Binding

1. **Silicon fingerprint** — hardware-specific measurements unique to each physical device
2. **Environment binding** — runtime environment properties that change across devices

```
dbrw_hash = BLAKE3("DSM/dbrw-bind\0" || silicon_fingerprint || env_entropy)
```

### Health Monitoring

The DBRW module continuously monitors binding validity:

| State | Meaning | Action |
|-------|---------|--------|
| Healthy | Measurements within expected variance | Normal operation |
| Degraded | Some anomalies (e.g., battery replacement) | Warning, may require re-binding |
| MeasurementAnomaly | Significant deviation | Potential cloning detected, operations restricted |

### Attack Resistance

- **State export attack** — extracting and importing device state fails because the DBRW hash won't match on the target device
- **Emulator attack** — emulators produce different silicon fingerprints than physical devices
- **Relay attack** — DBRW entropy is collected at bootstrap and bound to the identity; relaying requests doesn't help because the binding is checked at every operation

---

## Fork Prevention (Tripwire)

The Tripwire Fork-Exclusion theorem is the core safety property of DSM:

> No two valid successors can exist from the same parent commit tip.

### Formal Guarantee

Given parent tip `T` with hash `H(T)`:
- Creating successor `S1` requires a valid SPHINCS+ signature over `(H(T), S1_data)`
- Creating a second successor `S2 ≠ S1` would require either:
  - A second valid signature for a different message with the same key (breaks EUF-CMA)
  - Finding `S2_data ≠ S1_data` such that `H(T, S1_data) = H(T, S2_data)` (breaks BLAKE3 collision resistance)

### Implications

- **No double-spending** — a device cannot send to two different recipients from the same state
- **No rollbacks** — hash chain is append-only; previous states cannot be "re-entered"
- **Deterministic resolution** — any party can verify which successor (if any) is valid

---

## Server Blindness

Storage nodes are deliberately designed to be unable to compromise the protocol:

| Storage Node Limitation | Why It Matters |
|------------------------|----------------|
| Never signs messages | Cannot impersonate a device |
| Never validates balances | Cannot censor transactions based on amount |
| Never gates acceptance | Cannot selectively block state transitions |
| Never affects unlock predicates | Cannot interfere with DLV vault logic |
| Stores encrypted blobs only | Cannot read device state |

Even a fully compromised storage-node replica set cannot:
- Steal tokens
- Forge transactions
- Prevent offline transfers (BLE works without storage)
- Determine account balances
- Link identities to real-world entities (from storage data alone)

### Availability Attacks

A compromised or unavailable storage-node replica set can deny:
- New genesis creation (requires MPC endpoint)
- Online state sync (offline BLE transfers continue working)
- Recovery capsule retrieval

Mitigation: N=6 replicas with K=3 minimum — the replica set tolerates loss of 3 nodes.

---

## Offline Security

BLE transfers are fully secured without network connectivity:

1. **Identity verification** — SPHINCS+ signatures verify device identity
2. **State integrity** — hash chain structure prevents tampering
3. **Anti-replay** — nonces and sequence counters in every message
4. **Anti-cloning** — DBRW binding verified locally
5. **Conservation** — token balance checks run on-device

When connectivity returns, devices sync with storage nodes. Conflicts are impossible due to Tripwire — each device can only produce one valid successor per state.

---

## Key Management

### Key Hierarchy

```
DBRW entropy + hardware
    │
    ▼ BLAKE3 KDF
Master identity key (SPHINCS+)
    │
    ├── Signing key (state commits, bilateral)
    ├── Encryption key (at-rest, ChaCha20-Poly1305)
    ├── BLE session keys (per-connection, via ML-KEM-768)
    └── Bitcoin keys (BIP84, ECDSA secp256k1 — Bitcoin-compatible)
```

### Key Lifecycle

- **Generation** — derived from DBRW-bound hardware entropy at genesis
- **Storage** — encrypted at rest with ChaCha20-Poly1305
- **Rotation** — not currently supported (identity is permanent)
- **Recovery** — via recovery capsules stored on storage nodes

### Zeroization

Sensitive key material is zeroized from memory after use:
- BIP39 mnemonic: never written to disk, zeroized after derivation
- BIP32 master key: zeroized after deriving account key
- Session keys: zeroized after BLE session ends

---

## Token Conservation

The conservation invariant is enforced at every state transition:

```
B_{n+1} = B_n + Delta
B_{n+1} >= 0
```

This runs in the core crate (pure Rust, no I/O) and cannot be bypassed by the SDK or UI layers. The core validates that:

1. The balance change `Delta` is correctly computed from the operation
2. The resulting balance is non-negative
3. The total token supply is preserved (sender's loss = receiver's gain)

---

## Known Security Considerations

1. **DBRW thermal feedback** — health states exist but are not yet surfaced to the frontend UI
2. **DBRW key derivation** — currently duplicated in two files (`pbi.rs` and `crypto_brw.rs`) which is a security risk if they diverge
3. **UUID v4 in performance monitoring** — uses randomness, which is a determinism violation if it leaks into protocol paths
4. **Recovery capsule encryption** — relies on storage node availability; if all N replicas are lost, recovery is impossible

---

## Security Contacts

Report vulnerabilities to **team@irrefutablelabs.org**. Do not open public issues for security bugs.

---

Next: [Appendix A — Glossary](appendix-a-glossary.md)
