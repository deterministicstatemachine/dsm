# Chapter 6 — Cryptographic Architecture

DSM's post-quantum cryptographic stack for contributors and integrators.

---

## Cryptographic Stack Overview

| Primitive | Algorithm | Usage | Source |
|-----------|-----------|-------|--------|
| Hashing | BLAKE3-256 | All protocol hashing, domain-separated | `crypto/blake3.rs`, `crypto/hash.rs` |
| Signatures | SPHINCS+ | Post-quantum digital signatures (EUF-CMA) | `crypto/sphincs.rs` |
| Key Exchange | ML-KEM-768 (Kyber) | Post-quantum key encapsulation | `crypto/kyber.rs` |
| Anti-Cloning | DBRW | Dual-factor: silicon fingerprint + env binding | `crypto/dbrw.rs` |
| Commitments | Pedersen | Hiding + binding commitments | `crypto/pedersen.rs` |
| Storage Encryption | ChaCha20-Poly1305 | At-rest encryption | — |
| Key Derivation | BLAKE3 keyed | Domain-separated KDF | Per-use domain |
| Policy Anchors | CPTA | Token policy content addressing | `cpta/mod.rs` |

---

## BLAKE3 Domain Separation

All hashing in DSM uses BLAKE3-256 with domain separation. The domain prefix format is:

```
BLAKE3-256("DSM/<domain>\0" || data)
```

The null byte (`\0`) terminates the domain tag, preventing prefix collisions.

### Domain Tags

| Domain Tag | Usage |
|-----------|-------|
| `DSM/commit\0` | State commit hashing |
| `DSM/bilateral\0` | Bilateral transaction hashing |
| `DSM/token\0` | Token operation hashing |
| `DSM/dbrw-bind\0` | DBRW hardware binding |
| `DSM/cpta\0` | Content-Addressed Token Policy Anchor |
| `DSM/dlv-unlock\0` | DLV vault unlock key derivation |
| `DSM/assign\0` | Storage node assignment |
| `DSM/smt\0` | Sparse Merkle Tree node hashing |
| `DSM/device\0` | Device identity derivation |
| `DSM/recovery\0` | Recovery capsule hashing |

All domain tags are defined in `common/domain_tags.rs` and referenced throughout the core crate. Adding a new hashing context requires defining a new domain tag — never reuse existing tags.

### Implementation

```rust
// crypto/blake3.rs
pub fn domain_hash(domain: &str, data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(format!("DSM/{}\0", domain).as_bytes());
    hasher.update(data);
    *hasher.finalize().as_bytes()
}
```

---

## SPHINCS+ Post-Quantum Signatures

DSM uses SPHINCS+ for all digital signatures. SPHINCS+ is a hash-based signature scheme that achieves EUF-CMA (Existential Unforgeability under Chosen Message Attack) security without relying on the hardness of any number-theoretic problem.

### Properties

- **Post-quantum secure** — based solely on hash function security
- **Stateless** — no need to track which one-time keys have been used
- **EUF-CMA** — the strongest standard notion of signature unforgeability
- **Large signatures** — SPHINCS+ signatures are larger than classical signatures (~8-40 KB depending on parameters), which is a tradeoff for quantum resistance

### Role in Protocol

SPHINCS+ signatures appear in:
- **State commits** — every commit is signed by the device's SPHINCS+ key
- **Bilateral transfers** — both parties sign their respective state transitions
- **Tripwire Fork-Exclusion** — the theorem relies on SPHINCS+ EUF-CMA to guarantee that an adversary cannot produce two valid successors from the same parent

---

## ML-KEM-768 (Kyber) Key Encapsulation

ML-KEM-768 (formerly known as Kyber) is used for post-quantum key encapsulation in:
- **BLE session establishment** — secure key exchange between two devices
- **Storage node TLS** — post-quantum transport security
- **Recovery capsule encryption** — protecting recovery data

### Key Exchange Flow

```
Device A                          Device B
    │                                │
    │── ML-KEM public key ─────────►│
    │                                │  encapsulate(pk) → (ct, ss)
    │◄── ciphertext ────────────────│
    │  decapsulate(sk, ct) → ss     │
    │                                │
    │  Both have shared secret 'ss'  │
    │  Derive session key via BLAKE3 │
```

---

## DBRW Anti-Cloning

Device-Bound Random Walk (DBRW) prevents state cloning attacks by binding each identity to specific hardware.

### Dual-Factor Binding

1. **Silicon fingerprint** — derived from hardware-specific properties (sensor readings, timing characteristics) that are unique to each physical device
2. **Environment binding** — derived from the device's runtime environment, preventing state from being valid on a different device even with identical hardware

### DBRW Hash

```
dbrw_hash = BLAKE3("DSM/dbrw-bind\0" || silicon_fingerprint || env_entropy)
```

### Health States

The DBRW module (`crypto/dbrw_health.rs`) tracks three health states:
- **Healthy** — fingerprint measurements are within expected variance
- **Degraded** — some measurements show anomalies (e.g., battery replacement)
- **MeasurementAnomaly** — significant deviation detected, potential cloning attempt

### Bootstrap Integration

During PBI (Platform Boot Identity) bootstrap, the DBRW hash is computed and bound to the device identity. The SDK stores this in a `PlatformContext` via `OnceLock`, ensuring it's computed exactly once per app lifetime.

---

## Pedersen Commitments

Pedersen commitments provide both hiding and binding properties:
- **Hiding** — the commitment reveals nothing about the committed value
- **Binding** — the committer cannot change the value after committing

Used in:
- **Token conservation proofs** — proving balance changes sum correctly without revealing individual balances
- **DLV vault state** — committing to vault parameters before revealing them

---

## Token Conservation

Token conservation is enforced at every state transition:

```
B_{n+1} = B_n + Delta
B >= 0
```

Where `B_n` is the balance at commit n, `Delta` is the change (positive for receives, negative for sends), and `B_{n+1}` must be non-negative.

This is verified by the core crate at every transition — the SDK cannot bypass this check.

---

## Tripwire Fork-Exclusion

The Tripwire theorem guarantees that no two valid successors can exist from the same parent commit tip:

```
Given parent tip T with hash H(T):
  - Successor S1 signed with key K → valid
  - Successor S2 signed with key K → IMPOSSIBLE

Because:
  - Creating S2 requires a second valid SPHINCS+ signature for a different
    message with the same key under the same parent hash
  - SPHINCS+ EUF-CMA prevents this
  - Even if the signature could be forged, BLAKE3 collision resistance
    prevents finding two different states with the same parent hash
```

This eliminates double-spending without a central coordinator — if a device tries to send to two different recipients from the same state, the second transaction is cryptographically impossible.

---

## Key Derivation

DSM uses BLAKE3 in keyed mode for key derivation:

```rust
// Derive a child key from a parent key and context
fn derive_key(parent: &[u8; 32], context: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(parent);
    hasher.update(context.as_bytes());
    *hasher.finalize().as_bytes()
}
```

### DLV Unlock Key

The DLV unlock key (used as the HTLC preimage in the Bitcoin bridge) is derived from the burn proof:

```
sk_V = BLAKE3("DSM/dlv-unlock\0" || L || C || σ)
```

Where:
- `L` = DLV lineage identifier
- `C` = commit hash at the time of burn
- `σ` = stitched proof-of-completion from the bilateral burn

Without `σ`, the preimage cannot be computed, and the HTLC cannot be swept. The burn is irreversible (Tripwire), so mathematical possession of the dBTC transfers between users via bilateral hash chains.

---

## Bitcoin Key Management

DSM derives Bitcoin keys through a BIP84 HD wallet from device entropy:

```
Device entropy (32 bytes)
    │
    ▼  BIP39 — 24-word mnemonic (never stored)
    │
    ▼  BIP39 seed (64 bytes, no passphrase)
    │
    ▼  BIP32 master key (zeroized after derivation)
    │
    ▼  BIP84 account key  m/84'/coin'/0'
       │
       ├─ Receive: m/84'/coin'/0'/0/0, /0/1, ...
       └─ Change:  m/84'/coin'/0'/1/0, /1/1, ...
```

- `coin = 0` for mainnet, `coin = 1` for testnet/signet
- Bitcoin addresses are native SegWit (P2WPKH): `bc1q...` / `tb1q...`
- Signature scheme: ECDSA secp256k1 (Bitcoin-compatible, distinct from the post-quantum SPHINCS+ used in DSM protocol)

---

Next: [Chapter 7 — Storage Nodes](07-storage-nodes.md)
