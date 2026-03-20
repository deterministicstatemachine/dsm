---
name: crypto-guide
description: Expert guide for the DSM cryptographic stack — BLAKE3 domain-separated hashing, SPHINCS+ post-quantum signatures, ML-KEM-768 key exchange, C-DBRW anti-cloning, Pedersen commitments, ChaCha20-Poly1305 encryption, and key derivation. Use when working on any crypto primitive.
---

# DSM Cryptographic Stack Expert Guide

You are a cryptography expert for the DSM protocol. Every crypto primitive is post-quantum, deterministic, and domain-separated.

## Primitive Overview

| Primitive | Algorithm | Domain Prefix | Code Location |
|-----------|-----------|---------------|---------------|
| Hashing | BLAKE3-256 | `"DSM/<name>\0"` | `dsm/src/crypto/blake3.rs`, `crypto/hash.rs` |
| Signatures | SPHINCS+ (SPX256f) | — | `dsm/src/crypto/sphincs.rs` |
| Key Exchange | ML-KEM-768 (Kyber) | — | `dsm/src/crypto/kyber.rs` |
| Anti-Cloning | C-DBRW | `"DSM/dbrw-bind\0"` | `dsm/src/crypto/dbrw.rs`, `crypto/dbrw_health.rs` |
| Commitments | Pedersen | — | `dsm/src/crypto/pedersen.rs` |
| Encryption | ChaCha20-Poly1305 | — | (at-rest encryption) |
| Key Derivation | BLAKE3 keyed | Per-use domain | `dsm/src/crypto/hash.rs` |
| Policy Anchors | CPTA | `"DSM/cpta\0"` | `dsm/src/cpta/` |

## BLAKE3 Domain Separation

**Hard Invariant #9**: All hashing uses `BLAKE3-256("DSM/<domain>\0" || data)`.

### Complete Domain Tag Registry

| Domain Tag | Usage | Spec Reference |
|------------|-------|----------------|
| `"DSM/hash\0"` | General-purpose hashing | Whitepaper §2.1 |
| `"DSM/genesis\0"` | Genesis commitment | Whitepaper §2.5 |
| `"DSM/devid\0"` | Device ID derivation | Whitepaper §2.5 |
| `"DSM/device\0"` | Device ID (storage nodes) | Storage §4 |
| `"DSM/merkle-node\0"` | Merkle tree internal nodes | Whitepaper §2.2 |
| `"DSM/merkle-leaf\0"` | Merkle tree leaf nodes | Whitepaper §2.2 |
| `"DSM/smt-key\0"` | SMT relationship key | Whitepaper §2.2 |
| `"DSM/receipt-commit\0"` | ReceiptCommit hash | Whitepaper §4.2.1 |
| `"DSM/step-salt\0"` | Step salt derivation | Storage §5 |
| `"DSM/addr-G\0"` | b0x genesis address | Whitepaper §5.1 |
| `"DSM/addr-D\0"` | b0x device address | Whitepaper §5.1 |
| `"DSM/cpta\0"` | Token policy anchor | Whitepaper §9 |
| `"DSM/token-genesis\0"` | Token genesis | dBTC §2 |
| `"DSM/dlv\0"` | Vault ID | DeTFi §2 |
| `"DSM/ext\0"` | External commitment | DeTFi §3.2 |
| `"DSM/external-source-id\0"` | External source ID | Proto |
| `"DSM/external-commit-id\0"` | External commit ID | Proto |
| `"DSM/dbrw-bind\0"` | DBRW binding key | C-DBRW §8 |
| `"DSM/DBRW\0"` | DBRW commitment | Storage §4 |
| `"DSM/attractor-commit\0"` | C-DBRW ACD | C-DBRW §6.1 |
| `"DSM/kyber-coins\0"` | ML-KEM deterministic coins | C-DBRW v4 Phase 3 |
| `"DSM/ek\0"` | Ephemeral key derivation | C-DBRW §8 |
| `"DSM/place\0"` | Replica placement | Storage §6 |
| `"DSM/contact/add\0"` | Contact add | Storage §12 |
| `"DSM/contact/accept\0"` | Contact accept | Storage §12 |
| `"DSM/stake\0"` | Stake DLV | Storage §15 |
| `"DJTE.JAP"` | Join Activation Proof | Emissions §3.2 |
| `"DJTE.SHARD"` | Shard function | Emissions §3.1 |

### Pattern

```rust
// Correct usage
let hash = blake3::keyed_hash(b"DSM/genesis\0", &data);

// WRONG — missing domain prefix
let hash = blake3::hash(&data);  // NEVER DO THIS
```

## SPHINCS+ (Post-Quantum Signatures)

- **Parameter set**: SPX256f (fast, target < 2s signing)
- **Security**: EUF-CMA (existential unforgeability under chosen message attack)
- **Key evolution**: Per-step key derivation from hash chain state
- **Tripwire theorem**: SPHINCS+ EUF-CMA + BLAKE3 collision resistance → no two valid successors from same parent tip

### Key Derivation Chain

```
E_{n+1} = HKDF-BLAKE3("DSM/ek\0", h_n || C_pre || k_step || K_DBRW)
(EK_sk, EK_pk) = SPHINCS+.KeyGen(E_{n+1})
```

## ML-KEM-768 (Kyber)

- **NOT ML-KEM-1024** — 768 is the chosen parameter set
- **Deterministic encapsulation**: coins derived from `BLAKE3("DSM/kyber-coins\0" || h_n || C_pre || DevID || K_DBRW)[0:32]`
- **Usage**: Post-quantum key encapsulation for bilateral sessions

## C-DBRW Anti-Cloning

**Treats silicon thermal dynamics as a chaotic dynamical system — the thermal chaos IS the signal.**

### Core Components

1. **Silicon Substrate State**: `S = (t, v, τ)` — temperature (K), voltage (V), cache latency (ns)
2. **Discrete ARX Map**: `x_{n+1} = (x_n + ROL(x_n, r) XOR μ_n) mod 2^32`, r=7 default
3. **Orbit**: N ≥ 4096 iterations, B ∈ {256, 512, 1024} histogram bins
4. **Attractor**: Unique invariant probability measure per physical device
5. **ACD**: Attractor Commitment Digest = `BLAKE3("DSM/attractor-commit\0" || H_bar || ε_intra || B || N || r)`

### Entropy Health Test (every auth)

Three conditions on n=2048 thermal samples:
- `H_hat ≥ 0.45` (entropy)
- `|ρ_hat| ≤ 0.3` (autocorrelation)
- `L_hat ≥ 0.45` (LZ78 compressibility — NOT deflate)

### Manufacturing Gate

`σ_device = std(H_bar)/max(H_bar) ≥ 0.04`

### Current Status

- **Beta**: Observe-only — log/report anomalies but do NOT enforce/block
- **Known Gap**: DBRW thermal feedback not surfaced to frontend UI
- **v4 Plan**: 7 phases in `cdbrw-kyber-implementation-plan.instructions.md`

## Pedersen Commitments

- Hiding + binding commitments
- Used for value confidentiality in token operations
- Code: `dsm/src/crypto/pedersen.rs`

## Banned Crypto Patterns

| Banned | Why | Use Instead |
|--------|-----|-------------|
| SHA-256 | Not BLAKE3 | BLAKE3-256 with domain tag |
| `hex::encode/decode` in Core/SDK | Invariant #3 | Raw bytes, Base32 Crockford at boundaries |
| Floating-point in crypto | Non-deterministic | Integer arithmetic (ARX map uses u32) |
| `unsafe {}` | Unless audited | Safe Rust |
| SPX256s | Too slow (>2s) | SPX256f |
| ML-KEM-1024 | Over-specified | ML-KEM-768 |
| deflate for entropy test | Wrong algorithm | LZ78 compression |

## Spec References

- BLAKE3: Whitepaper §2.1, Rules
- SPHINCS+: Whitepaper §11
- ML-KEM: Whitepaper §2.4, C-DBRW v4 Phase 3
- C-DBRW: `cdbrw.instructions.md` (full spec), `cdbrw-kyber-implementation-plan.instructions.md` (v4 plan)
- Pedersen: Whitepaper §crypto section
- Domain tags: `dsm/src/common/domain_tags.rs`
