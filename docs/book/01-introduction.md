# Chapter 1 — Introduction

## What is DSM?

DSM (Deterministic State Machine) is a post-quantum, clockless bilateral state machine protocol for trustless token transfers between devices. It enables fully offline transactions over Bluetooth LE, instant-final transfers with no gas fees, and a Bitcoin bridge (dBTC) — all without a central authority or persistent server-side state.

The protocol runs entirely on-device. Storage nodes are index-only persistence services that never sign, validate, or gate acceptance of state transitions. All business logic — cryptographic verification, balance enforcement, and state evolution — executes locally.

## Design Philosophy

### Protobuf-only, no JSON

All protocol messages use Protocol Buffers (Envelope v3 with `0x03` framing byte). JSON is banned from the protocol layer. This ensures compact wire representation, deterministic serialization, and no ambiguity in field encoding.

### No wall-clock time

DSM uses no real-world timestamps in protocol logic. All ordering, expiry, and rate limiting within the protocol derive from hash chain adjacency — logical ticks based on commit heights and BLAKE3 iteration counters. Wall-clock time is permitted only for non-authoritative operational tasks like BLE session staleness detection and UI display metadata.

### Pure core, mediated I/O

The `dsm` core crate is pure Rust with no network calls, no OS time, no UI, and no global state. The SDK layer (`dsm_sdk`) mediates all I/O — JNI bindings, storage node communication, BLE transport, and platform-specific adapters.

### Post-quantum from day one

The cryptographic stack uses BLAKE3 for domain-separated hashing, SPHINCS+ for post-quantum digital signatures (EUF-CMA), ML-KEM-768 (Kyber) for key encapsulation, and DBRW for hardware-bound anti-cloning. No classical-only primitives are used in protocol-critical paths.

### Binary-first

Bytes flow through the core. Base32 Crockford encoding is used only at UI/string boundaries for display and QR codes. Hex encoding is banned in core protocol code.

## Key Concepts

### Hash Chains

Every device maintains a straight hash chain. Each state commit references the BLAKE3 hash of the previous state, forming an append-only ledger. State transitions produce a unique, irreversible commitment — given the same inputs, any party can independently verify the output.

### Bilateral Transfers

Transfers between two parties use a three-phase commit protocol (Prepare → Accept → Commit). Both participants advance their respective hash chains. The Tripwire Fork-Exclusion theorem guarantees no two valid successors can exist from the same parent tip, preventing double-spending without a central coordinator.

### Envelope v3

All wire messages are wrapped in Envelope v3 containers with a `0x03` framing byte prefix. The envelope carries protobuf-encoded payloads for all operations: genesis, bilateral transfers, DLV operations, BLE commands, and bridge RPC.

### Storage Nodes

Storage nodes are "dumb" HTTP persistence servers. They hold encrypted state blobs and provide index/lookup services but never interpret protocol semantics. Replica placement uses deterministic keyed Fisher-Yates shuffle — no leader election or consensus protocol is needed.

### DBRW Anti-Cloning

Device-Bound Random Walk (DBRW) binds each identity to specific hardware using a dual-factor approach: silicon fingerprint + environment binding. This prevents state cloning attacks where an adversary copies device state to a second device.

### Deterministic Limbo Vaults (DLV)

DLVs are time-locked vaults used for the Bitcoin bridge (dBTC), atomic swaps, and conditional transfers. They transition through lifecycle states (PendingActive → Active → PendingClosure → Claimed) with fulfillment conditions enforced on-device.

### dBTC (Deterministic Bitcoin)

dBTC is a 1:1 Bitcoin-backed token living inside DSM. The bridge uses HTLCs on the Bitcoin side and DLVs on the DSM side. After entry (BTC → dBTC), tokens trade freely on the DSM edge — gas-free, instant-final, offline-capable — until exit (dBTC → BTC) moves them back to Bitcoin.

## The 12 Hard Invariants

These rules are inviolable. Violating any one is build-blocking:

1. **Envelope v3 only** — sole wire container, `0x03` framing byte prefix
2. **No JSON** — protobuf-only transport throughout the protocol
3. **No hex in protocol** — raw bytes internally, Base32 Crockford at string boundaries
4. **No wall-clock time in protocol** — logical ticks from hash chain adjacency only
5. **No TODO/FIXME/HACK/XXX** — production-quality mandate
6. **No legacy code** — fully remove old paths when replacing systems
7. **Single authoritative path** — UI → MessagePort → Kotlin Bridge → JNI → SDK → Core
8. **Core is pure** — no network, no OS time, no UI, no global state
9. **BLAKE3 domain separation** — all hashing uses `BLAKE3-256("DSM/<domain>\0" || data)`
10. **Tripwire Fork-Exclusion** — no two valid successors from the same parent tip
11. **Token conservation** — `B_{n+1} = B_n + Delta, B >= 0`
12. **Storage nodes are index-only** — never sign, never validate, never gate acceptance

## Who This Guide Is For

This handbook is for developers who want to:

- **Run the DSM workspace locally** — bring up the repo, local services, Bitcoin signet flows, and device test paths
- **Understand the protocol and implementation** — trace how the Android app, frontend, SDK, core, storage nodes, BLE, and dBTC fit together
- **Work on DSM itself** — modify the wallet, protocol paths, storage nodes, tooling, tests, and docs
- **Contribute rigorously** — fix bugs, close gaps, improve documentation, and tighten the implementation against the stated invariants

### Reading Paths

| Role | Start With |
|------|-----------|
| New developer | Ch 2 (Quickstart) → Ch 3 (Dev Setup) → Ch 4 (Architecture) |
| Protocol researcher | Ch 4 (Architecture) → Ch 6 (Crypto) → Ch 15 (Security Model) |
| Mobile developer | Ch 3 (Dev Setup) → Ch 5 (Protocol Reference) → Ch 9 (BLE Testing) |
| Backend/infrastructure | Ch 7 (Storage Nodes) → Ch 8 (Bitcoin/dBTC) → Ch 10 (Testing) |
| Contributor | Ch 14 (Contributing) → Ch 12 (Command Reference) → Ch 13 (Troubleshooting) |

## Authoritative Sources

#### The research papaers & formal specs can be found here:
[deterministicstatemachine.org](https://www.deterministicstatemachine.org/)

Next: [Chapter 2 — Quickstart](02-quickstart.md)
