# Appendix A — Glossary

Terminology reference for the DSM protocol.

---

| Term | Definition |
|------|-----------|
| **b0x** | Unilateral transport mechanism for sending state updates to a device that is offline. Messages are stored on storage nodes and retrieved when the device reconnects. |
| **Bilateral Transfer** | A transfer between two parties using a three-phase commit protocol (Prepare → Accept → Commit). Both participants advance their hash chains. |
| **BLAKE3** | Cryptographic hash function used throughout DSM with domain separation. All hashes use the format `BLAKE3-256("DSM/<domain>\0" \|\| data)`. |
| **BLE** | Bluetooth Low Energy. Used for offline bilateral transfers between two devices in close proximity. |
| **Bridge** | The binary MessagePort channel connecting the React frontend to the Kotlin Android layer. Carries protobuf-encoded `BridgeRpcRequest`/`BridgeRpcResponse` messages. |
| **ByteCommit** | A state commitment anchored on storage nodes for persistence and replication. |
| **CPTA** | Content-Addressed Token Policy Anchor. Binds token policies to their canonical content hash: `BLAKE3("DSM/cpta\0" \|\| canonical_bytes)`. |
| **dBTC** | Deterministic Bitcoin. A 1:1 Bitcoin-backed token inside DSM. Bridge uses HTLCs on Bitcoin and DLVs on DSM. |
| **DBRW** | Device-Bound Random Walk. Anti-cloning mechanism using dual-factor binding: silicon fingerprint + environment entropy. |
| **DeTFi** | Decentralized Token Finance. DSM's framework for programmable token operations including DLVs, smart commitments, and atomic swaps. |
| **Device Tree** | Hierarchical structure aggregating per-device Sparse Merkle Trees into a global tree for cross-device verification. |
| **DJTE** | Deterministic Join-Triggered Emissions. Token emission model where new tokens are minted deterministically when new participants join. |
| **DLV** | Deterministic Limbo Vault. Time-locked vault with lifecycle states (PendingActive → Active → PendingClosure → Claimed). Used for Bitcoin bridge, atomic swaps, and conditional transfers. |
| **Domain Separation** | Technique of prefixing hash inputs with a unique tag to prevent cross-protocol attacks. DSM uses `"DSM/<name>\0"` prefixes. |
| **Envelope v3** | The sole wire container for all DSM messages. Prefixed with `0x03` framing byte, contains protobuf-encoded payload and SPHINCS+ signature. |
| **EUF-CMA** | Existential Unforgeability under Chosen Message Attack. The security property of SPHINCS+ signatures — an adversary cannot forge a signature even after seeing signatures on chosen messages. |
| **Fisher-Yates Shuffle** | Deterministic algorithm used for replica placement on storage nodes. Keyed variant ensures all clients independently compute the same node assignment. |
| **Genesis** | The initial state commit for a new device identity. Created via MPC (Multi-Party Computation) service. |
| **Hash Chain** | Append-only sequence of state commits where each commit references the BLAKE3 hash of its predecessor. |
| **HTLC** | Hash Time-Locked Contract. Bitcoin script pattern used in the dBTC bridge for atomic BTC↔dBTC swaps. |
| **JAP** | Join-Activated Participation. Component of the DJTE emissions model. |
| **JNI** | Java Native Interface. The boundary between Kotlin (Android) and Rust (SDK). DSM exposes 87+ JNI methods via `UnifiedNativeApi`. |
| **Logical Tick** | A time-like counter derived from hash chain adjacency (commit heights, BLAKE3 iteration counters). Used instead of wall-clock time for all protocol ordering. |
| **MessagePort** | WebView API for binary communication between JavaScript and Kotlin. Carries `[8-byte msgId][protobuf bytes]`. |
| **ML-KEM-768** | Module-Lattice Key Encapsulation Mechanism (formerly Kyber). Post-quantum key exchange used for BLE sessions and TLS. |
| **MPC** | Multi-Party Computation. Used for genesis creation — the MPC service contributes entropy that no single party controls. |
| **PBI** | Platform Boot Identity. The bootstrap process that establishes device identity from DBRW entropy, device ID, and genesis hash. |
| **Pedersen Commitment** | Cryptographic commitment scheme with hiding and binding properties. Used for token conservation proofs. |
| **PRLSM** | Partitioned Replicated Lightweight State Machine. DSM's approach to statelessness across the network. |
| **Signet** | Bitcoin's shared test network. Public test coins, public blocks, and realistic confirmation flow without using mainnet funds. |
| **SDK_READY** | Atomic flag in the Rust SDK that gates all post-bootstrap operations. Set after successful PBI initialization. |
| **SMT** | Sparse Merkle Tree. Per-device data structure for efficient membership and non-membership proofs. |
| **SPHINCS+** | Hash-based post-quantum digital signature scheme. Stateless, EUF-CMA secure. NIST PQC standard. Used for all DSM signatures. |
| **SPV Proof** | Simplified Payment Verification. Merkle proof + block header proving a transaction is buried in the Bitcoin blockchain. Used in the dBTC bridge. |
| **Storage Node** | Index-only, clockless, signature-free HTTP server for state persistence. Never validates protocol rules. |
| **Three-Phase Commit** | The bilateral transfer protocol: Prepare (sender proposes) → Accept (receiver validates) → Commit (both finalize). |
| **Tripwire Fork-Exclusion** | The core safety theorem: no two valid successors can exist from the same parent commit tip. Relies on SPHINCS+ EUF-CMA + BLAKE3 collision resistance. |
| **UnifiedNativeApi** | Kotlin class declaring all 87+ JNI methods. Previously named `Unified` (old `.so` files have `Unified_*` symbols). |

---

Back to [Table of Contents](README.md)
