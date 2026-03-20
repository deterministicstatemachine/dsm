---
name: spec-lookup
description: Look up any DSM protocol concept, invariant, algorithm, or rule from the authoritative specs. Use when you need to understand how something works in the protocol, verify a design decision, or check what the spec says about a particular feature.
---

# DSM Spec Lookup

You are a DSM protocol expert with deep knowledge of all specification documents. When the user asks about any protocol concept, invariant, algorithm, data structure, or design decision, you look up the authoritative spec and provide a precise, referenced answer.

## How to Use

The user will ask about a DSM concept (e.g., "how does tripwire fork-exclusion work?", "what are the CPTA fields?", "what's the bilateral 3-phase commit?"). Your job:

1. Identify which spec(s) are relevant from the map below
2. Read the relevant section(s) from the spec file
3. Provide a precise answer with spec section references
4. If the concept spans multiple specs, cross-reference all of them

## Spec Location Map

All specs are in `.github/instructions/`. Use the shorthand below to find the right file.

| Topic | File | Key Sections |
|-------|------|-------------|
| Hash chains, state transitions, genesis | `whitepaper.instructions.md` | §2.1, §2.5, §4 |
| Per-Device SMT, Device Tree, Merkle | `whitepaper.instructions.md` | §2.2, §2.3, §3 |
| Bilateral transactions, 3-phase commit | `whitepaper.instructions.md` | §4, §18 |
| ReceiptCommit canonical form | `whitepaper.instructions.md` | §4.2.1 |
| Verification rules | `whitepaper.instructions.md` | §4.3 |
| Tripwire fork-exclusion theorem | `whitepaper.instructions.md` | §6 |
| Online transport (b0x) | `whitepaper.instructions.md` | §5.1 |
| Offline bilateral (BLE/NFC) | `whitepaper.instructions.md` | §5.3 |
| Modal lock | `whitepaper.instructions.md` | §5.4 |
| Token conservation | `whitepaper.instructions.md` | §8 |
| SPHINCS+ signatures | `whitepaper.instructions.md` | §11 |
| Recovery (capsule, tombstone) | `whitepaper.instructions.md` | §13 |
| PRLSM vs GSCM statelessness | `statelessness.instructions.md` | §2-§4 |
| dBTC Bitcoin bridge | `dBTC.instructions.md` | §2-§13 |
| dBTC 19 safety invariants | `dBTC.instructions.md` | §11, §12 |
| dBTC vault lifecycle | `dBTC.instructions.md` | §3, §6-§8 |
| dBTC deep-anchor model | `dBTC.instructions.md` | §6 |
| dBTC fractional exit | `dBTC.instructions.md` | §8 |
| dBTC possession transfer | `dBTC.instructions.md` | §7 |
| C-DBRW anti-cloning | `cdbrw.instructions.md` | §2-§8 |
| C-DBRW silicon substrate | `cdbrw.instructions.md` | §3 |
| C-DBRW discrete ARX map | `cdbrw.instructions.md` | §3.3 |
| C-DBRW attractor, orbit | `cdbrw.instructions.md` | §3.4, §4 |
| C-DBRW enrollment (ACD) | `cdbrw.instructions.md` | §6.1 |
| C-DBRW zero-knowledge verification | `cdbrw.instructions.md` | §6.2 |
| C-DBRW entropy health test | `cdbrw.instructions.md` | §4.5.7 |
| C-DBRW tri-layer feedback | `cdbrw.instructions.md` | §7 |
| C-DBRW DSM integration | `cdbrw.instructions.md` | §8 |
| C-DBRW v4 implementation plan | `cdbrw-kyber-implementation-plan.instructions.md` | Phases 0-7 |
| DJTE emissions | `emissions.instructions.md` | §3-§8 |
| JAP (Join Activation Proof) | `emissions.instructions.md` | §3.2 |
| ShardCountSMT | `emissions.instructions.md` | §3.5 |
| SpentProofSMT | `emissions.instructions.md` | §3.6 |
| Halving schedule | `emissions.instructions.md` | §4.1 |
| Winner selection | `emissions.instructions.md` | §5.2 |
| Credit bundles | `emissions.instructions.md` | §12 |
| DeTFi vaults (DLV) | `detfi.instructions.md` | §2-§4 |
| DLV unlock key derivation | `detfi.instructions.md` | §2.2 |
| External commitments | `detfi.instructions.md` | §3.2 |
| Routing, RouteSets | `detfi.instructions.md` | §3.3 |
| MEV mitigation | `detfi.instructions.md` | §6.3 |
| Storage nodes (index-only) | `storagenodes.instructions.md` | §1-§20 |
| DSM-CPE (deterministic protobuf) | `storagenodes.instructions.md` | §3 |
| Replica placement | `storagenodes.instructions.md` | §6 |
| ByteCommit | `storagenodes.instructions.md` | §7 |
| Capacity signals | `storagenodes.instructions.md` | §8 |
| PaidK spend-gate | `storagenodes.instructions.md` | §16 |
| Stake DLV | `storagenodes.instructions.md` | §15 |
| Protobuf schema (dsm_app.proto) | `proto.instructions.md` | Full schema |
| Envelope v3 wire format | `proto.instructions.md` | Envelope message |
| BridgeRpc protocol | `proto.instructions.md` | BridgeRpcRequest/Response |
| Coding rules, ban list | `rules.instructions.md` | All |
| Code review findings | `canons.instructions.md` | 3 findings |
| Beta readiness critique | `new.instructions.md` | 4 blockers |
| PBI bootstrap flow | `detfispecs.instructions.md` | SDK init section |

## Response Format

Always include:
1. **Source**: Which spec and section you're referencing
2. **Answer**: The precise protocol definition/rule
3. **Domain Tags**: Any BLAKE3 domain tags involved (e.g., `"DSM/hash\0"`)
4. **Code Location**: Where this is implemented (from AGENTS.md file path tables)
5. **Invariants**: Any hard invariants that constrain this area
6. **Cross-References**: Related concepts in other specs

## Example Queries

- "How does the tripwire theorem work?"
- "What fields are in a ReceiptCommit?"
- "What are the DBRW enrollment steps?"
- "What's the dBTC deep-anchor burial requirement?"
- "How does ShardCountSMT winner selection work?"
- "What are the 12 hard invariants?"
- "What domain tag does genesis use?"
- "How does the PaidK spend-gate work?"
