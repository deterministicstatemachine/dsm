# Extraction — claude-chat

- **Extractor:** Claude Opus 5.5 (claude.ai chat, Filesystem + terminal connectors)
- **Format:** `specs/requirements/MASTER_REQUIREMENTS.md` §4–§6
- **Corpus hashes used:** DSM `c21b78c5…`, SoFi `86bce477…`, dBTC `233a3e72…`, Storage `cb306067…` (match §1)
- **Note:** this extractor drafted `DSM_Storage_Node_Specification.md` at the owner's request. Its extraction of that document should be cross-checked against the other extractors with that in mind.
- **Status:** COMPLETE. All four specifications extracted against the versions in PR #967: 798 requirements. Every section of every file is accounted for in the coverage ledger, and every quote is verified on its cited line.
- **Independence:** no other extraction file existed when this one was started.

---

## Requirements

### DSM-HL-001 — 1 The Central Question

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-001/L81 | theorem | derived | For one committed linear resource, two conflicting consumptions cannot both occur in one valid realized history (the core safety objective; proved in §52). | For one committed linear resource, two conflicting consumptions | — | none |
| DSM-HL-001/L85 | obligation | derived | Every transition carries enough canonical structure for a verifier to decide, with no global order, whether it is a valid continuation of the state it claims to extend. | each transition carries enough canonical structure for a verifier to determine whether it is a | — | none |

### DSM-HL-001-1 — 1.1 Candidate Futures Versus Realized Futures

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-001-1/L90 | invariant | derived | Multiple candidate futures from one parent are permitted. The safety property constrains only which candidates can join one realized lineage. | DSM permits multiple candidate futures. | — | none |

### DSM-HL-004 — 4 The Two Halves of an Agreement

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-004/L187 | invariant | derived | A transition that is not a valid successor of the state it claims to extend fails the realization predicate and never exists as a state. | A transition that is not a valid successor of the state it claims to extend cannot be | — | none |
| DSM-HL-004/L203 | dependency-boundary | derived | Offline consent (both parties present, both sign live) is imported from Part IV (offline, out of scope this round). | Offline, both parties are present. | — | none |
| DSM-HL-004/L207 | authority | derived | Online, an absent counterparty's consent must already exist as terms committed in its own state (a DLV). Anyone who meets those terms completes an agreement the owner already consented to. | That is what a Deterministic Limbo Vault is | — | none |
| DSM-HL-004/L227 | invariant | derived | The full state commitment ρ binds ρcore plus the digests of the precommitted candidate space and the guard family; changing any of them changes ρ. | additionally binds the digests of the precommitted | — | none |
| DSM-HL-004/L230 | invariant | derived | In online mode, u is a committed integer position that increments on every value-moving advance. | is a committed integer position that increments on every value-moving | — | none |
| DSM-HL-004/L231 | obligation | derived | A root is always presented together with its position, as (ρ, u). | A root is always presented | — | none |
| DSM-HL-004/L248 | invariant | derived | K = κres(s, x) is derived from the parent state and the resource descriptor only, so two candidates consuming the same thing from the same parent derive the same K. | state and the descriptor, and only from those | — | none |
| DSM-HL-004/L251 | invariant | derived | The consumed set Σ only grows, and realization requires K ∉ Σ. | It only grows. | — | none |
| DSM-HL-004/L255 | invariant | derived | Distinct relationship chains never share a parent, key, or counterparty. | Chains never share a parent, key, or counterparty. | — | none |

### DSM-HL-005 — 5 The Six Questions Every Transition Must Answer

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-005/L281 | transition | explicit | Accept(s, s′, w) is exactly CandidateOK ∧ GuardOK ∧ StructuralOK ∧ LinearityOK ∧ PolicyOK ∧ ModeOK. | The full acceptance predicate is | — | none |
| DSM-HL-005/L290 | invariant | explicit | Every conjunct of Accept is Boolean, so Accept ∈ {True, False}. | Every term is Boolean. | — | none |
| DSM-HL-005/L295 | transition | explicit | A transition either satisfies the full acceptance predicate or does not execute; there is no third protocol value. | Amendment A1 (owner, 2026-09-22) — acceptance stays binary. | DSM-HL-005/L281 | none |
| DSM-HL-005/L297 | liveness-boundary | explicit | Evidence that cannot be obtained yet is not a verdict: nothing executes and the attempt is retried (API status Pending/Unavailable). Both layers can end in Invalid: network evidence, once obtained, can show the transition Invalid, and when retrying ends without the evidence the transition is Invalid; where others depend on the outcome, retrying ends only through the challenge rule (storage §9.1). | Evidence that cannot be obtained yet is not a verdict. | — | none |
| DSM-HL-005/L298 | prohibition | explicit | A transition that does not execute leaves nothing in state or in storage. | Nothing negative is recorded. | — | none |
| DSM-HL-005/L300 | obligation | explicit | Where something waits on an outcome, the subsystem derives from raw reads whether a transition that has not executed can still execute. The next trade against a vault proceeds only once the trade ahead has executed or provably never can. | Where something else waits on the outcome | — | none |

### DSM-HL-006 — 6 DSM Does Not Need Global Ordering

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-006/L309 | invariant | derived | Global ordering is not an input to validity. Validity is expressed through parent state, explicit dependencies, chain adjacency, authenticated roots, precommitment, guards, resource consumption, and policy. | It removes global ordering from the validity mechanism. | — | none |
| DSM-HL-006/L328 | obligation | derived | An application that needs a sequence relation encodes it explicitly in canonical state or policy. No external ordering service supplies it. | If an application requires a sequence relation, that relation can be encoded as part of state. | — | none |

### DSM-HL-008 — 8 Both Candidates Can Look Valid

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-008/L399 | authority | derived | Each resource has exactly one acceptor, and its accept step is atomic: the successor root and the updated Σ are adopted together or not at all. | accept step is atomic | — | none |
| DSM-HL-008/L419 | theorem | derived | The static uniqueness form (at most one candidate passes the predicate) holds for selector families only. The realized-history form (§52) is the form that covers every guard family. | The static form of the theorem, where at most one candidate even passes the predicate | — | none |

### DSM-HL-009 — 9 Same Balance, Two Counterparties

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-009/L490 | invariant | derived | A balance is a holder-scoped leaf in the holder's device SMT with descriptor (cpta-balance, GT, PT, holder). Every transfer from it, over any relationship, derives the same K_bal from the same parent. | Its resource descriptor is holder-scoped | — | none |
| DSM-HL-009/L511 | invariant | derived | Every device root carries a committed progression object u; online, it is a position counter incremented on every root advance. | Every DSM device root carries a committed progression object u | DSM-HL-004/L230 | none |
| DSM-HL-009/L515 | invariant | derived | u is inside the root, so the root cannot advance without the counter and the counter cannot advance without the root. | The counter is inside the root | — | none |
| DSM-HL-009/L519 | transition | derived | A relationship is created only when both sides take the counterparty's committed device state from the mirror and verify it, not by first contact. | A relationship is not created by first contact. | — | none |
| DSM-HL-009/L524 | evidence | derived | The counterparty verifies the signed root chain that produced (ρA, uA) itself. The mirror supplies bytes, never the verdict. | He verifies the signed root chain that produced | — | none |
| DSM-HL-009/L529 | obligation | explicit | At acceptance, the receiver reads the payer's register cell at the next position only after every check it can decide from what it already holds has passed. | checked everything he can from what he already holds (Amendment A4) | — | none |
| DSM-HL-009/L530 | obligation | derived | Every value-moving advance of a device root must be registered in the economic-root register. | every value-moving advance of a device root has to be registered | — | none |
| DSM-HL-009/L535 | invariant | derived | The register has one cell per (G, DevID, position), and the cell key is derived from those three values. | key is derived from those three values | — | none |
| DSM-HL-009/L537 | invariant | derived | The cell leader is chosen by a deterministic shuffle seeded from G, DevID, position, and the validated root at the previous position. No node id or availability view enters the seed. | seeded from G, DevID, the position and Alice | — | none |
| DSM-HL-009/L540.a | authority | derived | A register cell entry is a root claim signed by the device owner, and only the owner can sign one. | only Alice can sign one | — | none |
| DSM-HL-009/L540.b | obligation | derived | The writer writes the claim to the leader first, then the same bytes to the other members. | She writes it to the leader | — | none |
| DSM-HL-009/L543 | evidence | derived | The rule deciding a cell is evaluated by the verifier from raw reads, never by a node. | to evaluate, from raw reads | — | none |
| DSM-HL-009/L544 | invariant | derived | The root at position n+1 is the first claim naming that cell at the leader. It is final once the leader and two other members hold it; a claim the leader does not hold is never final. | is final once the leader and two other members hold it | — | none |
| DSM-HL-009/L545 | liveness-boundary | derived | If the leader is unreachable the cell waits. No other member stands in. | no other member stands in | — | none |
| DSM-HL-009/L549 | transition | derived | Cell holds a root other than the presented one → the presented parent is superseded → reject. | The cell holds a root that is not the one Alice is presenting | — | none |
| DSM-HL-009/L552 | transition | derived | Cell empty → accept only once the payer has registered the presented root at n+1 and the receiver has derived it final from its own reads. No registration, no accept. | The cell is empty. Charlie will accept only once | — | none |
| DSM-HL-009/L556 | transition | derived | Cell holds exactly the presented root → accept. | The cell holds exactly the presented root. Accept. | — | none |
| DSM-HL-009/L558 | transition | explicit | The receiver first decodes the presentation, verifies its signatures and the payer's signed root chain, and runs the precommitment, guard, linearity and policy checks on evidence in hand; if any is Invalid the transition is Invalid with no network access. Only then does it read the register cell and fetch remaining evidence. | Amendment A4 (owner, 2026-09-22) — order of checks at acceptance. | — | none |
| DSM-HL-009/L562 | prohibition | explicit | Nothing is fetched from the network for a transition already Invalid on what the receiver holds. The verdict itself does not depend on the order of checks. | The verdict does not depend on the order. | — | none |
| DSM-HL-009/L609 | invariant | derived | A device names exactly one root per position and is the only party that can name it, whoever the counterparty was. | It cares that a device can name one root per | — | none |
| DSM-HL-009/L619 | safety-assumption | derived | The leader keeps what it holds, in arrival order, across restarts and restores, never altering or losing it. | It depends on the leader keeping what it holds, in the order it arrived, across restarts and restores | — | none |
| DSM-HL-009/L629 | dependency-boundary | derived | A receiver who cannot reach the leader is an offline receiver, and the offline machinery (§66–71) applies. Out of scope this round. | If the leader is unreachable, Charlie is not a weaker online verifier. | — | none |
| DSM-HL-009/L658 | liveness-boundary | derived | A payer who withholds registration gains no second spend; the receiver cannot accept. This is a liveness failure, not a safety failure. | A payer who withholds does not gain a second spend | — | none |

### DSM-HL-010 — 10 A Transition Cannot Cross Relationships

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-010/L672 | invariant | derived | A relationship transition's SMT leaf key embeds both device identifiers. Its parent is a node of that relationship's chain only, and its descriptor is (relationship, k_AB, h_AB,n). | which embeds both device identifiers | — | none |
| DSM-HL-010/L679 | evidence | derived | The counterparty's signature is over canonical bytes that name the counterparty's device. | over canonical bytes that name Bob | — | none |
| DSM-HL-010/L687 | invariant | derived | A transition from one relationship presented as a step on another fails on parent adjacency, leaf key, consumption key, and signer, and any one mismatch is fatal. | Any one of these is fatal. | — | none |

### DSM-HL-011 — 11 Storage Nodes

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-011/L747.a | authority | derived | A storage node holds no key and signs nothing. | A storage node holds no key and signs nothing, ever. | — | none |
| DSM-HL-011/L747.b | authority | derived | A storage node never validates a protocol rule, evaluates a guard, computes a balance, refuses a value on protocol grounds, compares values, or decides transition validity. | It never validates a protocol rule, never evaluates | — | none |
| DSM-HL-011/L750 | invariant | derived | Economic and protocol payloads are opaque to the node apart from content addressing. | Economic and protocol payloads are opaque to it apart from | — | none |
| DSM-HL-011/L752 | prohibition | derived | The node does not vary acceptance by what a payload would parse as. | The node does not vary acceptance by what a payload would | — | none |
| DSM-HL-011/L754 | invariant | derived | No protocol-relevant node path reads a clock; ordering inside the node uses logical ticks. | protocol-relevant path reads a clock | — | none |
| DSM-HL-011/L755 | invariant | derived | Inter-node gossip is state synchronisation only: no leader election, Raft, Paxos, or vote. | Inter-node gossip exists, and it is state synchronisation only | — | none |
| DSM-HL-011/L758 | authority | explicit | A node may refuse a write addressed to an account that has not met the one-time spend-gate, and refuses nothing else and nothing on protocol grounds; whether nodes also refuse exhausted-credit writes is open. | Amendment A2 (owner, 2026-09-22) — payment is the one refusal. | — | none |
| DSM-HL-011/L760 | liveness-boundary | explicit | A party pays all five members of its set; a write goes through once the cell's leader and two others hold it, so the other members carry what one refuses. | Paying and getting through are separate. | — | none |
| DSM-HL-011/L761 | liveness-boundary | explicit | A member refusing a cell it leads stalls that cell until the party opts it out or the network cuts it; this never changes validity. | The one exception is a leader. | — | none |
| DSM-HL-011/L763 | obligation | explicit | Payment enforcement is keyed on the account the write is addressed to, never on who is writing. | Enforcement is keyed on the account the write is addressed to | — | none |
| DSM-HL-011/L764 | prohibition | explicit | Payment enforcement never applies to DLVs; creating a vault consumes its creator's credits like any write, and afterwards its storage never depends on anyone's payment. | It never applies to DLVs. | — | none |
| DSM-HL-011/L765 | invariant | explicit | Storage is paid on-chain with credits, charged by storage used at a fixed network price, counted in storage and never in time, and checked by the receiver like any debit; before acting, a client checks its own credit balance. | Storage is paid on-chain with credits. | — | none |
| DSM-HL-011/L772 | invariant | derived | An immutable object's address is H(DSM/storage-object ∥ N ∥ H(N ∥ P)), computed by the node from the input. | addr = H(DSM/storage-object | — | none |
| DSM-HL-011/L774 | obligation | derived | A caller-supplied address is checked and never used as the key. | A caller-supplied address is checked, never used as the | — | none |
| DSM-HL-011/L775 | invariant | derived | No update or overwrite path exists for immutable objects: the path is absent, not a path that refuses. | There is no update path and no overwrite path in the code | — | none |
| DSM-HL-011/L776 | obligation | derived | Identical bytes replayed are re-acknowledged; different bytes at the same address are reported as corruption. | Replaying identical bytes re-acknowledges | — | none |
| DSM-HL-011/L777.a | obligation | derived | On read, the node recomputes the address before serving. | On read the node recomputes the address before serving | — | none |
| DSM-HL-011/L777.b | evidence | derived | The client re-hashes every object it reads regardless of the node's check. | The client re-hashes anyway | — | none |
| DSM-HL-011/L780 | obligation | derived | The per-device tip mirror holds a public head and encrypted per-relationship leaves, keyed by device and relationship. | Per-device tip mirror. | — | none |
| DSM-HL-011/L784 | obligation | derived | The inbox spool delivers unilaterally to an offline counterparty. Envelopes are strictly versioned, ordered by insertion, acknowledged per routing key, and never opened by the node. | Inbox spool. | — | none |
| DSM-HL-011/L785 | prohibition | explicit | The node never opens a spool envelope and checks nothing about it. | The node never opens the envelope and checks nothing | — | none |
| DSM-HL-011/L788 | invariant | explicit | Nothing can be sent to a party that has not pre-added the sender; with no relationship there is nothing to address. | Amendment A3 (owner, 2026-09-22) — routing exists only through a pre-established contact | — | none |
| DSM-HL-011/L790 | invariant | explicit | A message is addressed to a relationship by its chain id (the hash of the two device ids), never to a genesis account. | A message goes to a relationship, never to a genesis account. | — | none |
| DSM-HL-011/L791 | obligation | explicit | The sender sends only over relationships it has pre-added; the recipient reads only relationships it has pre-added and accepts only messages signed by the other device of that relationship. | Both ends check. | — | none |
| DSM-HL-011/L792 | prohibition | explicit | The node never checks who is writing, not even whether the writer is one of the relationship's two devices. | The node does not check who is writing | — | none |
| DSM-HL-011/L795 | dependency-boundary | derived | Identity and recovery storage (genesis anchoring, device-tree indexing, recovery capsules as bytes under derived keys) is imported. Recovery is out of scope this round. | Identity and recovery. | — | none |
| DSM-HL-011/L798 | obligation | derived | Each cycle a node emits an unsigned ByteCommit: an SMT root over what it holds, linked to the previous cycle's digest, stored under a deterministic address, and mirrored by peers. | Each cycle a node emits an unsigned ByteCommit | — | none |
| DSM-HL-011/L800 | obligation | derived | Capacity is regulated against ByteCommit. An operator exits by proving two consecutive empty cycles. | an operator exits | — | none |
| DSM-HL-011/L801 | evidence | derived | Verifiers check the ByteCommit chain link and root themselves; the node's word is not evidence. | Verifiers check the chain link and the root themselves | — | none |
| DSM-HL-011/L808 | obligation | derived | A device may write only after paying a flat rate to K = 3 distinct operators. The node stores the receipts and counts distinct operators, and the device is then enabled permanently. This join event drives DJTE (emissions: out of scope). | A device may write only once it has paid a flat rate to K = 3 distinct operators | — | none |
| DSM-HL-011/L821 | invariant | derived | A cell's leader is the first member of a Fisher–Yates shuffle of the owner-committed storage set, seeded from committed state: for a device, genesis, id, position, and validated root; for a vault, vault id and parent root. | shuffle of the owner-committed | DSM-HL-009/L529 | none |
| DSM-HL-011/L823 | invariant | derived | Node ids, availability, and the caller's identity never enter a leader seed. | Node ids, availability and the caller | — | none |
| DSM-HL-011/L826 | obligation | derived | Any party may carry a cell's bytes to members not yet reached. | Any party may | — | none |
| DSM-HL-011/L829 | invariant | derived | Every member keeps everything it is given for a key, in arrival order. Nothing is refused, replaced, or compared, and there is no write authorization. | Every member keeps everything it is given for a key, in arrival order. | — | none |
| DSM-HL-011/L833 | invariant | derived | The winner at a cell is the first object naming it at the leader, final once the leader and two other members hold it. | The winner at a cell is the first object naming that cell at the leader. | DSM-HL-009/L544 | none |
| DSM-HL-011/L837 | evidence | derived | The verifier derives winner and finality from raw reads; no node evaluates them. | The verifier derives both facts from raw reads. | DSM-HL-009/L535 | none |
| DSM-HL-011/L843 | invariant | derived | Registration is not validation. A node stores an invalid claim as faithfully as a valid one, and whether the root is a valid transition is the verifier's question. | Registered is not validated. | — | none |
| DSM-HL-011/L847 | safety-assumption | derived | Restoring a member from a snapshot that predates a value it held is a safety violation, not an availability event. | predates a held value is a safety violation | — | none |
| DSM-HL-011/L849 | safety-assumption | derived | Immutable-object misresponses are detectable by hash and affect availability only. | Immutable-object misresponses are detectable by hash and affect availability only | — | none |
| DSM-HL-011/L850 | safety-assumption | derived | The safety-critical storage assumption is that a member never alters, reorders, or loses what it holds. | safety-critical assumption is that a member never alters, reorders or loses what it holds | DSM-HL-009/L619 | none |

### DSM-HL-012 — 12 Online DSM

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-012/L902 | invariant | derived | Online transition uniqueness does not depend on hardware. | Ordinary online DSM does not require hardware to determine transition uniqueness. | — | none |
| DSM-HL-012/L937 | transition | derived | Online verification order: decode → recompute hashes and roots → verify signatures → read sender's register cell at the next position (empty or exactly this root) → precommitment → guard → linearity → recompute successor → accept or reject locally, with no ordering service. | Read sender | — | figure |

### DSM-HL-013 — 13 DSM Is Not a Payment Channel

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-013/L996 | liveness-boundary | derived | A hostile counterparty can only decline to continue, and no third party continues on its behalf. This is a liveness failure and outside the safety theorem. | DSM classifies that as a liveness | — | none |
| DSM-HL-013/L1008 | invariant | derived | Safety does not depend on anyone broadcasting anything within a deadline: there are no timeouts, penalty transactions, or watchtowers. | Safety does not depend on anyone broadcasting anything in time. | — | none |

### DSM-HL-014 — 14 Determinism

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-014/L1036 | invariant | derived | Two conforming verifiers given identical canonical inputs (s, c, w) reach the identical verdict. | Then for identical canonical inputs | — | none |
| DSM-HL-014/L1040 | authority | derived | No storage node can make an invalid object valid. | No storage node gets to declare an invalid object valid. | — | none |
| DSM-HL-014/L1048 | obligation | derived | A conforming verifier reproduces every validity decision from the canonical inputs alone. | A conforming verifier should be able to reproduce the decision from the canonical inputs alone. | — | none |

### DSM-HL-014-1 — 14.1 Determinism Is Broader Than Arithmetic

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-014-1/L1053 | obligation | derived | Serialization, hashing, relationship identifiers, candidate digests, guard evaluation, resource descriptors, consumption keys, SMT updates, policy evaluation, successor construction and root recomputation are all deterministic. | DSM requires deterministic: | — | none |

### DSM-HL-015 — 15 Canonical Encoding

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-015/L1111 | invariant | derived | Every protocol object has one protocol-defined canonical byte encoding, and digests are taken over it. | DSM therefore requires canonical encoding. | — | none |
| DSM-HL-015/L1119 | obligation | explicit | Every correct implementation generates exactly the same bytes for the same object. | Every correct implementation must generate exactly the same bytes. | — | none |

### DSM-HL-015-1 — 15.1 Canonical Equality

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-015-1/L1127 | invariant | explicit | Protocol objects that are equal have equal encodings: x = y implies enc(x) = enc(y). | as protocol objects, then a canonical encoder must satisfy | — | none |
| DSM-HL-015-1/L1130 | invariant | derived | Two implementations that encode one logical state differently are implementing different protocol objects; neither may be accepted as the other. | If two implementations produce different encodings for the same logical state | — | none |

### DSM-HL-015-2 — 15.2 Why This Matters Everywhere

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-015-2/L1137 | obligation | derived | Canonical encoding governs signatures, hashes, state roots, relationship heads, candidate commitments, guards, SMT leaves, resource keys, policy and proofs. | Canonical encoding affects: | — | none |

### DSM-HL-016 — 16 Domain Separation

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-016/L1183 | obligation | derived | Every hash operation is domain-separated by the kind of object it hashes, so no raw field can be read as two object types. | They make semantically different hash operations live in cryptographically different namespaces. | — | none |

### DSM-HL-017 — 17 Cryptographic Hashes

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-017/L1202 | safety-assumption | derived | The hash function is collision resistant. | under the collision-resistance assumption | — | none |

### DSM-HL-018 — 18 Forward-Only Hash Chaining

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-018/L1217 | invariant | derived | Each successor state binds the hash of its predecessor. | A successor binds its predecessor: | — | none |
| DSM-HL-018/L1227 | invariant | derived | Changing any committed state breaks verification of every later state that bound it. | The chain no longer verifies. | — | none |

### DSM-HL-019 — 19 Bilateral Relationships

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-019/L1248 | invariant | derived | Each bilateral relationship is a distinct resource with its own forward-only chain. | Each relationship has its own forward-only chain. | — | none |
| DSM-HL-019/L1275 | invariant | derived | Advancing one relationship does not advance any other. | An update to one does not imply an update to the others. | — | none |

### DSM-HL-021 — 21 Relationship Projections

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-021/L1316 | invariant | derived | A transition involving relationship r must equal r's deterministic transition on r's projection and leave every unrelated projection unchanged. | This means that any valid DSM state transition involving a relationship must agree exactly with the | — | none |

### DSM-HL-022 — 22 Why Bilateral State Matters

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-022/L1346 | invariant | derived | The validity of a transition on A↔B is determined only by state relevant to A↔B plus any named shared resources or policy. | is determined from the state relevant to A | — | none |

### DSM-HL-023 — 23 Why a Device Needs a Compact Commitment

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-023/L1373 | obligation | derived | A device commits its relationship state with an authenticated tree (the Sparse Merkle Tree), so one relationship can be proved without the whole list. | DSM therefore uses authenticated tree commitments. | — | none |

### DSM-HL-025 — 25 Sparse Merkle Trees

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-025/L1434 | invariant | derived | The SMT has a fixed 256-bit key space in which empty subtrees have deterministic default hashes. | Empty subtrees have deterministic default hashes. | — | none |

### DSM-HL-026 — 26 Relationship Keys

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-026/L1468 | invariant | derived | A relationship's SMT key is H(DSM/smt-key/v1 ∥ min(DevID_A, DevID_B) ∥ max(DevID_A, DevID_B)), so it is the same from either side. | = H(DSM/smt-key/v1 | — | none |
| DSM-HL-026/L1472 | invariant | derived | A relationship's SMT leaf stores that relationship's current head. | The relationship leaf stores its current head: | — | none |

### DSM-HL-027 — 27 Updating One SMT Leaf

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-027/L1517 | invariant | derived | Advancing one relationship changes only its own leaf; every unrelated leaf is unchanged and the root changes. | All unrelated leaves remain unchanged. | — | none |

### DSM-HL-028 — 28 Merkle Proofs

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-028/L1557 | evidence | derived | A Merkle inclusion proof supplies the leaf and sibling hashes; the verifier recomputes the path, ordering each step by the path direction, and accepts only if the result equals the committed root. | The proof is valid if | — | none |
| DSM-HL-028/L1580 | invariant | derived | The logical proof path of a 256-bit SMT has depth 256; compressing default subtrees is an encoding choice that must not change the recomputed root. | In a 256-bit SMT, the logical proof path has depth 256 | — | none |

### DSM-HL-029 — 29 The DSM State Object

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-029/L1605 | invariant | derived | A DSM state is the tuple s = (R, u, P, Γ, Σ, Π, Ω, ρ), each component with a distinct function. | A complete abstract DSM state can be represented as: | — | none |
| DSM-HL-029/L1615 | invariant | derived | R maps each relationship identifier to that relationship's current authenticated head. | It records the current authenticated relationship head. | — | none |
| DSM-HL-029/L1618 | invariant | derived | u is the state's monotonic progression object (a sequence digest, progression coordinate, receipt frontier, or committed offline anchor counter, by mode). | The object u represents monotonic progression. | — | none |
| DSM-HL-029/L1631 | invariant | derived | P commits the currently permitted future candidates. | It commits the currently permitted future candidates. | — | none |
| DSM-HL-029/L1635 | invariant | derived | Γ associates each candidate branch with a deterministic fulfillment rule and a resource set. | It associates candidate branches with deterministic fulfillment rules and resource sets. | — | none |
| DSM-HL-029/L1642 | invariant | derived | Σ contains the resource-consumption keys already consumed in the realized lineage. | contains resource-consumption keys already consumed in the realized lineage. | — | none |
| DSM-HL-029/L1646 | invariant | derived | Π contains deterministic policy and authority data. | contains deterministic policy and authority data. | — | none |
| DSM-HL-029/L1650 | invariant | derived | Ω contains mode-specific evidence and may be empty in an ordinary online state. | contains mode-specific evidence. In an ordinary online state it may be empty. | — | none |
| DSM-HL-029/L1654 | invariant | derived | ρ is the canonical state root. | is the canonical state root. | — | none |

### DSM-HL-030 — 30 The Layered Root

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-030/L1663 | invariant | derived | The core root ρcore = SMT(R, u, Σ, Π, Ω) commits everything except the candidate space and guard family. | DSM avoids this using a core root. | — | none |
| DSM-HL-030/L1667 | invariant | derived | Candidates and guards bind ρcore, never the full root ρ. | Candidates and guards may safely bind: | — | none |
| DSM-HL-030/L1670 | invariant | derived | The full root is ρ = H(ρcore ∥ digest(P) ∥ digest(Γ)). | Then the full root is: | DSM-HL-004/L227 | none |
| DSM-HL-030/L1698 | invariant | derived | The commitment dependency graph (R, u, Σ, Π, Ω) → ρcore → (P, Γ) → ρ is acyclic. | The dependency graph is acyclic. | — | none |

### DSM-HL-031 — 31 Canonical State Chaining

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-031/L1718 | invariant | derived | A state successor means a valid deterministic derivation from the committed parent, never a position in a globally ordered history. | The successor is a valid deterministic transformation of the committed parent. | — | none |
| DSM-HL-031/L1731 | invariant | derived | Every state commits both its current facts and its permitted transition structure (P, Γ). | Every state commits both current facts and its permitted transition structure. | — | none |

### DSM-HL-032 — 32 Bitcoin Chain Versus DSM State Chain

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-032/L1751 | invariant | derived | The authenticated state and the derivation rule are sufficient for the transition-validity test; no global event history is consulted. | The authenticated state and derivation rule are themselves sufficient for the transition-validity test. | — | none |

### DSM-HL-033 — 33 Logical Generations

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-033/L1757 | invariant | derived | Generations are logical and ordered by derivability, never by wall-clock time. | A generation is not a wall-clock timestamp. | — | none |

### DSM-HL-034 — 34 Precommitment

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-034/L1769 | invariant | derived | A parent state commits its allowed candidate future space before any of those futures is realized. | Precommitment means the parent state commits its allowed candidate future space before one of those | — | none |

### DSM-HL-035 — 35 Candidate Structure

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-035/L1783 | invariant | derived | A candidate is (s_i, b_i, g_i, K_i, d_i): successor, branch identifier, guard descriptor, required resource-key set, and digest d_i = H(enc(s_i)). | A candidate may be written as: | — | none |
| DSM-HL-035/L1804 | invariant | derived | Every candidate is bound to its parent. | The candidate must be bound to the parent. | — | none |
| DSM-HL-035/L1805 | prohibition | derived | A future state that the parent never committed cannot be realized. | An arbitrary future state that was never committed cannot simply be inserted later. | — | none |

### DSM-HL-036 — 36 Candidate Forks Are Allowed

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-036/L1849 | invariant | derived | A parent may commit more than one candidate; candidate branching is not a double execution. | Candidate branching is not itself a double execution. | — | none |
| DSM-HL-036/L1854 | theorem | derived | A linear resource is consumed at most once in a valid realized lineage, however many candidates exist. | One linear resource may be consumed once in a valid realized lineage. | DSM-HL-001/L81 | none |

### DSM-HL-037 — 37 Precommitment Chaining

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-037/L1860 | invariant | derived | Precommitment is part of canonical state evolution, not temporary metadata. | It is part of canonical state evolution. | — | none |
| DSM-HL-037/L1884 | transition | derived | When a candidate in P_n realizes as s_{n+1}, s_{n+1} commits a new future space (P_{n+1}, Γ_{n+1}) and becomes the parent of the next step. | Each realized successor becomes the parent of the next precommitted future space. | — | none |
| DSM-HL-037/L1903 | transition | derived | The verifier's candidate check is whether the successor is one of the futures the parent committed. | Is this successor one of the futures already committed by the parent? | DSM-HL-005/L281 | none |

### DSM-HL-038 — 38 Guards

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-038/L1911 | transition | derived | A precommitted candidate realizes only if its deterministic guard evaluates True on the parent and the witness. | It must satisfy a deterministic guard. | — | none |
| DSM-HL-038/L1916 | evidence | derived | A witness may be a signature, a preimage, a completion certificate, a receipt, a recovery proof, or a mode-specific evidence bundle. | A witness may be: | — | none |
| DSM-HL-038/L1930 | obligation | derived | A guard binds the parent, the branch identifier, the required resource keys, the accepted witness type, the witness predicate, and the conflict class. | A guard should bind: | — | none |

### DSM-HL-039 — 39 Guard Families

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-039/L1951 | invariant | derived | A well-formed guard family verifies deterministically and binds correctly to its state and branch. | A well-formed guard family requires deterministic verification and correct binding to the state and | — | none |

### DSM-HL-040 — 40 Guards Alone Are Not the Exclusion Mechanism

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-040/L1984 | invariant | derived | Safety holds even when two conflicting guards are both satisfiable; it does not rely on guards being mutually exclusive. | The load-bearing mechanism is shared resource consumption. | — | none |
| DSM-HL-040/L1986 | invariant | derived | Conflicting branches derive the same authoritative linear-resource key. | Conflicting branches must contend for the same authoritative linear-resource key. | — | none |

### DSM-HL-041 — 41 Linear Resources

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-041/L2004 | invariant | derived | A linear resource is an object whose committed generation can produce at most one realized successor inside its conflict class. | A linear resource is an object whose committed generation can produce at most one realized successor | — | none |

### DSM-HL-042 — 42 Resource Descriptors

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-042/L2032 | invariant | derived | A resource descriptor is derived from committed state; for a relationship it is (relationship, k_A↔B, h_n). | The descriptor is derived from committed state. | DSM-HL-010/L672 | none |
| DSM-HL-042/L2033 | prohibition | derived | A branch cannot choose a different descriptor for the resource it consumes in order to evade conflict. | A branch is not free to invent a different descriptor merely to evade conflict. | — | none |

### DSM-HL-043 — 43 Resource-Consumption Keys

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-043/L2038 | invariant | derived | The authoritative consumption key is κres(s, x) = H(DSM/consume resource/v1 ∥ ρcore,s ∥ x). | DSM derives the authoritative consumption key as: | DSM-HL-004/L248 | none |
| DSM-HL-043/L2044 | theorem | derived | Two branches that consume the same resource from the same parent derive the same consumption key. | If two branches consume the same resource x, then both derive the same: | — | none |

### DSM-HL-044 — 44 Why Branch-Specific Exclusion Keys Would Be Wrong

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-044/L2099 | prohibition | derived | The exclusion key is derived from the resource, never from the branch that consumes it. | DSM therefore derives the exclusion key from the resource, not from the choice of conflicting branch. | — | none |
| DSM-HL-044/L2100 | invariant | derived | Branch-local identifiers may exist for audit or indexing but are never the authoritative exclusion mechanism. | Branch-local identifiers may still exist for audit or indexing, but they are not the authoritative | — | none |

### DSM-HL-045 — 45 Conflict Classes

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-045/L2112 | invariant | derived | The conflict class of K is the set of branches whose required key set contains K; only branches sharing linear state are excluded from one another. | Only branches sharing relevant linear state need exclusion. | — | none |

### DSM-HL-046 — 46 The Consumed Set

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-046/L2123 | transition | derived | A valid transition consuming K requires K ∉ Σ and produces Σ' = Σ ∪ {K}. | After a valid transition consuming K: | — | none |
| DSM-HL-046/L2129 | invariant | derived | Consumption is monotonic: Σ ⊆ Σ' across every realized transition, and no path removes a key. | Consumption is monotonic: | DSM-HL-004/L251 | none |

### DSM-HL-047 — 47 The Consumed Set Can Also Be an SMT

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-047/L2150 | evidence | derived | Σ may be an authenticated sparse map; a proof then shows K ∉ Σ before execution and K ∈ Σ' after it. | The consumed set may itself be represented as an authenticated sparse map. | — | none |

### DSM-HL-049 — 49 The Complete Realization Predicate

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-049/L2211 | transition | derived | A potential transition is realized only if CandidateOK ∧ GuardOK ∧ StructuralOK ∧ LinearityOK ∧ PolicyOK ∧ ModeOK holds. | becomes realized only if: | DSM-HL-005/L281 | none |

### DSM-HL-051 — 51 Realized Histories

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-051/L2242 | invariant | derived | In a realized history every edge is a valid realization, and the consumed set threads forward monotonically along it. | such that every edge is a valid DSM realization. | — | none |
| DSM-HL-051/L2247 | prohibition | derived | A branch is never evaluated against an old snapshot that ignores state created by earlier realized transitions. | A branch is not repeatedly evaluated against an old snapshot while ignoring the state created by | — | none |

### DSM-HL-052 — 52 The Core Uniqueness Theorem

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-052/L2258 | theorem | explicit | Theorem 1: two conflicting branches over the same committed linear resource cannot both consume its key as separate realized transitions in one valid history. | cannot both consume K as separate realized transitions in one valid DSM history. | DSM-HL-001/L81 | none |
| DSM-HL-052/L2297 | theorem | explicit | For selector families (a deterministic selector per conflict class), at most one candidate passes the predicate even against the untouched parent. | For these families the theorem holds statically | DSM-HL-008/L419 | none |
| DSM-HL-052/L2301 | theorem | explicit | For shared-key families, the first acceptance updates Σ and every later conflicting candidate fails linearity against the updated set. | the theorem holds in its realized-history form | — | none |
| DSM-HL-052/L2304 | proof-obligation | explicit | The realized-history form holds for every well-formed family and is machine-checked as an invariant. | and it is the form that is machine checked as an invariant (Section 81). | — | none |

### DSM-HL-053 — 53 Tripwire

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-053/L2346 | theorem | derived | Tripwire: conflicting same-resource branches may be constructed and transmitted, but cannot both be derived as realized state in one valid lineage. | conflicting same-resource branches cannot both be derived as realized state in one valid lineage. | — | none |

### DSM-HL-054 — 54 Safety and Liveness

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-054/L2374 | liveness-boundary | derived | Safety does not imply progress: a valid candidate may fail to realize through refusal, unavailable data, a missing witness, unreachable storage, unmet policy, or a missing offline proof. | DSM safety does not imply guaranteed progress. | — | none |

### DSM-HL-055 — 55 Concurrency Without Global Ordering

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-055/L2407 | invariant | derived | Transitions over disjoint resource sets, neither depending on state the other modifies, commute; no order between them is defined. | and neither transition depends on state modified by the other, then they may commute: | — | none |

### DSM-HL-056 — 56 Token Conservation

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-056/L2465 | invariant | derived | An ordinary transfer is zero-sum: the sender's decrease equals the receiver's increase. | So ordinary transfer is zero-sum. | — | none |

### DSM-HL-057 — 57 Why Conservation Is Not Enough

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-057/L2498 | invariant | derived | Conservation and linearity are both required; conservation alone permits one parent to fund two conflicting branches. | are both required. | — | none |

### DSM-HL-058 — 58 Deterministic Limbo Vaults

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-058/L2514 | invariant | derived | Every terminal branch of a vault generation (release, refund, recovery, abort) consumes the same resource, the generation itself, and so derives the same key. | But all terminal branches consume: | — | none |
| DSM-HL-058/L2542 | theorem | derived | Once one terminal branch consumes a vault generation, no other terminal branch can consume that generation in the same lineage. | another terminal branch cannot consume the same generation in that lineage. | DSM-HL-052/L2258 | none |

### DSM-HL-059 — 59 Smart Commitments

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-059/L2575 | invariant | derived | A smart commitment is a bounded deterministic predicate over committed inputs: a guard family attached to a precommitted candidate space over linear resources. There is no contract virtual machine. | A smart commitment is a bounded deterministic predicate over committed inputs: | — | none |
| DSM-HL-059/L2583 | invariant | derived | A smart commitment may use only checked integer arithmetic and comparison, Boolean composition, hashing and signature verification, SMT inclusion and non-inclusion, membership in committed bounded sets, and iteration with a cardinality fixed at commit time. | A smart commitment can use: | — | none |
| DSM-HL-059/L2597 | prohibition | derived | A smart commitment cannot use recursion, dynamic dispatch, or unbounded loops, and every predicate family declares a static evaluation budget. | It cannot use recursion, dynamic dispatch, or unbounded loops, and every predicate family declares a | — | none |
| DSM-HL-059/L2630 | invariant | derived | Where a contract would use time, a smart commitment uses an iteration budget that decrements only on accepted local steps; there are no clocks. | that decrements only on accepted local steps | — | none |
| DSM-HL-059/L2634 | invariant | derived | A commitment can reference only what was committed when it was created (candidate space, guards, external commitments by hash); there is no open-ended composition. | can only reference what was committed when it was created | — | none |
| DSM-HL-059/L2639 | invariant | derived | Every outcome of a commitment is bounded by its committed candidate space and static budget, so it can be enumerated before acceptance. | bounded by the committed candidate space and the static evaluation budget, so it can be enumerated | — | none |

### DSM-HL-060 — 60 Multi-Party Workflows Through External Commitments

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-060/L2673 | invariant | derived | An external commitment is Y = H(DSM/external/v1 ∥ X); DSM never executes X and verifies only equality, inclusion, signature or proof predicates bound to Y. | DSM never executes X. | — | none |
| DSM-HL-060/L2699 | liveness-boundary | derived | A party's refusal on one bilateral chain is a liveness failure on that chain only and cannot affect another chain bound to the same external commitment. | is a liveness failure on B | — | none |
| DSM-HL-060/L2710 | invariant | derived | Authority chooses which branch is eligible; it cannot make a parent be consumed more than once, even when every branch's witnesses are available. | authority chooses an eligible branch; it cannot multiply the consumed parent. | — | none |
| DSM-HL-060/L2729 | liveness-boundary | derived | Atomicity across separate bilateral legs is not automatic; each leg's precommitted refund or abort branch is the remedy, and all-or-none settlement uses the one-bundle mechanism of §63. | Atomicity across the bilateral legs is not automatic. | — | none |

### DSM-HL-061 — 61 CPTA and Deterministic Policy

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-061/L2743 | invariant | derived | Authority determines eligibility and never overrides single-consumption state: an authorized branch still requires K ∉ Σ. | authority determines eligibility; it does not override single-consumption state. | — | none |
| DSM-HL-061/L2756 | invariant | derived | An asset is bound to a committed policy that is a hash-committed input to every verifier that touches the asset; the policy is checked, not implemented. | The policy is a hash-committed input to every verifier that ever touches the asset. | — | none |
| DSM-HL-061/L2759 | invariant | derived | Validity is the intersection of the operation's rules and every asset's rules: a swap of A for B is valid only if the vault policy, both token policies, the reserve arithmetic and economic-root admission all hold. | A market swap of A for B is valid only if every | — | none |
| DSM-HL-061/L2763 | prohibition | derived | No operation, including wrapping or placing an asset in a vault, bypasses the asset's committed policy. | There is no operation that lets an application bypass a token | — | none |
| DSM-HL-061/L2778 | invariant | derived | The order is economic validity, then the exact write set, then economic-root admission, then the register; the register only detects equivocation and decides nothing about validity. | The register is the last step and only the last step. | — | none |
| DSM-HL-061/L2790 | invariant | derived | A vault's policy can only narrow what an asset's policy already permits. | can only narrow what | — | none |
| DSM-HL-061/L2817 | invariant | derived | A token policy states what makes a transfer of that token valid and does not by default enumerate trading pairs; pair restrictions are an optional capability. | It does not enumerate trading pairs. | — | none |

### DSM-HL-062 — 62 Deterministic Emissions (DJTE)

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-062/L2855 | dependency-boundary | derived | Emissions (DJTE) are imported and out of scope: all native units exist from genesis in a locked source vault under a CPTA policy, emission is a vault transition that only decreases the remaining supply, and it is triggered by the spend-gate's join proof. | Emission is a vault transition, not minting | — | none |
| DSM-HL-062/L2867 | invariant | derived | A native token has no minting path: its full supply is created once, at genesis. | A native token therefore has no minting | — | none |
| DSM-HL-062/L2875 | invariant | derived | External assets such as dBTC mint on admission and burn on withdrawal, and outstanding units never exceed what is provably locked on the backing chain. | External assets are the one exception, and they are logically different. | — | none |
| DSM-HL-062/L2955 | obligation | derived | A transition binds to the receiver's committed context (expected parent, index and policy anchors), so arbitrary bytes cannot form a valid candidate. | A transition must bind to a receiver | — | none |
| DSM-HL-062/L2957 | invariant | derived | A device processes objects only from relationships it has established. | Inboxes are contact-gated | DSM-HL-011/L788 | none |
| DSM-HL-062/L2959 | invariant | derived | A zero-effect transition is not a transition. | a zero-effect transition is not a transition | — | none |
| DSM-HL-062/L2962 | obligation | derived | Valid high-volume traffic against storage capacity is priced by prepaid credit bundles: each accepted sender-authored transition costs one credit, refills go through the spend-gate, and receiving never debits. | Receiving never debits, so a victim | — | tension(STOR-017/L422) |

### DSM-HL-063 — 63 Sovereign Finance (SoFi)

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-063/L2986 | invariant | derived | Funding a vault moves value from spendable balance into vault reserves; no second spendable copy exists. | There is no second spendable copy. | — | none |
| DSM-HL-063/L2993 | authority | derived | A vault's owner commits its market policy and release policy at creation and is bound by them like a trader; reserves leave only through a governed vault transition. | The owner cannot reach into | — | none |
| DSM-HL-063/L2999 | authority | derived | A funded vault is authority committed in advance, so an absent owner's reserves can move to a live trader who meets the committed conditions. | A funded vault is the authority, committed in advance. | DSM-HL-004/L207 | none |
| DSM-HL-063/L3027 | invariant | derived | Every vault parent has a successor cell whose leader is the first member of a deterministic shuffle of the vault's storage set seeded from the vault id and the parent root. | has a successor cell, and that cell has one leader | — | none |
| DSM-HL-063/L3029 | evidence | derived | An exercise binds by hash the trader's signed fulfilment, signed precommit, settlement preimage and policy witnesses. | its signed fulfilment, its signed precommit | — | none |
| DSM-HL-063/L3035.a | invariant | derived | The winner at a vault cell is the first exercise at the leader naming that cell, final once the leader and two others hold it; everything else at the cell counts as nothing. | Everything else at the cell counts as nothing. | — | none |
| DSM-HL-063/L3035.b | transition | derived | A losing attempt is dropped and never becomes state; the parent's next attempt key goes live and the loser rebuilds from the parent actually selected. | A losing attempt is dropped | — | none |
| DSM-HL-063/L3046 | invariant | derived | The cells of different vaults have different leaders and never wait for each other; there is no shared sequencer. | never wait for each other. | — | none |
| DSM-HL-063/L3052 | transition | derived | Winning a vault cell does not move reserves. Reserves move only when the trader's position resolves: fulfilment registered at its own position cell, conforming to the precommit, route valid against the exact parents named, and every leg final with a live attempt and a canonical parent. | Reaching the leader first settles who may consume the parent. | — | none |
| DSM-HL-063/L3057 | transition | derived | If any leg cannot resolve, the position is Void: no leg is consumed, nothing rolls back, and the trader's balance is untouched. | If any leg cannot resolve that way | — | none |
| DSM-HL-063/L3063 | liveness-boundary | derived | A trader who registers and walks away leaves nothing locked; any party can carry the remaining copies. | A trader who registers and walks away leaves nothing locked. | — | none |
| DSM-HL-063/L3070 | invariant | derived | A route drawing on several vaults binds all their parents in one settlement bundle and executes fully or not at all; the vaults stay independently owned. | it executes fully or not at all. | — | none |
| DSM-HL-063/L3074 | invariant | derived | Allocation and pricing are checked integer arithmetic, so two conforming SDKs given the same vault states produce byte-identical routes. | produce byte-identical routes | — | none |
| DSM-HL-063/L3078 | invariant | derived | Visibility of a settlement bundle to its storage set grants no priority. | visibility grants no priority. | — | none |
| DSM-HL-063/L3080 | invariant | derived | Perpetual funding is denominated in trade activity, liquidation is a branch precommitted at open, and reference prices are co-signed windows over verified trade digests, never an oracle feed as authority. | Funding is denominated in trade activity rather than elapsed time | — | none |
| DSM-HL-063/L3084 | invariant | derived | No timestamp, height or duration appears in any SoFi validity rule. | No timestamp, height, or duration appears in any validity rule. | — | none |
| DSM-HL-063/L3100 | invariant | derived | A vault's storage set is owner-chosen. | owner-chosen storage set | — | tension(STOR-010/L214) |
| DSM-HL-063/L3103 | liveness-boundary | derived | A market trade is online: it needs the vault's storage set reachable, and SoFi does not inherit the offline-bearer path. | so SoFi does not inherit DSM | — | none |
| DSM-HL-063/L3107 | authority | explicit | A vault's storage set is the network's pinned set, assigned and never chosen by any owner, liquidity provider or trader. | Amendment A5 (owner, 2026-09-22) — a vault's storage set is assigned, never chosen. | STOR-010/L214 | none |

### DSM-HL-064 — 64 dBTC: Bitcoin as a DSM Asset

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-064/L3123 | invariant | derived | Each depositor's lock is its own tap: no shared operator, key, decision or failure between taps. | There is no shared operator, no shared key, no shared decision | — | none |
| DSM-HL-064/L3130 | invariant | derived | Value from any external system enters DSM the same way: each lock into it is a sovereign tap, and nothing is bridged. | It is how value from any external system enters DSM | — | none |
| DSM-HL-064/L3201 | authority | derived | Economic authority is ownership of live dBTC state in a device root; execution authority is the narrowly scoped Bitcoin material for one authorised withdrawal; the two are never conflated. | Economic authority is ownership of live dBTC state in a device root | — | none |
| DSM-HL-064/L3209 | invariant | derived | Knowledge of vault identifiers, lineage, receipts, ciphertext, public keys, the fulfilment hash or storage records is not ownership and produces no withdrawal. | None of that is ownership and none of it produces a withdrawal | — | none |
| DSM-HL-064/L3215 | transition | derived | At origin the admitting device verifies the Bitcoin transaction, its inclusion, script, amount, network and profile confirmation depth; exactly that quantity enters as dBTC bound to its origin lineage, and the depositor has no continuing role. | Exactly that quantity enters DSM as dBTC | — | none |
| DSM-HL-064/L3222 | transition | derived | A dBTC transfer is an ordinary DSM economic transition carrying nothing Bitcoin-specific; there is no second double-spend system. | dBTC adds no second | — | none |
| DSM-HL-064/L3225 | transition | derived | Withdrawal: the holder commits an exact intent W; live dBTC is consumed in a burn bound to it; the completion evidence σ derives skVn = H(DSM/dlv-unlock ∥ Ln ∥ Cn ∥ σ), which opens a capsule that signs exactly the committed Tn. | The holder constructs an exact intent W | — | none |
| DSM-HL-064/L3238 | invariant | derived | The burn precedes the Bitcoin secret, which is a consequence of the burn's evidence; the hash equality is the last check and never independently sufficient. | The hash equality is the last check, not the first, and it is never independently sufficient. | — | none |
| DSM-HL-064/L3278 | invariant | derived | Withdrawability is conjunctive: live state, state authority, a valid burn, valid completion, and the preimage. | Withdrawable = LiveState | — | none |
| DSM-HL-064/L3290 | invariant | derived | In a partial withdrawal the spent parent is terminal and the successor holds the remainder in the same origin lineage; parent and successor are never both live backing. | The spent parent is terminal | — | none |
| DSM-HL-064/L3291 | prohibition | derived | A successor below the vault profile's floor is refused by the burn predicate as a DSM transition. | the floor is fixed in the vault profile and enforced by the burn predicate | — | none |
| DSM-HL-064/L3293 | prohibition | derived | The remainder is never trimmed into fee. | The remainder is never trimmed into fee | — | none |
| DSM-HL-064/L3302 | authority | derived | A storage node holding dBTC material decides nothing: not ownership, not a burn, not a key, not an exit, not a successor. | It decides nothing: it does not determine who owns dBTC | STOR-002/L75 | none |
| DSM-HL-064/L3317 | dependency-boundary | derived | Offline movement of dBTC uses the offline-bearer machinery, which is out of scope this round. | A bearer asset that moves offline, in any amount | — | none |
| DSM-HL-064/L3321 | liveness-boundary | derived | Withdrawal is online and inherits Bitcoin's settlement assumptions, including the profile's confirmation depth; no claim is made that a deeper reorganisation is impossible. | Withdrawal is online by design | — | none |

### DSM-HL-065 — 65 Recovery as a Linear Generation

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-065/L3343 | dependency-boundary | derived | Recovery is out of scope; imported property: all terminal alternatives of a recovery generation consume one key, so a generation cannot terminate two conflicting ways. | The same recovery generation cannot terminate a second conflicting way. | — | none |

### DSM-HL-066 — 66 Offline Bearer DSM

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-066/L3362 | dependency-boundary | derived | Offline bearer DSM is out of scope this round. Imported boundary: software linearity answers whether an offline transition is unique; hardware identity evidence answers whether it came from the intended device; the two questions are kept separate. | DSM keeps these questions separate. | — | none |

### DSM-HL-073 — 73 Conflict-Local Finality as a State Property

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-073/L3643 | invariant | derived | Finality means the consumed resource cannot produce another conflicting realized successor in the same valid lineage; it does not mean global observation. | The consumed committed resource cannot produce another conflicting realized successor inside | — | none |

### DSM-HL-076 — 76 Why Every Piece Is Necessary

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-076/L3848 | theorem | derived | The kernel's guarantee requires all of canonical encoding, determinism, bilateral hash chains, SMT authentication, precommitment, guards, canonical resource derivation, shared consumption keys and monotonic consumed state; within one valid realized lineage no linear resource is consumed twice. | within one valid realized lineage, no linear resource is consumed twice. | — | none |
| DSM-HL-076/L3850 | invariant | derived | Protecting two counterparties who never communicate from a stale root requires the economic-root register on top of the kernel. | requires one more piece on top of the kernel | DSM-HL-009/L530 | none |

### DSM-HL-078 — 78 Produced and Discarded, or Never Producible

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-078/L3893 | invariant | derived | The realization predicate is the only way a state comes into existence; a transition that breaks a rule is never produced. | The realization predicate of Part II is the | — | none |
| DSM-HL-078/L3897 | obligation | derived | No implementation path may create state while skipping any step of the realization predicate; the guarantee is exactly as strong as the predicate being the only door. | bug that lets a step be skipped breaks it. Once no step can be skipped, it holds. | — | none |
| DSM-HL-078/L3935 | invariant | derived | Where ordering is not semantically required, DSM does not invent one; where it is, it is encoded as state. | Where ordering is not semantically required, DSM does not invent one. | DSM-HL-006/L328 | none |

### DSM-HL-080 — 80 Security Assumptions

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-080/L3988 | safety-assumption | explicit | The hash function is collision resistant. | 1. cryptographic hash collision resistance; | DSM-HL-017/L1202 | none |
| DSM-HL-080/L3989 | safety-assumption | explicit | Signatures are unforgeable. | 2. signature unforgeability; | — | none |
| DSM-HL-080/L3990 | safety-assumption | explicit | Canonical serialization is implemented correctly. | 3. canonical serialization correctness; | — | none |
| DSM-HL-080/L3991 | safety-assumption | explicit | Relationship keys are derived correctly. | 4. correct relationship-key derivation; | — | none |
| DSM-HL-080/L3992 | safety-assumption | explicit | Resource descriptors are derived correctly. | 5. correct resource-descriptor derivation; | — | none |
| DSM-HL-080/L3993 | safety-assumption | explicit | Conflicting branches derive the same authoritative resource key. | 6. conflicting branches deriving the same authoritative resource key; | — | none |
| DSM-HL-080/L3994 | safety-assumption | explicit | SMT proofs are verified correctly. | 7. correct SMT proof verification; | — | none |
| DSM-HL-080/L3995 | safety-assumption | explicit | Consumed-state updates are correct and monotonic. | 8. correct monotonic consumed-state updates; | — | none |
| DSM-HL-080/L3996 | safety-assumption | explicit | The deterministic transition predicate is implemented faithfully. | 9. faithful implementation of the deterministic transition predicate; | — | none |
| DSM-HL-080/L3997 | dependency-boundary | explicit | Offline physical claims rest on the security of the fused hardware and measurement boundary (offline: out of scope). | 10. for offline physical claims, security of the relevant fused hardware and measurement boundary; | — | none |
| DSM-HL-080/L3998 | safety-assumption | explicit | Durable member memory: a storage member never alters, reorders or loses what it holds for a key, across restart, restoration and storage migration. | 11. durable member memory: a storage member never alters, reorders or loses what it holds for a | STOR-003/L94 | none |
| DSM-HL-080/L4001 | safety-assumption | explicit | Writer and verifier compute a cell's leader from the owner-committed member set and committed state only; no availability view, node id or caller choice moves a cell. | 12. leader derivation: the writer and the verifier compute a cell | STOR-011-1/L256 | none |
| DSM-HL-080/L4004 | liveness-boundary | explicit | Failing to reach a cell's leader, or two other members, is a liveness failure and the cell waits; violating durable member memory is a safety failure. | Failure to reach a cell | — | none |
| DSM-HL-080/L4008 | obligation | explicit | The concrete primitives are post-quantum: BLAKE3 for hashing, SPHINCS+ for signatures, Kyber for key encapsulation. | The concrete primitives behind the first two assumptions are post-quantum: BLAKE3 for hashing, | — | none |

### DSM-HL-081 — 81 Formal Verification

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-081/L4036 | proof-obligation | explicit | Key-scoped uniqueness and Tripwire are proved in Lean 4 over an abstract guarded model, with no axioms in the uniqueness and Tripwire core. | The uniqueness and Tripwire core depends on no axioms. | DSM-HL-052/L2304 | none |
| DSM-HL-081/L4045 | proof-obligation | explicit | A TLA+ model checks that a deliberately malformed family (different keys for one shared resource) violates uniqueness, showing guard-family well-formedness is load-bearing. | a deliberately malformed family, in which conflicting branches are given different keys for a shared | — | none |
| DSM-HL-081/L4049 | proof-obligation | explicit | A TLA+ relationship-scoped model confirms same-parent multi-receiver forks are unconstructible in online DSM. | a relationship-scoped model, in which keys embed the relationship identity and each relationship | — | none |
| DSM-HL-081/L4053 | proof-obligation | explicit | A TLA+ storage-cell model checks that a value is final only if the leader holds it, at most one value is final per cell, the leader depends only on the seed and committed set, and non-objects never occupy, finalize or consume a cell; each property has a failing companion configuration. | a storage-cell model, in which members keep every value in arrival order and one leader per cell is | — | none |
| DSM-HL-081/L4060 | proof-obligation | explicit | A Lean module proves that for arbitrary adversary bytes, constructible implies recognized implies valid, with seven mutation controls and a non-vacuity witness. | for arbitrary bytes from an adversary, constructible implies | — | none |
| DSM-HL-081/L4074 | obligation | explicit | Resource-key derivation and descriptor injectivity, not covered by the models, are discharged by the derived-keys-only rule and the implementation enforcement skeleton. | those are discharged by the derived-keys-only rule | — | none |
| DSM-HL-081/L4085 | obligation | explicit | A production implementation must faithfully refine the abstract model; conformance testing and the enforcement skeleton tie the code to it. | A production implementation must faithfully refine the abstract model. | — | none |

### DSM-HL-082 — 82 One Mathematical Picture of DSM

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-082/L4129 | transition | derived | A step computes ρcore, selects a candidate from P, verifies its guard, derives descriptor and key, checks K ∉ Σ, applies the transformation, adds K to Σ, updates u, Π and Ω, recomputes ρcore, commits the next P and Γ, and recomputes ρ. | Apply the named state transformation: | DSM-HL-049/L2211 | none |

### DSM-HL-085 — 85 The Core DSM Statement

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-085/L4273 | invariant | derived | Applications with shared public resources use one keyed cell per resource, with one leader derived from committed state, where the first object to arrive counts; this gives exclusivity without a universal order. | with genuinely shared public resources use one keyed cell per resource | — | none |

### SOFI-PREAMBLE — Read this first: if it exists, it is valid

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-PREAMBLE/L42 | invariant | explicit | A state change that breaks a rule cannot be made; it never comes into existence, so anything that exists is valid and nothing else has to check it. | A state change that breaks a rule cannot be made. | DSM-HL-004/L187 | none |
| SOFI-PREAMBLE/L47 | authority | explicit | A storage node holds no key and signs nothing; the client signs its own transitions and everything else is bound by hashed preimages. | A storage node holds no key and signs nothing, ever. | DSM-HL-011/L747 | none |
| SOFI-PREAMBLE/L52 | invariant | explicit | No node attests who got there first; attempts that lose are dropped and never become states, and the canonical chain is the only order. | Attempts that lose are dropped and never become states, so there is nothing to order; | — | none |
| SOFI-PREAMBLE/L56 | prohibition | explicit | No storage node receives a key, signature, certificate or attestation role; no ordering problem between attempts is invented; no rule depends on which node returned something. | Giving a storage node a key of any kind | — | none |
| SOFI-PREAMBLE/L116 | invariant | derived | The next state is a fixed function of the parent, the operation, and entropy derived from the parent; no clock, no outside randomness, no other party's choice. | The next state is produced by a fixed function of three things | — | none |
| SOFI-PREAMBLE/L121 | authority | derived | A transition is signed by its owner over its exact bytes, so only the owner can extend the owner's history. | A transition is signed by its owner over its | — | none |
| SOFI-PREAMBLE/L164 | invariant | derived | Signing is deterministic, so one body has exactly one valid envelope. | so one body has exactly one valid envelope | — | none |
| SOFI-PREAMBLE/L165 | invariant | derived | Every object carries its lineage (parent claim, position, pre-roots, parent roots), so it cannot attach to another parent or position or be replayed later. | attaching to another parent or position; replay later | — | none |
| SOFI-PREAMBLE/L166 | invariant | derived | Every key is computed from fields the object itself carries, so an object never counts at a key it does not name. | counting at a key the object does not name | — | none |
| SOFI-PREAMBLE/L167 | invariant | derived | Consumption keys derive from the parent, each parent has one constructor, and each witness is a function of its inputs, so there are no alternative witnesses or successors. | alternative witnesses, alternative successors, choice | — | none |
| SOFI-PREAMBLE/L168 | invariant | derived | E, each witness Gj and F bind every leg, amount, core, witness and outcome of an operation, so none can be swapped. | swapping any leg, amount, core, witness or outcome | — | none |
| SOFI-PREAMBLE/L169 | invariant | derived | The vault state commits its market, fee and release policies by content address, and a token's identity is the hash of its whole policy. | trading under other rules, or against another token | — | none |
| SOFI-PREAMBLE/L170 | evidence | derived | Every object proves itself: core entries carry all 256 siblings against their pre-roots, hop amounts are recomputed from committed reserves and the fee policy, and realize_root and void_root are fixed in P. | hop amounts are recomputed from committed reserves and the fee policy | — | none |
| SOFI-PREAMBLE/L171 | prohibition | derived | No free input: entropy comes from the parent, no clock, no outside randomness, one canonical encoding and one tag per object type, checked arithmetic. | entropy from the parent; no clock; no outside randomness | — | none |
| SOFI-PREAMBLE/L180 | invariant | derived | The position cells cannot disagree: Cq is computed from F and P, so a claim that does not match is not F's claim. | Because Cq is computed | — | none |
| SOFI-PREAMBLE/L187 | invariant | derived | No key is ever dead: a key is open until an object that names it reaches its leader. | No key is ever dead. | — | none |
| SOFI-PREAMBLE/L196 | obligation | explicit | The constructor is the only door: one transition function in Core makes every state, and nothing else creates, repairs, completes or adjusts one. | The constructor is the only door. | DSM-HL-078/L3893 | none |
| SOFI-PREAMBLE/L198 | obligation | explicit | Every input comes from committed state and passes through Core; no state is built from values another layer computed, and no evidence is defaulted or filled in. | Every input comes from committed state and passes through Core. | — | none |
| SOFI-PREAMBLE/L200 | obligation | explicit | Everything is deterministic and canonical: one encoding per object, domain-separated hashes, no clock, no outside randomness, checked arithmetic. | Everything is deterministic and canonical. | — | none |
| SOFI-PREAMBLE/L202 | obligation | explicit | Every module on the path is used, and every piece of evidence is consumed by the constructor. | Every module on the path is used, and every piece of evidence is consumed by the constructor | — | none |
| SOFI-PREAMBLE/L207 | prohibition | explicit | Nothing downstream (SDK, storage, app) checks what construction guarantees; a validity check outside the constructor is forbidden and means the constructor has a hole to close in Core. | Adding a validity check anywhere outside the constructor. | — | none |
| SOFI-PREAMBLE/L247 | proof-obligation | derived | Because nothing outside committed state enters validity, every reachable state of a bounded model can be enumerated and every safety property checked in all of them. | reachable state of the protocol can be enumerated and every safety property checked | — | none |
| SOFI-PREAMBLE/L268 | invariant | explicit | If it exists, it is valid; if it is not valid, it does not exist. | If it exists, it is valid. If it is not valid, it does not exist. | — | none |

### SOFI-001-4 — 1.4 Notation

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-001-4/L315 | invariant | explicit | H(tag; x) = BLAKE3(tag ∥ 0x00 ∥ x), and every SoFi tag starts with DSM/sofi/. | Every SoFi tag starts with | — | none |
| SOFI-001-4/L316 | invariant | explicit | Concatenated parts are fixed width or a single canonical encoding, so no length prefixes are added. | so no length prefixes are added | — | none |
| SOFI-001-4/L318 | invariant | explicit | CCB is the canonical binary encoding by class number; two distinct well-formed objects never share an encoding. | Two distinct well-formed objects never share an encoding. | DSM-HL-015-1/L1127 | none |
| SOFI-001-4/L320 | invariant | explicit | A trader's next position is q = p + 1 with checked arithmetic. | q = p + 1 with checked arithmetic | — | none |

### SOFI-001-5 — 1.5 Three valued predicates

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-001-5/L335 | transition | explicit | A conjunction of predicates is Invalid if any conjunct is Invalid; it is Valid only when every conjunct is Valid; while a conjunct's evidence is still being fetched it is undecided (as read under Amendment S3). | Any conjunct Invalid gives Invalid. | DSM-HL-005/L281 | none |
| SOFI-001-5/L338 | invariant | explicit | Core predicates are binary and evaluated only over evidence in hand; Unavailable is the network layer's report that it is still fetching, never a predicate value, and nothing is marked Invalid while it is still retried. | Amendment S3 (owner, 2026-09-22) — Unavailable is not a predicate value. | DSM-HL-005/L295 | none |
| SOFI-001-5/L340 | transition | explicit | Core first evaluates every conjunct decidable from evidence in hand; if any is Invalid the conjunction is Invalid and the network layer is never asked; only an operation nothing in hand shows Invalid goes on to fetch the rest. | Core first evaluates every conjunct it can decide from evidence already in hand. | — | none |
| SOFI-001-5/L342 | liveness-boundary | explicit | Evidence obtained from the network can make the conjunction Invalid; when fetching ends without the evidence, which for a trader position happens only through the challenge rule, the position resolves Void. | Evidence obtained from the network is evaluated like any other and can make the conjunction Invalid. | STOR-009-1/L193 | none |

### SOFI-002 — 2 The layer rule

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-002/L356 | invariant | explicit | There are no validators: a transition is admissible only by satisfying the complete deterministic predicate that constructs it. | There are no validators. | — | none |
| SOFI-002/L357 | authority | explicit | Storage does not establish validity; it preserves already-established artifacts and enforces only generic storage mechanics. | Storage does not establish validity. | — | none |

### SOFI-002-1 — 2.1 Who owns what

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-002-1/L366 | prohibition | derived | Core SoFi never reads a storage verdict as a truth value. | Never reads a storage verdict as a truth value. | — | none |
| SOFI-002-1/L367 | prohibition | derived | The Core state machine never names a SoFi type. | Never names a SoFi type. | — | none |
| SOFI-002-1/L368 | prohibition | derived | The SDK adapter only packages a result Core accepted: it never validates a second time, computes a second root, or supplies its own entropy. | Never validates a second time, never computes a second root, never supplies its own entropy. | — | none |
| SOFI-002-1/L369 | prohibition | derived | The storage node holds and returns bytes and never checks, interprets or decides anything. | Never checks, interprets or decides anything. | DSM-HL-011/L747 | none |

### SOFI-002-2 — 2.2 The storage question

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-002-2/L386 | obligation | derived | Every addition asks whether storage needs to know what it means; if so, it is in the wrong layer. | Every addition to the implementation answers one question before it is written | — | none |

### SOFI-002-3 — 2.3 Distinct facts

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-002-3/L391 | prohibition | explicit | StorageFinal, StorageReachable, Canonical, Consumed, TraderRealized and the other listed facts are distinct; code that treats one as another is wrong. | Code that treats one as another is wrong. | — | none |
| SOFI-002-3/L405 | invariant | derived | A trader precommit P is noneconomic: publishing or storing it is never exercise, and abandoning it has no effect. | Noneconomic: publishing or storing it is never exercise, and abandoning it has no effect. | — | none |
| SOFI-002-3/L406 | invariant | derived | A policy fulfillment witness Gj is a noneconomic deterministic witness: never consent, approval, acceptance or a lock, and it has no issuer. | It is never consent, approval, acceptance or a lock. It has no issuer. | — | none |
| SOFI-002-3/L408 | invariant | derived | FulfillmentRegistered(F) (F final at its fulfillment coordinate) is the one irreversible exercise boundary. | The one irreversible exercise boundary. | — | none |
| SOFI-002-3/L409 | invariant | derived | StorageFinalE(K, E) is a storage fact only and implies nothing about exercise, conformance or consumption. | A storage fact only: it implies nothing about exercise, conformance or consumption. | — | none |

### SOFI-003 — 3 How value moves

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-003/L417 | invariant | derived | Relationships are bilateral and online movement is unilateral: the sender advances its own state and delivers to the recipient's storage nodes, and the recipient applies it on its own schedule. | Relationships are bilateral. Movement online is unilateral. | — | none |
| SOFI-003/L423 | invariant | derived | Nobody approves anything at trade time; the owner is not asked and no other party is consulted. | Nobody approves anything at | — | none |
| SOFI-003/L426 | transition | explicit | A trader unlocks a DLV by carrying, in its own transition, evidence that the vault's committed criteria are met; Core checks it deterministically, the trader's state advances, and the vault's committed successor follows from the same operation. | A trader unlocks a DLV by carrying, in its own transition, the evidence that the vault | — | none |
| SOFI-003/L428 | authority | explicit | No party other than the trader signs a trade. | No party other than the trader signs. | — | none |

### SOFI-004 — 4 What SoFi settles

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-004/L436 | invariant | derived | SoFi settles five operations, all online: vault creation, setup, trade, route and close. | SoFi settles five operations, all online. | — | none |
| SOFI-004/L439 | invariant | derived | A multihop route is one operation with one external commitment E binding every hop; either every hop is consumed or none is, and each hop lands at its own vault's cell under that vault's leader. | either every hop is consumed or none is | — | none |

### SOFI-005-1 — 5.1 Storage nodes

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-005-1/L449.a | safety-assumption | explicit | A storage node may crash and omit messages. | A storage node may crash and may omit messages. | — | none |
| SOFI-005-1/L449.b | safety-assumption | explicit | A storage node never equivocates, never alters content it holds, and never permanently loses stored bytes. | It never equivocates, never alters content it holds | STOR-003/L94 | none |
| SOFI-005-1/L450 | obligation | explicit | A store that falls outside the fault model fails closed. | A store that falls outside this model fails closed. | — | none |

### SOFI-005-2 — 5.2 Traders and other callers

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-005-2/L459 | safety-assumption | derived | Traders and other callers are arbitrary; nothing in the safety argument assumes a well-behaved caller. | Nothing in the safety argument assumes a well behaved caller. | — | none |

### SOFI-005-3 — 5.3 Safety and liveness

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-005-3/L463 | invariant | derived | Safety is deterministic and assumes none of the liveness conditions. | Safety is deterministic and assumes none of the liveness conditions below. | — | none |
| SOFI-005-3/L465 | liveness-boundary | derived | Liveness assumes the evidence needed for validation eventually becomes available. | the evidence needed for validation eventually becomes available; | — | none |
| SOFI-005-3/L466 | liveness-boundary | derived | Liveness assumes the storage nodes needed for finality, in particular the leader, are eventually reachable and messages eventually delivered. | the storage nodes needed for finality are eventually reachable and messages are eventually delivered | — | none |
| SOFI-005-3/L468 | liveness-boundary | derived | Liveness assumes an enabled, conforming completion write has a fair chance to reach some live attempt coordinate, recursively for any predecessor position. | an enabled, conforming completion write has a fair chance to reach some live attempt coordinate; | — | none |
| SOFI-005-3/L470 | liveness-boundary | derived | No liveness is claimed against an adversary who wins every future write forever. | No liveness is claimed against an adversary who wins every future write forever. | — | none |
| SOFI-005-3/L471 | liveness-boundary | explicit | If required evidence never appears, a registered fulfillment may stay Pending forever. | a registered fulfillment MAY stay Pending forever. | — | none |

### SOFI-005-4 — 5.4 Boundaries that remain

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-005-4/L477 | safety-assumption | derived | An identity can split its own registers (self split); the consequence falls on that identity. | An identity can split its own registers (self split). | — | none |
| SOFI-005-4/L478 | liveness-boundary | derived | A registered route with a leg that cannot be written stays unresolved until that leg's vault acts. | A registered route with a leg that cannot be written stays unresolved until that leg | — | none |
| SOFI-005-4/L479 | liveness-boundary | derived | A position may stay Pending after its DLV keys become skippable. | A position may stay Pending after its DLV keys become skippable. | — | none |
| SOFI-005-4/L480 | liveness-boundary | derived | A fulfillment may resolve Void under contention; policy fulfillment witnesses do not lock parents, and there is no prepare lock. | A fulfillment may resolve Void under contention. | — | none |

### SOFI-005-5 — 5.5 Checked arithmetic

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-005-5/L486 | invariant | explicit | Position, attempt index and vault generation use checked arithmetic; overflow is an error, never a wrap. | Overflow is an error | — | none |

### SOFI-006 — 6 The committed set

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-006/L506 | invariant | explicit | Every vault commits its storage set in its own state: five member ids sorted by raw bytes; an offline member is still in the set. | Every vault commits its storage set in its own state. | — | none |
| SOFI-006/L508 | invariant | explicit | The set is identified by storage_set_id, which covers member ids only and never endpoints. | storage_set_id, which covers the member ids only, never endpoints | STOR-011/L230 | none |
| SOFI-006/L527 | invariant | derived | Membership of a vault's committed set is frozen; replacement changes only the operator serving a seat. | Membership is frozen per vault. | STOR-011/L232 | none |

### SOFI-007 — 7 The leader of a cell

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-007/L538 | authority | explicit | The writer and Core compute a cell's leader; a storage node never does and does not know which cells it leads. | The writer and Core compute the leader. | STOR-009/L167 | none |
| SOFI-007/L539 | invariant | explicit | Availability, the caller's identity and node ids never enter a leader seed. | Availability, the caller | — | none |

### SOFI-007-1 — 7.1 The shuffle

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-007-1/L546 | invariant | explicit | The shuffle sorts S ascending by raw bytes and refuses a duplicate member id. | Sort S ascending by raw bytes. A duplicate member id is refused. | — | none |
| SOFI-007-1/L550 | invariant | explicit | Each draw uses rejection sampling over H(fy-prf/v1; s ∥ i ∥ ctr) so it is unbiased. | The rejection makes the draw | — | none |
| SOFI-007-1/L552 | invariant | explicit | The draw counter is 32 bits; exhausting it is a defined error, never a wrap. | Exhausting it is a defined error, never a wrap. | — | none |
| SOFI-007-1/L553 | invariant | explicit | The leader is position 0 of the shuffle result. | The leader is position 0 of the result. | — | none |

### SOFI-007-2 — 7.2 The two SoFi seeds

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-007-2/L561 | invariant | explicit | Vault successor cells of vault v at parent Rn use the seed sv = H(storage-seed/v4; v ∥ Rn) for every attempt key. | K(a) for every attempt a | — | none |
| SOFI-007-2/L567 | invariant | explicit | A trader position q uses the seed H(DSM/economic/position-seed/v1; G ∥ DevID ∥ q ∥ Rp), with Rp the validated economic root at p or the genesis root at the first position. | where Rp is the validated economic root at p, or the genesis root when q is the first position. | — | none |

### SOFI-008 — 8 Writing a cell

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-008/L598 | obligation | explicit | The writer computes K and its leader. | Compute K and its leader. | — | none |
| SOFI-008/L600 | invariant | explicit | The winner at K is the first object at the leader that names K. | at K is the first object at the leader that names K | DSM-HL-009/L544 | none |
| SOFI-008/L601 | obligation | explicit | The writer writes the same bytes to the other members of S. | Write the same bytes x to the other members of S. | — | none |
| SOFI-008/L602 | invariant | explicit | Once the leader and two other members hold x, the value is final at K. | Once the leader and two other members hold x, the value is final at K. | — | none |
| SOFI-008/L603 | obligation | explicit | Any party may carry the bytes to members not yet reached. | Any party MAY carry the bytes to them. | — | none |
| SOFI-008/L610 | evidence | explicit | Core evaluates finality from raw reads; no node evaluates it. | Core evaluates this from raw reads. No node evaluates it. | — | none |
| SOFI-008/L612 | invariant | explicit | A value the leader does not hold is never final. | A value the leader does not hold is never final. | — | none |
| SOFI-008/L613 | invariant | explicit | At most one value is final at a cell. | At most one value is final at a cell. | — | none |
| SOFI-008/L615 | evidence | explicit | A verifier may classify a loss from the leader's cell alone. | A verifier MAY classify the loss from the leader | — | none |
| SOFI-008/L616 | liveness-boundary | explicit | If the leader is unreachable the cell waits for it; no other member stands in. | If the leader is unreachable, the cell waits for it. | — | none |
| SOFI-008/L620 | prohibition | explicit | No member refuses, replaces or compares anything held at a key. | No member refuses, replaces or compares anything. | — | tension(DSM-HL-011/L758) |

### SOFI-009 — 9 Who may write

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-009/L631 | authority | explicit | Anyone may write; there is no write authorization because every object carries its own authority. | Anyone. There is no write authorization | — | none |
| SOFI-009/L633 | obligation | explicit | A trader's two position cells, Kful(q) and Kroot(q), are written together at their leader. | are written together at their leader. | — | none |

### SOFI-010 — 10 Content addressed objects

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-010/L644 | invariant | explicit | Protocol identities such as PrecommitId are recomputed by Core from the bytes and are never storage addresses. | they are never storage addresses | — | none |
| SOFI-010/L646 | invariant | explicit | Stored(o) holds when three members of S return the exact bytes of o. | Stored(o) holds when three members of S return the exact bytes of o. | — | none |

### SOFI-011 — 11 Indexes

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-011/L656 | obligation | explicit | Anyone may append the content address of an object the member already holds under any locator; appends are never removed and are read back in append order. | Anyone MAY append the content address | — | none |
| SOFI-011/L659 | liveness-boundary | explicit | An index scan that exceeds its budget is Unavailable, never Invalid; Core recomputes each candidate's identity and keeps the one that verifies. | is Unavailable, never Invalid. | — | none |

### SOFI-012 — 12 Everything a member does

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-012/L679 | obligation | explicit | Put at a key stores the bytes a writer sends after anything already held there. | Store the bytes a writer sends for a key, after anything already held there. | — | none |
| SOFI-012/L681 | obligation | explicit | Get returns everything held at the key in arrival order, or that it holds none, and the member signs nothing. | Return everything held at the key, in the order it arrived, or that it holds none. | — | none |

### SOFI-013 — 13 How Core reads storage

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-013/L689 | evidence | explicit | Core turns raw member reads into exactly three storage facts (LeaderHeld, Final, Stored) and uses nothing else from storage. | Core turns raw member reads into three storage facts and uses nothing else from storage. | — | none |
| SOFI-013/L704 | evidence | explicit | Core derives FulfillmentRegistered, EconomicRootRegistered, SetupRegistered and StorageFinalE from the three storage facts. | Core derives the SoFi facts from them: | — | none |

### SOFI-014-1 — 14.1 Domain tags

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-014-1/L718 | invariant | derived | Every SoFi domain tag string is exactly as listed in the registry. | The string is exact | — | none |
| SOFI-014-1/L760 | prohibition | derived | Reserved tags (membership-handover, trade-digest, ref-window) are never used for anything else. | Reserved, never used for anything else | — | none |
| SOFI-014-1/L771 | prohibition | derived | A retired tag (route-outcome/v2) is never reused. | Retired, never reused | — | none |

### SOFI-014-2 — 14.2 Object classes

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-014-2/L777 | invariant | derived | A CCB class number is never reassigned. | A class number is never reassigned. | — | none |
| SOFI-014-2/L794 | prohibition | derived | Class numbers 0x0043 to 0x0049 are burned and never assigned to any object. | never assigned to any object | — | none |
| SOFI-014-2/L808 | invariant | derived | The successor owner-authority class exists only to be refused. | owner authority, successor (always refused) | — | none |

### SOFI-014-3 — 14.3 Signed objects

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-014-3/L822 | invariant | derived | Identities are computed over the canonical body bytes, never the envelope, so a second valid signature over one body is the same object. | Identities are always computed over the canonical body bytes, never over the envelope | — | none |
| SOFI-014-3/L824 | invariant | derived | Signing is deterministic (SPHINCS+ randomizer H(sk_prf ∥ m)), so at most one valid envelope exists per body. | at most one valid envelope exists per body | — | none |

### SOFI-015 — 15 Derivations

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-015/L831 | invariant | derived | A vault id is v = H(vault-id/v1; Go ∥ DevIDo ∥ u64be(pcreate)). | H(vault-id/v1; Go | — | none |
| SOFI-015/L844 | invariant | derived | The trader–vault relationship chain starts at h0 = H(rel-genesis/v1; σ) and advances as h_{j+1} = H(rel-leaf/v1; h_j ∥ E). | H(rel-leaf/v1; hj | — | none |
| SOFI-015/L859 | invariant | derived | A trader's fulfillment key is Kful(q) = H(fulfillment/v1; G ∥ DevID ∥ u64be(q)). | H(fulfillment/v1; G | — | none |
| SOFI-015/L860 | invariant | derived | The resolution claim is Cq = (G, DevID, q, FulfillmentId, Rrealize, Rvoid). | FulfillmentId, Rrealize | — | none |
| SOFI-015/L861 | invariant | derived | A trader's root register key is Kroot(q) = H(DSM/trader-economic-root-register-key/v1; G ∥ DevID ∥ u64be(q)). | H(DSM/trader-economic-root-register-key/v1; G | — | none |
| SOFI-015/L863 | invariant | derived | The first successor key of vault v at parent Rn is K(0) = H(succ-cell/v2; v ∥ Rn). | H(succ-cell/v2; v | — | none |
| SOFI-015/L864 | invariant | derived | Later attempt keys are K(a) = H(succ-attempt/v1; K(0) ∥ u64be(a)) for a > 0. | H(succ-attempt/v1; | — | none |
| SOFI-015/L869 | invariant | derived | A single-leg E is H(atomic-ext/v4; v ∥ Rn ∥ ρ ∥ cT ∥ cV ∥ b ∥ Xroute). | H(atomic-ext/v4; v | — | none |
| SOFI-015/L871 | invariant | derived | A multi-leg E is H(atomic-ext/multivault/v5; cT ∥ b ∥ Xroute ∥ H(Γ)). | H(atomic-ext/multivault/v5; | — | none |
| SOFI-015/L882 | invariant | derived | No attempt index, availability view, routing order, member identity or witness enters E. | No attempt index, availability view, routing order, member identity or witness enters E. | — | none |

### SOFI-016 — 16 Setup

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-016/L886 | obligation | derived | A trader sets up once per vault before its first operation against that vault. | A trader sets up once per vault before its first operation against that vault. | — | none |
| SOFI-016/L904 | invariant | derived | Equality of setups is equality of ρ; alternative envelopes over one body are the same setup. | Equality of setups is equality of | — | none |
| SOFI-016/L911 | transition | explicit | Accepting E requires both SetupValid (semantic, decided by Core) and SetupRegistered (durability, derived from storage reads); storage establishes neither. | Accept(E) requires both. Storage establishes neither. | — | none |
| SOFI-016/L915 | invariant | explicit | SetupRegistered holds when three members of S return the exact bytes of the setup body. | three members of S return its exact bytes (Section 13). | — | none |
| SOFI-016/L919 | transition | explicit | On the first relationship-gated operation both sides prove the trader leaf h0 and the DLV-side non-inclusion and become h1; on every later operation both sides advance by H(rel-leaf/v1; h_j ∥ E). | On the first relationship gated DLV operation | — | none |

### SOFI-017 — 17 The operation

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-017/L927 | authority | derived | A route is one unilateral trader operation: the trader signs P and F, nothing else signs anything, and each Gj has no issuer. | The trader signs P and F and nothing else signs anything. | — | none |
| SOFI-017/L937 | invariant | explicit | The hash dependency order is exact registered parent claim → closure index → B → E → P → G1..Gn → F → Cq; nothing depends back on E, and E depends on no attempt index. | E, and E does not depend on any attempt index. | — | none |

### SOFI-017-1 — 17.1 Stage 1: the trader precommit P

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-017-1/L969 | invariant | derived | P occupies no economic position: it installs nothing at Kroot, many precommits may exist from one parent, and publishing or storing it is never exercise. | P occupies no economic position | SOFI-002-3/L405 | none |
| SOFI-017-1/L974 | obligation | explicit | Before publication, P's G, DevID and p equal those of the trader core. | G, DevID and p equal those of T | — | none |
| SOFI-017-1/L975 | obligation | explicit | P's parent claim reference resolves to the exact registered predecessor claim at p that Core has accepted, matching the typed parent reference in the closure index. | ParentClaimRef resolves to the exact registered predecessor claim at p that Core has accepted | — | none |
| SOFI-017-1/L977 | prohibition | explicit | One member's copy of a register cell is never the source of truth. | copy of a register cell is never the source of truth. | — | none |
| SOFI-017-1/L978 | obligation | explicit | An unresolved conditional position has selected no root and is not a predecessor; the trader core's pre-root equals the one root its parent selected. | An unresolved conditional position has selected no root and is not a predecessor. | — | none |
| SOFI-017-1/L982 | obligation | explicit | E recomputes from the settlement preimage P(E). | E recomputes from P | — | none |
| SOFI-017-1/L983 | obligation | explicit | P's legs equal those derived from P(E) and Γ. | The legs equal those derived from P | — | none |
| SOFI-017-1/L984 | obligation | explicit | Rrealize and Rvoid recompute. | Rrealize and Rvoid recompute. | — | none |
| SOFI-017-1/L985 | obligation | explicit | P's storage_set_id equals the committed set S. | storage_set_id equals S. | — | none |
| SOFI-017-1/L986 | obligation | explicit | The signing key binds to the parent claim. | The key binds to the parent claim. | — | none |
| SOFI-017-1/L989 | prohibition | explicit | Core must not construct, sign, publish, fulfill, register or admit a child of an unresolved conditional position. | Core MUST NOT construct, sign, publish, fulfill, register or admit a child of an unresolved conditional position. | — | none |

### SOFI-017-2 — 17.2 Stage 2: policy fulfillment Gj

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-017-2/L1018 | invariant | derived | There is exactly one policy fulfillment per (P, E, vault, exact parent, exact shadow), so each PolicyFulfillmentIdj is a deterministic function of leg j of P. | There is exactly one policy fulfillment per (P, E, vault, exact parent, exact shadow) | — | none |
| SOFI-017-2/L1021 | invariant | derived | Gj is not a transition and not a lock: the DLV parent it names stays consumable by other operations. | not a transition and not a lock | — | none |
| SOFI-017-2/L1024 | authority | explicit | Gj has no issuer signature; its authority is deterministic validation against the exact DLV parent named by P and that parent's committed policy. | Gj has no issuer signature. | — | none |
| SOFI-017-2/L1025 | invariant | explicit | Whether Gj's parent is canonical or live is decided by consumption, never by static validation; hash binding establishes integrity, not issuer authentication. | Whether that parent is canonical or live belongs to | — | none |
| SOFI-017-2/L1030 | invariant | derived | Proof material never enters PolicyFulfillmentId; E-dependent material is referenced by content address as auxiliary candidates, with no single slot anyone could fill first with junk, and Core accepts whichever candidate verifies. | Proof material never enters PolicyFulfillmentId. | — | none |
| SOFI-017-2/L1036 | evidence | explicit | A verifying auxiliary candidate establishes that one validity step holds. | A verifying candidate establishes that one validity step holds. | — | none |
| SOFI-017-2/L1037 | liveness-boundary | explicit | No candidate, or only non-verifying candidates, leaves the step undecided (Unavailable), never Invalid. | No candidate, or only nonverifying candidates, gives Unavailable, never Invalid. | — | none |
| SOFI-017-2/L1038 | invariant | explicit | Only a class with one uniquely derived canonical encoding can establish a negative result. | Only a class with one uniquely derived canonical encoding can establish a negative result | — | none |
| SOFI-017-2/L1041 | liveness-boundary | explicit | Per-class candidate budgets and local byte, memory and work budgets bound hostile input; they are computational, and exhausting one leaves the step undecided, never Invalid. | Both are computational, never semantic | — | none |
| SOFI-017-2/L1043 | invariant | explicit | Non-verifying candidates never count toward the normative fetch bound; only verifying objects used by validation do. | Nonverifying candidates never count toward the normative fetch bound | — | none |

### SOFI-017-3 — 17.3 Stage 3: the trader fulfillment F

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-017-3/L1075 | invariant | derived | F carries the precommit id, the canonical policy fulfillment set, the attempts fixed at exercise time against keys live then, and position q = P.p + 1; it restates no field of P. | F restates no field of P | — | none |

### SOFI-017-4 — 17.4 Fulfillment ingress

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-017-4/L1082 | obligation | explicit | Any caller may relay F; the writer puts F at Kful(q) and Cq at Kroot(q) in one local transaction at the leader of s(q), both or neither, then puts the same bytes on the other members. | in one local transaction | — | none |
| SOFI-017-4/L1084 | authority | explicit | The member stores bytes and establishes nothing about F or the route; only Core establishes conformance. | it establishes nothing about the conformance of F or the route | — | none |
| SOFI-017-4/L1085 | invariant | explicit | Because Cq is computed from F and P, no claim that disagrees with F can be F's claim. | Because Cq is | — | none |
| SOFI-017-4/L1093 | invariant | explicit | FulfillmentRegistered(F) holds iff Final(Kful(q), F) and Final(Kroot(q), Cq); Core concludes it from raw reads, and no member computes it or writes a registration record. | It is a conclusion Core draws from raw | — | none |
| SOFI-017-4/L1095 | invariant | explicit | At most one fulfillment is registered per position q. | at most one fulfillment is registered per position q | — | none |

### SOFI-017-5 — 17.5 The exercise

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-017-5/L1100 | invariant | explicit | The value written to each successor key of a route is the exercise: one canonical object carrying the signed F, the signed P, P(E), every Gj in leg order, and every closure object. | that carries everything needed to judge it. | — | none |
| SOFI-017-5/L1111 | invariant | explicit | At successor key K(a) of vault v at parent Rn, the value that counts is the first exercise at the leader whose F names (v, a) in attempts and whose P names (v, Rn) in legs; everything else at K counts as nothing. | At a successor key K = K (a) of vault v at parent Rn | DSM-HL-063/L3035 | none |

### SOFI-018-1 — 18.1 The preimage

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-018-1/L1134 | invariant | derived | P(E) is SettlementPreimage{settlement, trader_core, dlv_cores} with a strict decoder. | with a strict decoder | — | none |
| SOFI-018-1/L1152 | prohibition | derived | P and every Gj contain E, so neither can appear in the pre-E closure; the classes of B, T, V and P(E) are forbidden inside it. | are forbidden | — | none |

### SOFI-018-2 — 18.2 Inputs after E

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-018-2/L1158 | invariant | derived | P (by PrecommitId), the policy fulfillment set, auxiliary evidence, F and Cq are inputs to validation and are never committed by E. | These are inputs to validation and are never committed by E | — | none |

### SOFI-018-3 — 18.3 Choosing the form of E

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-018-3/L1165 | invariant | explicit | A single-leg Swap and every Close use the single-leg form of E (atomic-ext/v4); a Swap with two or more legs uses the route form (atomic-ext/multivault/v5). | A Swap with one leg and every Close use the single leg form | — | none |
| SOFI-018-3/L1166 | transition | explicit | BindExt inserts the external commitment and h_{j+1} into the relationship posts. | BindExt inserts the external commitment | — | none |

### SOFI-018-4 — 18.4 Bounds

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-018-4/L1171 | invariant | explicit | A known bound violation is Invalid, never Unavailable: closure references 64, canonical bytes per object 256 KiB, signed envelopes 16, aggregate unique fetch 4 MiB, provenance fanout 16, P(E) 256 KiB. | A known bound violation is Invalid, never Unavailable. | — | none |

### SOFI-019-1 — 19.1 Leaves

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-019-1/L1195 | invariant | derived | The vault state leaf carries owner genesis, owner device, create position, market, fee and release policies, storage_set_id, generation, both reserves and status; Active means both reserves positive. | owner_genesis | — | none |
| SOFI-019-1/L1197 | invariant | derived | A setup inserts exactly one trader relationship leaf, with no prior value and h0 = H(rel-genesis/v1; σ); only resolution advances it. | A setup inserts exactly one, with no prior value | — | none |
| SOFI-019-1/L1202 | invariant | derived | The whole input of a trade, fee included, stays in reserve_in; there is no add-liquidity operation (an owner closes and creates again). | There is no add liquidity operation: | — | none |

### SOFI-019-2 — 19.2 Cores and the batch fold

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-019-2/L1210 | invariant | derived | Every core entry path carries all 256 siblings, and one batch fold computes the post root; a single batch is required. | Every path carries all 256 siblings. | — | none |

### SOFI-019-3 — 19.3 Closed write sets

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-019-3/L1217 | prohibition | explicit | No write-set entry outside the closed Swap and Close sets is permitted. | No entry outside these sets is permitted in either branch. | — | none |
| SOFI-019-3/L1220 | transition | explicit | Swap: the trader core debits token_in, credits token_out and advances one relationship per leg; each vault core goes Active to Active with priced reserves, generation plus one, and one relationship advance. | debit token_in, credit token_out, one relationship advance per leg | — | none |
| SOFI-019-3/L1224 | transition | explicit | Close: the trader is credited reserve_a and reserve_b with no debit; the vault goes Active with exactly the committed reserves to Retired with both zero and generation plus one. | Active with exactly the committed reserves to Retired with both reserves zero and generation plus | — | none |

### SOFI-019-4 — 19.4 Route digest and leg rules

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-019-4/L1234 | invariant | explicit | The canonical codec, decoder and recompute_e accept any number of legs (one upward for Swap), bounded only by the object byte bound. | The canonical codec, decoder and recompute_e accept any number of legs | — | none |
| SOFI-019-4/L1237 | prohibition | explicit | The route cap of two legs is admission and builder policy only and never appears in a canonical constructor or decoder. | It never appears in a canonical constructor or decoder. | — | none |
| SOFI-019-4/L1239 | invariant | explicit | Vault ids within one route are pairwise distinct: each DLV parent is referenced at most once. | Vault ids within one route are pairwise distinct | — | none |

### SOFI-019-5 — 19.5 Static economics

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-019-5/L1246 | invariant | derived | Swap economics: per leg, amount_out equals the constant-product output with checked reserve updates; hops chain; endpoints match; write sets hold; every token passes its policy; per-token conservation holds; any overflow is static Invalid. | overflow is static Invalid. | — | none |
| SOFI-019-5/L1252 | invariant | derived | Close economics: no pricing; the vault goes to Retired with exactly the committed reserves, the trader credits equal them, conservation holds, the release policy is OWNER_LOCAL_FULL_CLOSE, owner authority holds, and both tokens' policies hold. | No constant product pricing applies. | — | none |
| SOFI-019-5/L1259 | invariant | explicit | A static Valid creates no canonical or spendable credit: output becomes canonical only when the position resolves Realized and advance_resolved installs Rrealize; Void installs the previous root. | It creates no canonical | — | none |
| SOFI-019-5/L1261 | prohibition | explicit | No new credit-source arm exists for SoFi, and a validated peer debit refuses a SoFi position. | creates no credit. No new credit source | — | none |

### SOFI-019-6 — 19.6 Advancing the lineage

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-019-6/L1266 | transition | derived | advance_resolved is the only constructor of a validated economic root at q for a SoFi position: it checks q = p + 1, recomputes Cq from P and F (never reading it from a register), checks the parent claim, Rvoid and Rrealize, and T.pre_root at advance; Realized installs Rrealize, Void the previous root, Invalid is terminal. | is the only constructor of a validated economic root at q for a SoFi | — | none |

### SOFI-019-7 — 19.7 Close authority

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-019-7/L1275 | authority | derived | A Close is authorized iff P's G and DevID equal the vault owner's, P and F are signed under the key proven for that identity at p, that identity holds its own setup and relationship with the vault, and the release policy is OWNER_LOCAL_FULL_CLOSE; a recovered owner closes through Origin. | A Close is authorized if and only if | — | none |
| SOFI-019-7/L1280 | prohibition | explicit | The DsmSuccessor owner authority is always refused by semantic validation as Invalid; no builder or producer emits it, and vault_id never changes. | DsmSuccessor decodes and encodes canonically and is always refused by semantic validation as Invalid | — | none |

### SOFI-019-8 — 19.8 Vault genesis

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-019-8/L1285 | transition | derived | Vault creation is the owner's ordinary transition at pcreate, which debits the funding and inserts a VaultCreation leaf (insert only). | The owner’s ordinary transition at pcreate debits the funding | — | none |
| SOFI-019-8/L1291 | invariant | explicit | Genesis is accepted only if R0 recomputes, the initial state is generation zero, Active, with no relationship leaves, reserves equal the funding, v derives from the inserting position, token_a < token_b, the storage set is the network's pinned set, and the owner's root at p is validated. | All of the following hold: R0 recomputes | STOR-010/L214 | none |
| SOFI-019-8/L1294 | invariant | explicit | GenesisStored is only a storage fact. | GenesisStored is only a storage fact. | — | none |
| SOFI-019-8/L1296 | invariant | explicit | An owner may trade against its own vault with no special case, and the fee stays in the reserves. | An owner MAY trade against its own vault | — | none |

### SOFI-020 — 20 Validation predicates

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-020/L1302 | invariant | derived | Two Core predicates, RouteValidation and FulfillmentConformance, decide semantic validity and are evaluated independently (their "three valued" form read under Amendment S3). | Two Core predicates decide semantic validity. | SOFI-001-5/L338 | none |

### SOFI-020-1 — 20.1 RouteValidation

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-020-1/L1317 | transition | explicit | RouteValidation is the conjunction over legs of PolicyFulfillmentValid, with TraderSideValid and RouteWideValid; it covers each leg's SetupValid, policy fulfillment, arithmetic and reserves, exact branch effects, conservation, relationship correspondence, network scope, exact shadows, the trader core against the validated parent, P's signature and key binding, and witness canonicality. | under the three valued conjunction of Section 1.5. | — | none |
| SOFI-020-1/L1319 | invariant | explicit | Whether a leg's DLV parent is canonical or live is not checked by RouteValidation. | Whether Rj is canonical or live is not checked here. | — | none |
| SOFI-020-1/L1327 | invariant | explicit | RouteValidation is static: it never depends on attempt indices, storage finality, canonicality, attempt liveness or any outcome; a known bound violation is Invalid. | RouteValidation never depends on attempt indices, storage finality, canonicality, attempt liveness or any out- | — | none |

### SOFI-020-2 — 20.2 FulfillmentConformance

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-020-2/L1344 | transition | explicit | FulfillmentConformance(F) is Valid only when every item holds, Invalid when any is known false, and undecided while needed evidence is still being fetched. | FulfillmentConformance(F ) is Valid when every item below holds | — | none |
| SOFI-020-2/L1346 | obligation | explicit | Conformance item: the exact referenced P is available and verifies, and q = P.p + 1 with checked arithmetic. | the exact referenced P is available and verifies | — | none |
| SOFI-020-2/L1347 | obligation | explicit | Conformance item: F is signed and its key equals the key P committed. | F is signed, and its key equals the key P committed; | — | none |
| SOFI-020-2/L1349 | obligation | explicit | Conformance item: the policy fulfillment set is complete and canonical; a subset, an extra entry or an id not derived from P is malformed. | a subset, an extra entry or an id not derived from P is malformed; | — | none |
| SOFI-020-2/L1350 | obligation | explicit | Conformance item: the attempts cover exactly the legs of P with no numeric holes. | the attempts cover exactly the legs of P , with no numeric holes; | — | none |
| SOFI-020-2/L1351 | obligation | explicit | Conformance item: for every attempt a > 0, the earlier attempt key has a permanent storage resolution. | the earlier attempt K (aj −1) has a permanent storage resolution; | — | none |
| SOFI-020-2/L1352 | obligation | explicit | Conformance item: SetupRegistered holds for every leg. | SetupRegistered holds for every leg (Section 13); | — | none |
| SOFI-020-2/L1353 | obligation | explicit | Conformance items: identities and bounds hold, and the exact P(E) and pre-E closure are available and verify. | identities and bounds hold; | — | none |
| SOFI-020-2/L1357 | invariant | explicit | Registration supplies no truth value for conformance; a registered F injected by an arbitrary caller may be Invalid. | Registration supplies no truth value for this predicate. | — | none |
| SOFI-020-2/L1358 | obligation | explicit | A producer must obtain Valid conformance before it publishes F. | A producer MUST obtain Valid before it publishes F . | — | none |

### SOFI-021 — 21 Exercise and atomicity

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-021/L1371 | invariant | explicit | FulfillmentRegistered(F) is the exercise; publishing P or any policy fulfillment witness is not. After registration the trader has no remaining discretion, and any caller may relay F, publish closure objects and write E into the reserved successor keys. | is the exercise. Publishing P is not | — | none |
| SOFI-021/L1375 | prohibition | explicit | Nothing stores a route outcome; Core derives completion or permanent defeat from the leg reads. | No outcome register. | — | none |
| SOFI-021/L1377 | invariant | explicit | Occupancy is not admissibility: a value in a successor cell carries no economic authority by being stored, and a storage node cannot gate on F. | Occupancy is not admissibility. | — | none |
| SOFI-021/L1379 | invariant | explicit | A route is realized only by the all-leg predicate; if any required leg cannot resolve to E the position is Void and no leg is consumed. F is an irreversible attempt, never a guarantee. | A route is realized only by the all leg predicate of Section 23. | — | none |
| SOFI-021/L1381 | prohibition | explicit | There is no prepare lock: witnesses do not lock parents, and success after F is never claimed. | No prepare lock. | — | none |

### SOFI-021-1 — 21.1 Registration and realizability are separate

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-021-1/L1385 | invariant | derived | P, G and F are realizable only while the trader parent has not been consumed by an incompatible trader transition and every named DLV parent remains available to E; a fulfillment may register after losing a parent and can then never be realized. | are realizable only while the trader parent | — | none |
| SOFI-021-1/L1390 | transition | explicit | If either predicate is Invalid the position is Invalid; otherwise, while either is undecided, it is Pending; only when both are Valid and the route is permanently defeated is it Void. No route becomes Void while its conformance is unknown. | If either predicate is Invalid, the position is Invalid. | — | none |
| SOFI-021-1/L1393 | invariant | explicit | Registration establishes only that bytes are held at the fulfillment coordinate; two fulfillments from one parent compete at the same leader and at most one registers. | Registration establishes only that bytes are held at the fulfillment coordinate. | — | none |
| SOFI-021-1/L1400 | invariant | explicit | StorageFinalE and FulfillmentRegistered are independent; ConsumedRoute requires both, and storage finality never manufactures exercise. | storage finality never manufactures exercise | — | none |

### SOFI-022 — 22 The predecessor rule

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-022/L1405 | transition | derived | A child needs an exact selected predecessor root: Realized selects Rrealize, Void selects Rvoid; Pending and Invalid select none and permit no child. | A child needs an exact selected predecessor root. | — | none |
| SOFI-022/L1415 | invariant | derived | At most one fulfillment per lineage is unresolved in storage at a time; StorageResolved is internal to resolution and never a predecessor authority. | At most one fulfillment per lineage is unresolved in storage at a time. | — | none |
| SOFI-022/L1419 | obligation | explicit | Core blocks any descendant economic root while a conditional predecessor is unresolved for the verifier (the local fence). | Core blocks any descendant economic root while a conditional predecessor is unresolved for the verifier. | — | none |

### SOFI-023-1 — 23.1 Successor resolution

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-023-1/L1437 | evidence | explicit | Core derives SuccessorResolution(K) from raw reads as Unresolved or Final(x) for an exercise x; LeaderHeld settles early that no other value will be final at K, and a cache never establishes it. | A cache never | — | none |
| SOFI-023-1/L1438 | invariant | explicit | For a > 0, the attempt key K(a) is usable only once K(a−1) is skipped. | is usable only once K (a−1) is skipped. | — | none |

### SOFI-023-2 — 23.2 Consumed route

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-023-2/L1442 | invariant | derived | AttemptLive(v, R, a) holds iff every earlier attempt key is skipped. | AttemptLive(v, R, a) | — | none |
| SOFI-023-2/L1453 | invariant | explicit | ConsumedRoute(F, E) holds iff F is registered, conformance and route validation are Valid, the trader parent is compatible, and every leg has a canonical parent, a live attempt and E final at its key; route completion is exactly this conjunction, with no separate outcome. | Route completion is exactly the conjunction over the legs | — | none |

### SOFI-023-3 — 23.3 Trader parent compatibility

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-023-3/L1464 | invariant | derived | TraderParentCompatible and TraderParentImpossible are objective and monotone; while the trader's parent position is Pending both are false, so that parent neither consumes nor skips anything. | Both are objective and monotone. | — | none |

### SOFI-023-4 — 23.4 Routes with more than one leg

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-023-4/L1473 | invariant | derived | A multi-leg operation is Realized only when every required leg satisfies the conjunction; if a required parent becomes permanently incompatible it resolves Void once storage has resolved and RouteValidation is Valid, and its stranded cells are skipped with nothing rolled back. | The whole operation is Realized when every | — | none |

### SOFI-023-5 — 23.5 Impossibility and skips

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-023-5/L1484 | invariant | explicit | FulfillmentImpossible holds iff conformance is Invalid or the route is impossible; a step still waiting on evidence is never a ground for impossibility. | Unavailable is never a ground for impossibility; it waits. | — | none |
| SOFI-023-5/L1487 | invariant | explicit | RouteImpossible(P, E) holds when RouteValidation is Invalid, a named parent is permanently orphaned, a named parent is consumed by a different E, or the trader parent is impossible. | It holds when any arm holds: | — | none |
| SOFI-023-5/L1499 | invariant | explicit | Arms (ii) to (iv) need no validation evidence, so a stranded cell of an impossible operation is skippable even while other evidence is outstanding; arm (iv) creates no Void. | Arms (ii) to (iv) need no validation evidence | — | none |
| SOFI-023-5/L1508 | invariant | explicit | A key is Skipped when E is final there, the fulfillment is impossible, and (for a single leg) the parent is canonical and the attempt live. | RejectedFinalSingleLeg ∨ RejectedFinalRoute | — | none |

### SOFI-023-6 — 23.6 The walk

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-023-6/L1516 | transition | derived | For one DLV parent the walk visits K(0), K(1), … in order: a skipped key moves on, a consumed key stops the walk, anything else is unresolved. | a skipped key moves to the next attempt, a consumed key | — | none |
| SOFI-023-6/L1518 | invariant | derived | The walk is budgeted; running it in chunks gives the same result as running it at once. | running it in chunks gives the same result as running it at once | — | none |
| SOFI-023-6/L1523 | invariant | derived | A parent is orphaned once its canonical successor at g + 1 resolves to something else; storage reachability of the objects needed to rebuild a tuple is required for P's legs, F's legs and every cell. | is orphaned once its canonical successor at g + 1 resolves to something else | — | none |

### SOFI-024 — 24 Resolution of a trader position

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-024/L1529.a | invariant | explicit | Resolution is local to the verifier, deterministic, and permanent once not Pending; the first matching rung of the ladder decides. | Resolution is local to the verifier, deterministic, and permanent once it is not Pending. | — | none |
| SOFI-024/L1529.b | transition | explicit | Resolution ladder: not registered → Pending; defensive unresolved predecessor → Pending; terminal or mismatched predecessor → Invalid; conformance Invalid → Invalid; route validation Invalid → Invalid; either still undecided → Pending; ConsumedRoute → Realized; both Valid and permanently defeated → Void; otherwise Pending. | The first matching row decides. | — | none |
| SOFI-024/L1545 | prohibition | explicit | No shortcut exists from registration to conformance. | No shortcut from registration to conformance exists. | — | none |
| SOFI-024/L1554 | invariant | explicit | Invalid means the operation never satisfied the rules; Void means a valid operation could not execute. No position moves from Void to Invalid, and a Void position performs zero mutations. | Void means a valid operation could not execute. | — | none |
| SOFI-024/L1556 | invariant | explicit | Mutual exclusion: if a fulfillment is registered at q and a root claim C is registered at q, then C = Cq. | Mutual exclusion holds | — | none |
| SOFI-024/L1560 | invariant | explicit | Realized, Void, Invalid and Pending are computed by each verifier from raw reads and never recorded; a position pending on one party can be challenged under storage §9.1 and, if dropped, resolves Void. | Amendment S1 (owner, 2026-09-22) — nothing negative is recorded, and Pending can end. | DSM-HL-005/L295 | none |

### SOFI-025 — 25 Crash and recovery

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-025/L1571 | transition | derived | Crash recovery: before F is registered nothing economic has happened and the trader may abandon; F held by members but not the leader is not exercised; F at the leader is settled and relayers complete copies; after registration any party completes the exercise; Realized only if the whole conjunction holds; missing evidence waits. | F held by the leader of Kful(q), fewer than two copies | — | none |

### SOFI-026 — 26 The stack

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-026/L1609 | prohibition | explicit | Producers assemble and publish; Core decides. A producer never interprets a storage read, never skips a Core check, and never advances state except through the Core transition with Core's result unchanged. | Producers assemble and publish; Core decides. | — | none |

### SOFI-028 — 28 Creating a vault

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-028/L1633 | transition | derived | Vault creation: the owner chooses the pair, reserves, policies and the network's pinned storage set; the owner's transition carries the signed creation through the Core transition, debiting the funding and inserting the creation leaf; any trader accepts the vault by binding the signed operation to the accepted owner transition. | The owner chooses the pair, the reserves, the market, fee and release policies, and the network | — | none |

### SOFI-029 — 29 Setting up with a vault

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-029/L1650 | transition | derived | Setup: the setup body is stored and indexed under ρ (SetupRegistered once Stored), and the trader's transition carrying it inserts the relationship leaf h0. | SetupRegistered holds once it is Stored. | — | none |

### SOFI-030 — 30 Finding the head of a vault

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-030/L1657 | invariant | derived | Anyone finds a vault's current head the same way, and path search uses nothing else: accept the genesis, then at each parent compute the seed and leader, read the attempt cells in order and classify them; a consumed attempt gives the next parent, a skipped one moves on, an unresolved one ends the walk with that attempt live. | Anyone finds a vault’s current parent the same way, and path search uses nothing else. | — | none |

### SOFI-031 — 31 A trade and a multihop route

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-031/L1697 | invariant | explicit | Every hop of a multihop route lands at its own vault's cell under that vault's leader, and no vault waits for another; the route realizes only when every hop's cell is final on E with a canonical parent and a live attempt. | realizes only when every hop | — | none |
| SOFI-031/L1698 | transition | explicit | One permanently defeated hop voids the whole route, and every other hop's final cell is then skipped so each of those vaults' next attempt goes live; there is no partial route and no coordination between vaults. | defeated hop voids the whole route | — | none |

### SOFI-032 — 32 Closing a vault

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-032/L1707 | transition | derived | Closing a vault is a one-hop route against the owner's own vault under its release policy; the owner's trader core credits the released reserves and the vault has no successor. | the owner’s T ◦ credits the | — | none |

### SOFI-033 — 33 Relaying

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-033/L1713 | liveness-boundary | derived | A relay can complete any registered fulfillment whose hops are not all final, using only F read at the position and recomputed hop keys; it needs nothing else from the trader. | It needs nothing else from the trader. | — | none |

### SOFI-035 — 35 Rules

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-035/L1766 | obligation | explicit | Rule T1: every public item under the Core SoFi module is called from production code or is test support under cfg(test); a function with no production caller is wired or deleted. | A function with no production caller is wired or deleted. | — | none |
| SOFI-035/L1772 | obligation | explicit | Rule T2: every evidence item Core consumes is bytes fetched by content address or coordinate, or supplied and published by the trader, strictly decoded after its address is recomputed; evidence is never defaulted, synthesized, filled in by the SDK, or replaced by a cached verdict. | Evidence is never defaulted, synthesized, filled in by the SDK, or replaced by a cached verdict. | — | none |
| SOFI-035/L1776 | obligation | explicit | Rule T3: every evidence item in the unlock preimage is consumed by a named Core check feeding RouteValidation, FulfillmentConformance or ConsumedRoute; an unconsumed item is refused as malformed, never ignored. | An item that no check consumes is | — | none |
| SOFI-035/L1781 | obligation | explicit | Rule T4: the values Core verified are the values installed: E recomputes from the verified preimage, the post root is exactly Fold(T, E), Cq is recomputed from verified P and F, and the SDK passes Core's result unchanged. | The values Core verified are the values the transition installs. | — | none |
| SOFI-035/L1786 | prohibition | explicit | Rule T5: a producer that receives Unavailable stops; it never publishes, exercises or advances on it. | A producer that receives Unavailable stops. | — | none |

### SOFI-037 — 37 Gates

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-037/L1854 | conformance-test | explicit | Gate G1: a CI check fails if any public function under the Core SoFi module has no caller in production code, naming each. | A CI script fails if any pub fn under CORE/sofi/ has no caller in production code. | — | none |
| SOFI-037/L1882 | conformance-test | explicit | Gate G2: Evidence derives Default only under test, and a static check fails on any Evidence::default() outside test code. | A static check fails on | — | none |
| SOFI-037/L1891 | conformance-test | explicit | Gate G3: for every evidence item there is a named test that removes it and asserts it is undecided, and one that corrupts it and asserts the specific Invalid refusal; deleting the consuming check turns the test red. | For every row of the table above there is a named test that removes the item and asserts Unavailable | — | none |
| SOFI-037/L1897 | conformance-test | explicit | Gate G4: for an accepted operation, the installed root equals Fold(T, E) from the verified cores, Cq recomputed from P and F equals the one at Kroot(q), and changing any evidence byte changes E or produces a refusal. | For an accepted operation, a test asserts that the installed root equals Fold | — | none |
| SOFI-037/L1903 | conformance-test | explicit | Gate G5: withholding each evidence item in turn on the production path results in nothing published, exercised or advanced. | On the production path, a test withholds each evidence item in turn | — | none |
| SOFI-037/L1909 | invariant | derived | A SoFi operation changes canonical state only through the one Core transition every DSM transition uses; SoFi adds no second path into state. | SoFi adds no second path into state. | — | none |

### SOFI-038 — 38 What enters the transition

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-038/L1922 | transition | explicit | Inside the transition: verify the operation against the key of the device whose state advances; run the Core checks and require Valid, stopping on any other result; derive the entropy from the relationship tip; advance with Core's result unchanged. | checks the operation against the key of the device | — | none |

### SOFI-039 — 39 Requirements

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-039/L1931 | obligation | explicit | One function prepares every transition; no SoFi producer calls a lower-level advance. | One function prepares every transition. | — | none |
| SOFI-039/L1932 | prohibition | explicit | The SDK supplies no entropy; the entropy derived from the relationship tip is the only entropy of the transition, and it goes into the tip and both receipt hashes. | The SDK supplies no entropy. | — | none |
| SOFI-039/L1934 | invariant | explicit | A transfer nonce, where an operation has one, stays in the operation bytes. | stays in the operation bytes, where it is already hashed | — | none |
| SOFI-039/L1937 | conformance-test | explicit | For each SoFi operation, applying it twice from the same state gives byte-identical results, changing any carried byte changes or refuses the result, and the tip and both receipt hashes contain the one derived entropy value. | applying it twice from the same state gives byte identical results | — | none |

### SOFI-042-1 — 42.1 Delete first

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-042-1/L2209 | proof-obligation | derived | The formal model contains no member-created registration record, no stored outcome, no semantic node ingress, and no counting of member answers; early cell occupancy is reachable and early cell consumption is not. | Early cell occupancy | — | none |

### SOFI-042-2 — 42.2 Then the invariants

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-042-2/L2214 | proof-obligation | derived | Model invariants: an unresolved conditional position is never a predecessor; stored and registered are not valid; an invalid stored artifact is never admitted; Realized requires every Core predicate. | an unresolved conditional position is never a predecessor; | — | none |
| SOFI-042-2/L2217 | proof-obligation | derived | PositionPairAtomic: whenever a position is installed, no reachable state contains only one of Kful(q) and Kroot(q). | PositionPairAtomic: whenever a position is installed | — | none |
| SOFI-042-2/L2221 | proof-obligation | derived | FinalRequiresLeader, AtMostOneFinalPerCoordinate, and LeaderFromCommittedSet (the leader is a function of the seed and S only), each with a mutation that must fail by name. | LeaderFromCommittedSet: the leader is a function of the seed and S only. | — | none |

### SOFI-042-3 — 42.3 Two properties the floor must prove

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-042-3/L2242 | proof-obligation | explicit | P1 OnlyExercisesCount: at every successor key the only value that can be final is an exercise naming that key, every other value has no effect, and K(a+1) goes live exactly when K(a) is skipped. | P1, OnlyExercisesCount. | — | none |
| SOFI-042-3/L2246 | proof-obligation | explicit | P2 RegisteredFulfillmentCanBeCompletedByAnyone: once F is registered, any party can write the exercise to every remaining successor key. | P2, RegisteredFulfillmentCanBeCompletedByAnyone. | — | none |

### SOFI-042-4 — 42.4 Files and counts

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-042-4/L2267 | conformance-test | explicit | Each model invariant holds and each falsification configuration violates exactly its named property; every Lean module builds with warnings as errors and no sorry. | Each invariant holds, and each falsification configuration violates exactly its named property. | — | none |

### SOFI-046 — 46 Not in this work

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-046/L2377 | dependency-boundary | derived | Coordinate burn surfaces outside SoFi that accept unauthenticated writes (dlv slot, recovery authority anchor, tips, devtree root, bytecommit publish, device register) are triaged separately. | Coordinate burn surfaces outside SoFi that accept unauthenticated writes are triaged separately | — | none |
| SOFI-046/L2386 | invariant | derived | Every balance, issuance and vault names a token by the hash of its whole policy, so no transition can move a token under rules other than its own. | every issuance and every vault names a token by the hash of its whole policy | DSM-HL-061/L2756 | none |
| SOFI-046/L2390 | authority | explicit | A token policy creates a tokenized asset and is anchored to its creator's state, but the creator does not own it; under the standard policy the creator locks itself out completely. | A token policy creates a tokenized asset. | — | none |
| SOFI-046/L2393 | invariant | explicit | A DLV needs no token policy of its own; its market policy points to the policy commits of the tokens it trades. | A DLV needs no token policy of its own | — | none |

### SOFI-047 — 47 What a token policy is

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-047/L2400 | obligation | derived | One canonical packer produces the token policy blob, with all integers big-endian. | Rust packs one canonical blob, the only packer for the format | — | none |
| SOFI-047/L2410 | invariant | derived | Policy field bounds: signer set k of n with 1 ≤ n ≤ 16, authorizing only what the policy's own rules name; ticker 2 to 8 characters; decimals 0 to 18. | the k of n keys | — | none |
| SOFI-047/L2422 | invariant | explicit | A token's identity is policy_commit, the hash of the whole policy blob; any differing field makes a different token. | The token’s identity is policy_commit, the hash of the whole blob. | — | none |
| SOFI-047/L2423 | invariant | explicit | The ticker is display only; two tokens may share one. | The ticker is display only; two tokens may share one. | — | none |

### SOFI-048 — 48 Two kinds of supply

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-048/L2436 | invariant | derived | Every token belongs to exactly one supply class fixed in its policy, native or externally backed, and neither class has an unlimited option. | Every token belongs to exactly one supply class, fixed in its policy. | — | none |
| SOFI-048/L2453 | invariant | explicit | For a native token, genesis supply equals unreleased units plus every balance plus burned units at every state; there is no minting after genesis, and emission is a release under the token's policy. | There is no minting after genesis. | DSM-HL-062/L2867 | none |
| SOFI-048/L2459 | invariant | explicit | For an externally backed token, outstanding units never exceed the value proven locked net of redemptions; for dBTC the correspondence is one for one. | and for dBTC, one for one under its intended construction, | DSM-HL-062/L2875 | none |
| SOFI-048/L2464 | invariant | explicit | An externally backed policy fixes an issuance rule, not a reserve: there is no pre-existing pool holding future units. | is no pre-existing pool holding all future units | — | none |

### SOFI-049 — 49 What each rule governs

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-049/L2477 | authority | derived | A policy's signer set and threshold authorize only what the policy's own rules name. | only what the policy’s own rules name | — | none |
| SOFI-049/L2478 | obligation | derived | The transferable flag is checked on every transfer (online and offline), on vault creation, and on every SoFi leg for both tokens of its vault. | every transfer, online and offline; vault | — | none |
| SOFI-049/L2482 | invariant | derived | The recipient allowlist governs only who may receive issuance; it has no market meaning, and a token trades freely once issued. | who may receive issuance; it has no mar- | — | none |

### SOFI-050 — 50 The mandatory baseline

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-050/L2497 | obligation | explicit | Every token policy states its version and kind, supply class, decimals, transferability and recipient allowlist (or none); a native policy also states genesis supply and release rule, an externally backed policy its backing rule; the constructor refuses to create a token whose policy omits any of these. | The constructor refuses to create a token whose | — | none |

### SOFI-051 — 51 Native supply

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-051/L2506 | invariant | explicit | A native token's genesis supply is fixed in its policy, and so in its identity. | The genesis supply is fixed in the token’s policy, and so in its identity. | — | none |
| SOFI-051/L2508 | authority | explicit | Under the standard policy the issuer locks itself out: it cannot change the policy or take units outside its rules. | the standard policy the issuer locks itself out completely | — | none |
| SOFI-051/L2510 | transition | explicit | Unreleased native units come out only when the conditions committed in the policy are met, verifiable by anyone by recomputing. | Units not yet released come out only when the conditions committed in the policy are met | — | none |
| SOFI-051/L2512 | invariant | explicit | A burn destroys the units it burns; they never return to the unreleased supply, so the total ever released only grows. | A burn destroys the units it burns. | — | none |
| SOFI-051/L2519 | obligation | explicit | A verifier reads each token's own committed policy and recomputes what it says; no rule is assumed from another token, a default, or the standard. | no rule is assumed from another token | — | none |

### SOFI-052 — 52 Externally backed supply

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-052/L2536 | invariant | explicit | Issuance of an externally backed token is admissible only against a lock the policy's backing rule accepts as proven, for exactly the amount proven. | Issuance is admissible only against a lock that the policy | — | none |
| SOFI-052/L2538 | invariant | explicit | Each proven lock admits its amount once: the lock is a consumed resource whose key derives from the lock itself, so two issuances against one lock collide. | Each proven lock admits its amount once. | — | none |
| SOFI-052/L2540 | transition | explicit | A redemption burns units in the same transition that releases the matching backing; backing is never released without the burn, and units are never burned without the release. | A redemption burns units in the same transition that releases the matching backing. | — | none |

### SOFI-053 — 53 Raising supply

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-053/L2560 | invariant | derived | A native token's genesis supply never changes; more supply means a new token, and an externally backed token grows only with its backing. | never changes, so a token that needs more supply is a new token. | — | none |
| SOFI-053/L2564 | transition | explicit | The new token's policy commits a conversion rule releasing it one for one for the old token, and the old units taken in are locked for good. | the old units it takes in are locked for good. | — | none |
| SOFI-053/L2566 | invariant | explicit | The conversion rule is part of the new token's anchored, locked policy and is not a DLV. | It is not a DLV: a DLV | — | none |
| SOFI-053/L2567 | invariant | explicit | The new token's policy names the old token's policy_commit, and that is the only link between them. | The new token’s policy names the old token | — | none |

### DBTC-SPEC-01-01 — 1.1 Scope

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-01-01/L42 | dependency-boundary | explicit | dBTC does not redefine DSM identity, bilateral state progression, the per-device SMT, the online economic-root register, the offline anti-cloning profile, SoFi market arithmetic, or Bitcoin consensus; those are imported as substrate. | It does not redefine DSM identity, DSM bilateral state progression | — | none |

### DBTC-SPEC-01-03 — 1.3 Specification status

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-01-03/L58 | obligation | explicit | Where an implementation differs from this specification, conformance requires bringing the implementation to the specification, never weakening the specification; the implementation references in §37 are informative. | conformance requires the implementation to be brought to this specification | — | none |
| DBTC-SPEC-01-03/L62 | authority | explicit | Bitcoin does not determine who owns dBTC: DSM determines whether the claimant owns live dBTC and whether it was validly consumed, and the DLV converts that verified consumption into Bitcoin release authority. | The protocol does not ask Bitcoin to determine who owns dBTC. | — | none |

### DBTC-SPEC-02 — 2 Architectural Principle

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-02/L75 | authority | explicit | dBTC has two authority layers, economic authority (ownership of live DSM dBTC state) and execution authority (the scoped Bitcoin material to realize an authorized withdrawal), and they must never be conflated. | These must never be conflated. | DSM-HL-064/L3201 | none |
| DBTC-SPEC-02/L79 | invariant | explicit | Definition 2.1: a party owns dBTC only if that quantity exists in a currently valid DSM economic state under authority the party can satisfy. | A party owns a quantity of dBTC only if that quantity exists in a currently valid DSM economic state | — | none |
| DBTC-SPEC-02/L83 | invariant | explicit | Definition 2.2: Bitcoin execution material is settlement machinery used to spend a backing output after a valid dBTC consumption, and is not evidence of dBTC ownership. | It is settlement machinery and is not itself evidence of dBTC ownership. | — | none |
| DBTC-SPEC-02/L109 | prohibition | explicit | Requirement 2.3: no implementation may treat knowledge of a vault identifier, lineage, ciphertext, public key, hash lock, preimage commitment, storage record, or Bitcoin transaction template as sufficient evidence of dBTC ownership. | No implementation may treat knowledge of a vault identifier | DSM-HL-064/L3209 | none |

### DBTC-SPEC-03-01 — 3.1 DSM substrate

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-03-01/L121 | safety-assumption | explicit | Assumption 3.1: accepted DSM state is linked to its predecessor by canonical cryptographic commitment, not a global sequence. | Accepted DSM state is linked to its predecessor by canonical cryptographic commitment | DSM-HL-018/L1217 | none |
| DBTC-SPEC-03-01/L125 | safety-assumption | explicit | Assumption 3.2: a realized transition consumes the identified parent and produces only the successor or successor set the transition permits. | A realized state transition consumes the identified parent state | — | none |
| DBTC-SPEC-03-01/L129 | safety-assumption | explicit | Assumption 3.3: economically relevant state is committed into the authenticated DSM state structure; unauthenticated caches are not authority. | Unauthenticated caches are not authority. | — | none |
| DBTC-SPEC-03-01/L133 | safety-assumption | explicit | Assumption 3.4: conflicting accepted successors to the same consumed state are excluded under DSM's Tripwire construction. | Conflicting accepted successors to the same consumed state are excluded | DSM-HL-053/L2346 | none |
| DBTC-SPEC-03-01/L137 | safety-assumption | explicit | Assumption 3.5: debits, credits, burns, reserve movements and provenance are accepted only through canonical DSM economic transitions satisfying conservation. | Token debits, credits, burns, reserve movements, and provenance are accepted only through canonical DSM economic transitions | — | none |

### DBTC-SPEC-03-02 — 3.2 Sovereign Finance boundary

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-03-02/L148 | invariant | explicit | An offline allocation is a separate accounting domain and is not SoFi-spendable merely because the asset is dBTC. | It is not made SoFi-spendable merely because the asset is dBTC. | — | none |
| DBTC-SPEC-03-02/L152 | obligation | explicit | Requirement 3.6: a dBTC implementation must preserve the separation between online admitted dBTC and offline allocated dBTC; no dBTC-specific bridge may merge them, and value moves between custody domains only through the canonical DSM transition for that movement. | A dBTC implementation must preserve the existing separation between: | — | none |

### DBTC-SPEC-03-03 — 3.3 DLV compatibility

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-03-03/L165 | invariant | derived | A dBTC backing vault is a DLV: value leaves only through a successor or fulfillment satisfying the condition family committed at creation, and public vault data is not reserve authority. | A dBTC backing vault is a specialization of the existing DLV idea: | — | none |

### DBTC-SPEC-04 — 4 Conformance Classes

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-04/L182 | authority | explicit | Class C (Core) is the deterministic verifier: it emits canonical commit bytes, verifies state, provenance, conservation and burns, evaluates DLV fulfillment, verifies successor arithmetic, and rejects any mismatch deterministically. | Class C is the deterministic protocol verifier. | — | none |
| DBTC-SPEC-04/L210 | obligation | explicit | Class K (SDK) constructs and orchestrates, embeds Class C, and invokes constrained vault execution only after successful Class C verification. | invokes constrained vault execution only after successful verification; | — | none |
| DBTC-SPEC-04/L242 | authority | explicit | Class N (storage) is non-authoritative persistence and indexing and does not determine economic validity. | Class N does not determine economic validity. | — | none |
| DBTC-SPEC-04/L246 | prohibition | explicit | Requirement 4.4: Class N must not become a Bitcoin signing committee, threshold signer, custodian, mint or validator set because encrypted vault bytes are stored there; any storage-set write-once barrier stays a persistence primitive, not signing authority. | Class N must not become a Bitcoin signing committee | — | none |

### DBTC-SPEC-05 — 5 Clocklessness and External Bitcoin Finality

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-05/L257 | prohibition | explicit | Requirement 5.1: no ownership, burn, DLV unlock or successor validity predicate may depend on wall-clock time, elapsed duration, or a globally shared DSM sequence. | No dBTC ownership predicate, burn predicate, DLV unlock predicate, or successor validity predicate may depend on wall-clock time | — | none |
| DBTC-SPEC-05/L259 | invariant | explicit | Bitcoin confirmation depth is an external settlement observation, not a DSM ordering primitive. | Bitcoin confirmation depth is an external settlement observation, not a DSM ordering primitive. | — | none |
| DBTC-SPEC-05/L269 | obligation | explicit | Requirement 5.2: the Bitcoin network identifier and minimum confirmation depth are committed into the vault profile or resolved from an immutable network profile. | The Bitcoin network identifier and $d_{\min}$ policy must be committed into the vault profile | — | none |
| DBTC-SPEC-05/L271 | liveness-boundary | explicit | A reorganization deeper than the accepted depth is an external Bitcoin assumption and is not claimed impossible. | A reorganization deeper than the accepted Bitcoin depth is an external Bitcoin assumption | — | none |

### DBTC-SPEC-06 — 6 Canonical Encoding and Domain Separation

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-06/L284 | obligation | explicit | Security-critical objects are converted to canonical commit bytes before hashing or signing, preserving: canonical fixed-width byte order, length-delimited variable strings, canonical field order, explicit absence, deterministic set and map order, no floating point in predicates, and a class discriminant and schema version on every object. | At minimum, CCB must preserve the existing DSM rules: | — | none |
| DBTC-SPEC-06/L306 | invariant | explicit | Transport is Protobuf; identifiers are binary internally and Base32 Crockford for human display; hexadecimal text is not a protocol encoding. | Hexadecimal text is not a protocol encoding. | — | none |

### DBTC-SPEC-06-01 — 6.1 Required domains

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-06-01/L311 | invariant | explicit | The DLV unlock domain DSM/dlv-unlock is retained, and the dBTC domains are dbtc-origin, dbtc-burn, dbtc-exit, dbtc-successor and dbtc-vault-capsule (v1). | The existing DLV unlock domain is retained: | — | none |
| DBTC-SPEC-06-01/L339 | prohibition | explicit | Where an equivalent registered DSM domain already exists, it is authoritative and a duplicate domain must not be created. | the registered domain is authoritative and duplicate domains must not be created | — | none |

### DBTC-SPEC-07 — 7 The dBTC Asset

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-07/L350 | invariant | explicit | One dBTC base unit is one satoshi-equivalent unit of DSM economic state whose positive issuance traces to accepted Bitcoin backing; a valid quantity requires provenance, not just the asset identifier. | A valid quantity requires provenance. | — | none |
| DBTC-SPEC-07/L369 | invariant | derived | A holder's dBTC state retains per-origin allocations; the wallet may show one fungible balance while the protocol keeps the provenance needed to reconcile withdrawals with backing. | while the protocol retains the provenance needed to reconcile withdrawals with actual Bitcoin backing | — | none |
| DBTC-SPEC-07/L373 | invariant | explicit | Invariant 7.2: a positive dBTC credit must have a canonical source accepted by DSM; no generic self-asserted mint or custom credit source may manufacture dBTC. | A positive dBTC credit must have a canonical source accepted by DSM. | — | none |

### DBTC-SPEC-08-01 — 8.1 Origin output

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-08-01/L399 | invariant | explicit | Definition 8.1: an origin DLV commits vault id, generation, outpoint, backing amount, fulfillment condition, parameter commitment, execution public key, fulfillment hash, the Bitcoin network and confirmation profile, and the policy (including any successor minimum backing). | A dBTC origin DLV is represented abstractly as: | — | none |
| DBTC-SPEC-08-01/L441 | invariant | derived | The vault identifier is stable across partial-withdrawal successors; the generation and Bitcoin outpoint change. | The generation and Bitcoin outpoint change. | — | none |

### DBTC-SPEC-09 — 9 Origin Admission and dBTC Issuance

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-09/L448 | obligation | explicit | Class C must verify an origin: a Bitcoin output does not create dBTC because a client says it exists. | Class C must verify the origin. | — | none |
| DBTC-SPEC-09/L470 | invariant | explicit | Definition 9.1 ValidOrigin: valid funding transaction; outpoint exists; amount equals B0; script matches the committed profile; inclusion in an accepted chain; required depth met; origin id recomputes; the origin is bound to one canonical issuance position; and the policy commitment matches the canonical dBTC asset. | the exact Bitcoin origin is bound to one canonical DSM issuance position; and | — | none |
| DBTC-SPEC-09/L476 | invariant | explicit | Requirement 9.2 (mint gate): positive dBTC issuance must satisfy ValidOrigin. | Positive dBTC issuance must satisfy: | SOFI-052/L2536 | none |

### DBTC-SPEC-10 — 10 What Moves During an Ordinary dBTC Transfer

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-10/L507 | transition | explicit | An ordinary dBTC transfer is a DSM operation proving the source exists, authority, currency, exact debit, canonical credit, exact remainder, preserved provenance, and that the source cannot stay spendable. | The existing DSM transfer verifier proves: | DSM-HL-064/L3222 | none |
| DBTC-SPEC-10/L527 | prohibition | explicit | Requirement 10.1: an ordinary dBTC transfer must not require a Bitcoin confirmation, the original depositor, a custodian, a signing quorum, a mint, a global ledger, or a storage-node economic verdict. | An ordinary dBTC transfer must not require: | — | none |
| DBTC-SPEC-10/L549 | invariant | explicit | The Bitcoin backing generation advances only when the backing outpoint is actually consumed, not when DSM ownership changes. | The Bitcoin backing generation advances when the backing Bitcoin outpoint is actually consumed | — | none |

### DBTC-SPEC-11 — 11 Withdrawal Is a DSM Consumption First

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-11/L556 | invariant | derived | Withdrawal is a DSM consumption first: a holder never obtains a Bitcoin key and then promises to burn dBTC; the order is reversed. | A holder does not first obtain a Bitcoin key and then promise to burn dBTC. | DSM-HL-064/L3238 | none |

### DBTC-SPEC-11-01 — 11.1 Withdrawal intent

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-11-01/L575 | obligation | explicit | Before vault execution authority is usable, Class K constructs a canonical withdrawal intent binding origin vault, consumed quantity, payout, fee, destination, backing generation, current outpoint, live source state, and (for a partial withdrawal) the successor rule. | Before the vault execution authority is usable, Class K constructs a canonical withdrawal intent: | — | none |
| DBTC-SPEC-11-01/L621 | invariant | explicit | Requirement 11.1: the burn proof binds the exact withdrawal intent; changing amount, destination, origin, outpoint, fee treatment or successor construction changes its commitment. | The burn proof must bind the exact withdrawal intent. | — | none |

### DBTC-SPEC-12 — 12 The dBTC Burn

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-12/L630 | transition | explicit | Definition 12.1: a withdrawal burn is a canonical DSM transition that consumes an actual spendable dBTC quantity and produces a non-spendable withdrawal-completion object; the consumed dBTC is then no longer spendable. | A withdrawal burn is a canonical DSM transition consuming an actual spendable dBTC quantity | — | none |
| DBTC-SPEC-12/L644 | authority | explicit | Requirement 12.2: Class C must reject a burn unless the claimant possesses the live dBTC state it names and satisfies that state's authority. | unless the claimant possesses the live dBTC state identified by | — | none |
| DBTC-SPEC-12/L648 | prohibition | explicit | Requirement 12.3: a burn proof is never accepted because its bytes are well formed; Class C verifies the actual transition, including source inclusion, freshness, authority, provenance, exact debit and successor root. | A burn proof must not be accepted merely because its bytes are well formed. | — | none |

### DBTC-SPEC-13 — 13 DLV Completion Evidence

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-13/L696 | invariant | explicit | The completion commitment σ must cryptographically commit to the transition that consumed the dBTC and to the exact withdrawal intent. | It must cryptographically commit to the state transition that consumed the dBTC and to the exact withdrawal intent. | — | none |
| DBTC-SPEC-13/L731 | invariant | explicit | Requirement 13.1: a candidate vault secret is valid only if the live state, claimant authority, consumed quantity, origin lineage, withdrawal intent, DLV lock, parameter commitment, completion commitment and fulfillment hash all align. | is valid only if all of the following align: | — | none |
| DBTC-SPEC-13/L755 | invariant | explicit | Hash equality with the fulfillment hash is necessary but not independently sufficient; it is the final equality of an already-verified state relation. | is necessary but not independently sufficient at the DSM layer. | — | none |

### DBTC-SPEC-14 — 14 Knowledge Is Not Possession

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-14/L782 | invariant | explicit | Knowledge is not possession (normative): holding the complete DLV, lineage, receipts, Bitcoin history, encrypted capsule, public key, fulfillment hash and every storage replica creates no valid burn; the withdrawal relation is conjunctive. | None of those facts create a valid burn. | — | none |
| DBTC-SPEC-14/L808 | invariant | explicit | Copied lineage, a copied preimage commitment, stale state, a key not matching the live state's authority, a completion proof from another state, and a preimage from another vault or generation are each inert. | A completion proof from a different state is inert. | — | none |

### DBTC-SPEC-15-01 — 15.1 Purpose

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-15-01/L818 | invariant | explicit | The Bitcoin execution key is not the bearer asset and should not reside as an ordinary reusable secret in transferable dBTC state; it is held outside it as a sealed execution capsule, which storage nodes may persist. | should not reside as an ordinary reusable secret in the transferable dBTC state | — | none |
| DBTC-SPEC-15-01/L841 | prohibition | explicit | Requirement 15.1: possession of the execution capsule alone provides no usable Bitcoin signing authority. | alone must provide no usable Bitcoin signing authority. | — | none |

### DBTC-SPEC-15-02 — 15.2 Fulfillment-gated opening

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-15-02/L866 | transition | explicit | The capsule opens only with a valid DLV fulfillment secret and a verified withdrawal intent, yielding constrained execution authority for the current generation. | Here $\mathcal{A}_n$ is the constrained Bitcoin execution authority for the current backing generation. | — | none |
| DBTC-SPEC-15-02/L870 | prohibition | explicit | Requirement 15.2: a conforming high-assurance implementation must not expose the execution scalar through a general-purpose signing or export API after fulfillment; the authority is usable only by the vault execution path bound to the verified intent. | A conforming high-assurance implementation must not expose | — | none |

### DBTC-SPEC-16 — 16 Current Bitcoin Fulfillment Script Profile

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-16/L905 | invariant | derived | The current profile may use the dual-hashlock DLV script; the normal withdrawal path is the fulfill branch, requiring the preimage of the fulfillment hash and a signature under the execution key. | The normal dBTC withdrawal path is the fulfill branch. | — | none |
| DBTC-SPEC-16/L917 | invariant | explicit | Requirement 16.1: the hashlock witness and Bitcoin signature correspond to the same DLV generation and the same committed execution; a preimage from one generation is never paired with authority from another. | A valid preimage from one generation must not be paired with execution authority from another generation. | — | none |

### DBTC-SPEC-16-01 — 16.1 Refund branch

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-16-01/L922 | prohibition | explicit | A refund branch, if present, must not be a discretionary depositor backdoor. | If a refund branch exists, it must not be a discretionary depositor backdoor. | — | none |
| DBTC-SPEC-16-01/L926 | prohibition | explicit | Requirement 16.2: a live dBTC-backed vault never exposes a refund secret because a wall clock expired or the depositor asks; any refund secret derives from a mutually exclusive DSM condition under the committed policy. | must not expose a refund secret merely because a wall clock expired or because the depositor requests one | — | none |
| DBTC-SPEC-16-01/L930 | invariant | explicit | A refund path never lets Bitcoin backing leave while corresponding live dBTC remains outstanding. | A refund path must never allow Bitcoin backing to leave while corresponding live dBTC remains outstanding. | — | none |

### DBTC-SPEC-17 — 17 Constructing the Bitcoin Withdrawal

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-17/L952 | obligation | explicit | The withdrawal intent binds the transaction commitment, or contains enough canonical fields for Class C to recompute the same transaction body. | The withdrawal intent must bind | — | none |
| DBTC-SPEC-17/L958 | prohibition | explicit | Requirement 17.1: execution authority released by one burn never authorizes an arbitrary destination or amount; the execution routine verifies the candidate transaction equals the one the burn committed. | The vault execution routine must verify that the candidate transaction equals the transaction committed by the burn. | — | none |

### DBTC-SPEC-18 — 18 Full Withdrawal

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-18/L985 | transition | derived | A full withdrawal consumes all dBTC backed by the selected vault quantity and creates no successor vault. | No successor vault is created. | — | none |
| DBTC-SPEC-18/L989 | invariant | explicit | Property 18.1: after a valid full withdrawal consumes the backing outpoint, that DLV generation is terminal and never advertises a live successor. | the corresponding DLV generation is terminal and must not advertise a live successor. | — | none |

### DBTC-SPEC-19 — 19 Partial Withdrawal and Successor Vault

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-19/L1026 | obligation | explicit | If a partial withdrawal's fee is funded by a separate Bitcoin input, the accounting is adjusted and that external fee source is explicit. | that external fee source must be explicit | — | none |
| DBTC-SPEC-19/L1030 | invariant | explicit | Requirement 19.1: a profile permitting partial withdrawal commits an immutable lineage-wide successor minimum backing, and every successor satisfies it after the declared fee and anchor treatment. | That value is a lineage property and must remain immutable across successor generations. | — | none |
| DBTC-SPEC-19/L1046 | obligation | explicit | Class C enforces the successor minimum as part of burn acceptance, not only at construction; if it fails the burn is invalid and no completion evidence, unlock value, signature or successor activation follows. | Class C must enforce this condition as part of burn acceptance | DSM-HL-064/L3291 | none |

### DBTC-SPEC-19-01 — 19.1 Successor identity

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-19-01/L1051 | invariant | derived | A successor keeps the stable origin v, advances its backing generation, and has a new Bitcoin outpoint. | The successor retains the same stable origin: | — | none |

### DBTC-SPEC-19-02 — 19.2 Fresh successor authority

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-19-02/L1071 | invariant | explicit | A successor uses fresh Bitcoin execution authority and fresh generation-specific DLV fulfillment material. | The successor must use fresh Bitcoin execution authority: | — | none |
| DBTC-SPEC-19-02/L1091 | prohibition | explicit | Requirement 19.2: a partial withdrawal never returns the remainder to the spent parent execution key. | A partial withdrawal must not return the remainder to the spent parent execution key. | — | none |
| DBTC-SPEC-19-02/L1097 | obligation | explicit | Requirement 19.3: successor-key derivation is canonical, domain-separated, pinned by known-answer vectors, and binds at least the vault id, successor generation, parent outpoint, exact transaction commitment, successor parameters and fresh material. | The exact successor-key derivation must be canonical, domain-separated, and pinned by known-answer test vectors. | — | none |
| DBTC-SPEC-19-02/L1113 | prohibition | explicit | The parent scalar alone never constitutes an unrestricted reusable successor credential outside the constrained vault transition. | The parent scalar alone must not constitute an unrestricted reusable successor credential | — | none |

### DBTC-SPEC-19-03 — 19.3 Successor activation

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-19-03/L1118 | transition | derived | The successor DLV is constructed in the same authorized split, and becomes active once its output is proven in the accepted chain at the required depth. | The successor DLV is constructed as part of the same authorized split. | — | none |
| DBTC-SPEC-19-03/L1132 | invariant | explicit | Property 19.4: activation changes the backing generation, not the economic origin; the remaining live dBTC still traces to origin v. | Activation changes the Bitcoin backing generation, not the economic origin. | — | none |

### DBTC-SPEC-20 — 20 Why the Parent Cannot Remain the Authority

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-20/L1155 | invariant | explicit | After a partial withdrawal the parent outpoint is no longer backing and the old generation is terminal; the remainder is represented only by the successor. | The protocol must not represent both as active backing. | — | none |
| DBTC-SPEC-20/L1159 | invariant | explicit | Invariant 20.1: for one realized branch of a vault lineage, a spent parent generation and its confirmed successor are never both classified as live backing. | a spent parent Bitcoin generation and its confirmed successor must not both be classified as live backing | DSM-HL-064/L3290 | none |

### DBTC-SPEC-21 — 21 No Separate dBTC Double-Spend System

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-21/L1166 | invariant | derived | dBTC adds no second ownership consensus: the withdrawal verifier asks only whether the party holds a valid current state under valid authority and the transition consumes it by the committed rules. | dBTC does not need a second ownership consensus mechanism layered on top of DSM. | — | none |
| DBTC-SPEC-21/L1174 | invariant | explicit | Without a valid burn there is no completion evidence, and without it the correct unlock value does not exist. | If no valid burn exists, no valid completion evidence | — | none |
| DBTC-SPEC-21/L1190 | invariant | explicit | Property 21.1: arbitrary dBTC-looking bytes cannot authorize release; the claimant must prove state inclusion, current-state validity, authority, provenance and consumption. | Producing arbitrary dBTC-looking bytes cannot authorize Bitcoin release | — | none |
| DBTC-SPEC-21/L1194 | invariant | explicit | Property 21.2: a prior owner holding an old state does not regain withdrawal authority after that state was consumed by an accepted successor. | A prior owner who retains an old dBTC state does not regain withdrawal authority | — | none |

### DBTC-SPEC-22 — 22 Online dBTC

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-22/L1209 | evidence | explicit | An online withdrawal proves the burn against the canonical economic root: the leaf existed in the predecessor root, the claimant had authority, the exact quantity was removed, the result is canonical, the position is admitted under the online root machinery, and the completion evidence binds the intent. | A withdrawal from online dBTC must prove the burn against the canonical economic root: | — | none |
| DBTC-SPEC-22/L1229 | prohibition | explicit | Requirement 22.1: a local wallet cache never substitutes for proof of the canonical economic-root state. | A local wallet cache must not substitute for proof of the canonical | — | none |

### DBTC-SPEC-23 — 23 Offline dBTC

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-23/L1238 | dependency-boundary | explicit | Offline dBTC is a separate bearer domain using the offline appliance machinery (out of scope); an offline burn proof must show a live allocation, genuine appliance authority, current protected state, exactly-once consumption, a recomputed successor, and the bound intent. | A Bitcoin withdrawal from an offline allocation may use | — | none |
| DBTC-SPEC-23/L1254 | prohibition | explicit | Requirement 23.1: an offline burn proof is never treated as an admitted SoFi economic root because both carry dBTC, and an online balance proof never impersonates an offline allocation. | An offline burn proof must not be treated as an admitted SoFi | DBTC-SPEC-03-02/L148 | none |

### DBTC-SPEC-24 — 24 Storage Nodes

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-24/L1265 | invariant | derived | Storage nodes may hold each generation's vault, capsule, proofs and metadata so a future holder can retrieve them even if the depositor is permanently offline. | They may be used so that a future dBTC holder can retrieve the vault material | — | none |
| DBTC-SPEC-24/L1279 | prohibition | explicit | Requirement 24.1: a storage node must not decide ownership, validate a burn as economic authority, hold a mint key or plaintext reusable vault key, sign an exit, turn an invalid transition valid, or choose a successor. | A storage node must not: | STOR-002/L75 | none |
| DBTC-SPEC-24/L1297 | invariant | explicit | A malicious or unavailable storage service may degrade availability but gains no economic authority from the bytes it stores. | It must not gain economic authority from the bytes it stores. | — | none |

### DBTC-SPEC-25 — 25 Original Depositor Independence

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-25/L1302 | invariant | derived | After origin admission the depositor has no continuing role; a later bearer may obtain lineage, generation, capsule, proofs and parameters from any source, and the depositor need not sign. | the original depositor has no continuing authorization role in ordinary dBTC circulation | — | none |
| DBTC-SPEC-25/L1324 | liveness-boundary | explicit | Property 25.1: an ordinary withdrawal by a valid current holder never requires the origin depositor to return online. | must not require the origin depositor to return online | STOR-020/L463 | none |

### DBTC-SPEC-26 — 26 Multi-Origin Balances

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-26/L1347 | obligation | explicit | Each backing input of a multi-origin withdrawal is independently justified by dBTC consumed from its own origin. | Each input must be independently justified by dBTC consumed from the corresponding origin. | — | none |
| DBTC-SPEC-26/L1350 | invariant | explicit | Invariant 26.1: for every origin, the dBTC consumed against it does not exceed the dBTC attributed to it before the burn. | Invariant 26.1 — Origin conservation | — | none |
| DBTC-SPEC-26/L1361 | prohibition | explicit | Requirement 26.2: dBTC attributed to one origin is never redeemed against an unrelated origin unless a canonical transition has changed the provenance. | must not redeem dBTC attributed to origin | — | none |

### DBTC-SPEC-27 — 27 Fee Accounting

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-27/L1366 | invariant | explicit | Bitcoin fees consume value and appear in conservation arithmetic, including any retained anchor value. | Bitcoin fees consume value and therefore must appear in conservation arithmetic. | — | none |
| DBTC-SPEC-27/L1380 | prohibition | explicit | Requirement 27.1: the Bitcoin fee is never silently increased after the burn if that changes how much backing leaves; an economically relevant fee change needs a transition whose accounting recomputes exactly. | No implementation may silently increase the Bitcoin fee after the DSM burn | — | none |

### DBTC-SPEC-28 — 28 Conservation

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-28/L1397 | invariant | explicit | Per origin lineage, backing equals live plus in-flight consumed dBTC before release, and a payout with a backing-paid fee reduces backing and redeemable dBTC by the same amount. | The exact state labels are implementation-specific, but the economic conservation relation is not. | — | none |
| DBTC-SPEC-28/L1419 | invariant | explicit | Invariant 28.1: no accepted sequence leaves more redeemable dBTC attributed to an origin than the backing that origin retains under the committed fee and reserve policy. | No accepted protocol sequence may leave more redeemable dBTC attributed to an origin | SOFI-048/L2459 | none |

### DBTC-SPEC-29 — 29 Crash Safety and Replay

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-29/L1424 | obligation | explicit | Withdrawal is crash-safe across its stages: intent, transaction candidate, burn, durable completion evidence, fulfillment material, constrained execution, exact signing, durable signed transaction, broadcast, settlement observation, successor publication. | Withdrawal crosses two systems and must be crash-safe. | — | none |
| DBTC-SPEC-29/L1458 | prohibition | explicit | Requirement 29.1: once a burn commits an exact transaction, recovery either re-emits that identical transaction or fails closed, and never uses the burn for a different destination, amount or successor. | Recovery must not use the same burn to construct a different destination, amount, or successor. | — | none |
| DBTC-SPEC-29/L1462 | prohibition | explicit | Requirement 29.2: failing to observe a transaction never automatically recreates spendable dBTC while a signed transaction may exist; any recovery or refund proves a mutually exclusive state in which the release can no longer take effect. | must not automatically recreate spendable dBTC if a Bitcoin-valid signed transaction may still exist | — | none |

### DBTC-SPEC-30 — 30 Concurrent Local Invocation

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-30/L1479 | obligation | explicit | Requirement 30.1: Class K serializes local execution of one vault generation (or uses an atomic compare-and-set), and a second request against an already committed generation fails closed; this is concurrency control, not economic authority. | must serialize local execution of one | — | none |

### DBTC-SPEC-31 — 31 Security Properties

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-31/L1490 | theorem | explicit | Property 31.1: if vault authority is opened through the conforming path, a valid DSM consumption of the dBTC bound to that withdrawal exists. | If a Bitcoin vault authority is opened through the conforming dBTC path | — | none |
| DBTC-SPEC-31/L1494 | theorem | explicit | Property 31.2: public or replicated DLV metadata cannot create a positive dBTC balance. | Public or replicated DLV metadata cannot create a positive dBTC balance. | — | none |
| DBTC-SPEC-31/L1498 | theorem | explicit | Property 31.3: a state already consumed by a valid successor cannot satisfy the current-state requirement for another withdrawal. | A state already consumed by a valid DSM successor cannot independently satisfy the current-state requirement | — | none |
| DBTC-SPEC-31/L1508 | theorem | explicit | Property 31.4: substituting any of the lock, parameters or completion evidence for a fixed generation changes the unlock derivation except with negligible probability. | changes the DLV unlock derivation except with negligible probability under the hash assumptions. | — | none |
| DBTC-SPEC-31/L1512 | theorem | explicit | Property 31.5: a partial withdrawal cannot create a successor retaining more than the backing minus payout minus the declared fee. | A partial withdrawal cannot validly create a successor whose retained Bitcoin value exceeds: | — | none |
| DBTC-SPEC-31/L1520 | theorem | explicit | Property 31.6: a partial withdrawal cannot create or activate a successor below the lineage-wide minimum backing. | cannot validly create or activate a successor whose retained Bitcoin backing is below the lineage-wide | — | none |
| DBTC-SPEC-31/L1524 | theorem | explicit | Property 31.7: a spent parent generation does not remain execution authority for the confirmed successor. | A spent parent generation does not remain the Bitcoin execution authority for the confirmed successor generation. | — | none |
| DBTC-SPEC-31/L1528 | theorem | explicit | Property 31.8: compromise of storage alone creates neither a valid burn nor a valid constrained withdrawal. | Compromise of Class N storage alone does not create a valid dBTC burn | — | none |
| DBTC-SPEC-31/L1532 | theorem | explicit | Property 31.9: after admission, ordinary transfer and valid bearer withdrawal never need the original depositor's approval. | ordinary transfer and valid bearer withdrawal do not require the original depositor | — | none |

### DBTC-SPEC-32 — 32 What a Device Compromise Means

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-32/L1541 | safety-assumption | explicit | dBTC inherits the security of the DSM custody profile used: whoever can produce a burn the verifier accepts controls that dBTC, and the vault does not pretend otherwise; unrelated storage or metadata compromise creates no burn. | The dBTC vault must not pretend otherwise. | — | none |

### DBTC-SPEC-33 — 33 What Is Deliberately Not Introduced

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-33/L1562 | prohibition | explicit | The protocol introduces no threshold-signing federation, custodian committee, validator set, global ledger, approving mint, storage voting, second double-spend database, depositor liveness requirement, wall-clock settlement validity, dBTC-only ownership model or appliance, or knowledge-as-ownership rule. | This protocol introduces none of the following: | — | none |

### DBTC-SPEC-34 — 34 What Is Deliberately Not Claimed

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-34/L1591 | liveness-boundary | explicit | Not claimed: prevention of reorganizations beyond the chosen depth; security after compromise of the DSM authority needed to burn; that storage unavailability cannot delay retrieval; safety of malformed Bitcoin transactions by convention; exportable raw parent scalars; a refund path coexisting with live dBTC without an exclusive condition; mainnet security from testnet shortcuts; conformance merely because primitives exist. | The following are not claimed: | — | none |

### DBTC-SPEC-38 — 38 Required Conformance Tests

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-38/L1846 | obligation | explicit | A conforming implementation includes deterministic tests covering at least the cases of §38.1 to §38.8. | A conforming implementation must include deterministic tests covering at least the following cases. | — | none |

### DBTC-SPEC-38-01 — 38.1 Origin admission

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-38-01/L1861 | conformance-test | explicit | Origin admission: valid confirmed backing admits exactly matching dBTC; wrong amount, wrong script, wrong network and insufficient depth reject; reusing one origin proof for a second issuance rejects. | Reusing one origin proof for a second independent dBTC issuance rejects. | — | none |

### DBTC-SPEC-38-02 — 38.2 DSM ownership

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-38-02/L1876 | conformance-test | explicit | DSM ownership: valid live dBTC can enter a burn; nonexistent dBTC, stale consumed state, wrong claimant authority and wrong origin allocation cannot; a forged positive balance fails provenance verification. | A forged positive dBTC balance cannot pass provenance verification. | — | none |

### DBTC-SPEC-38-03 — 38.3 DLV fulfillment

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-38-03/L1895 | conformance-test | explicit | DLV fulfillment: correct L, C and σ derive the expected secret; mutating any of them changes it; a wrong preimage fails the hash lock; burn proofs from another vault or generation fail; completion evidence not binding the exact intent fails. | Completion evidence that does not bind the exact withdrawal intent fails. | — | none |

### DBTC-SPEC-38-04 — 38.4 Full withdrawal

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-38-04/L1900 | conformance-test | explicit | Full withdrawal: the burn signs only the committed withdrawal; changing destination, amount or fee treatment after the burn fails; no successor is created; the parent becomes terminal after the confirmed spend. | Full burn signs only the committed full withdrawal. | — | none |

### DBTC-SPEC-38-05 — 38.5 Partial withdrawal

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-38-05/L1915 | conformance-test | explicit | Partial withdrawal: exactly one canonical successor output; conservation holds; the generation increments once; the outpoint matches the transaction; successor authority differs from and cannot reuse the parent's; the origin id is retained; mutating successor key, script or amount after the burn fails; a split below the minimum backing rejects before completion evidence; a successor cannot alter the minimum. | Partial burn creates exactly one canonical successor output. | — | none |

### DBTC-SPEC-38-06 — 38.6 Storage

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-38-06/L1944 | conformance-test | explicit | Storage: public DLV data or the encrypted capsule alone produce no burn or withdrawal; copying all storage records creates no dBTC; omission causes availability failure, not value creation; storage never invokes signing authority. | Copying all Class N records to another host does not create dBTC. | — | none |

### DBTC-SPEC-38-07 — 38.7 Crash and recovery

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-38-07/L1965 | conformance-test | explicit | Crash and recovery: a crash before the burn leaves no unlock proof; after the burn only the same withdrawal resumes; after signing the exact transaction is retained; after broadcast nothing is reminted; recovery cannot change destination or successor; replaying a completed burn creates no second debit or credit. | Replaying a completed burn cannot generate a second independent dBTC debit or credit. | — | none |

### DBTC-SPEC-38-08 — 38.8 Online/offline separation

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-38-08/L1978 | conformance-test | explicit | Online/offline separation: online burns verify against the admitted economic root; an unauthenticated wallet cache is rejected; offline burns use the protected-state path; offline allocations are not SoFi liquidity; online and offline proofs cannot substitute for each other. | Online and offline proofs cannot substitute for one another. | — | none |

### DBTC-SPEC-39 — 39 Proof Obligations

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-39/L1987 | proof-obligation | explicit | 39.1 Burn uniqueness: for one spendable source state, two different accepted burns cannot consume the same quantity. | two different accepted burns cannot both consume the same economic quantity | — | none |
| DBTC-SPEC-39/L1991 | proof-obligation | explicit | 39.2 Burn/unlock implication: every accepted vault unlock implies a valid burn bound to it. | For any accepted dBTC vault unlock: | — | none |
| DBTC-SPEC-39/L2000 | proof-obligation | explicit | 39.3 Intent binding: for any valid burn proof, changing amount, destination, generation or successor commitment makes the execution check fail. | changing the withdrawal amount, destination, backing generation, or successor commitment causes the associated vault execution check to fail. | — | none |
| DBTC-SPEC-39/L2003 | proof-obligation | explicit | 39.4 Successor conservation: a partial withdrawal's backing equals payout plus fee plus successor backing plus anchor under the declared profile. | Proof Obligation 39.4 — Successor conservation | — | none |
| DBTC-SPEC-39/L2014 | proof-obligation | explicit | 39.5 No hidden duplicate reserve: after a partial withdrawal confirms, the parent output is not represented as live backing beside its successor. | the parent backing output is not simultaneously represented as live backing beside its successor | — | none |
| DBTC-SPEC-39/L2022 | proof-obligation | explicit | 39.6 Successor minimum backing: every accepted partial withdrawal's successor meets the lineage minimum, and no valid burn produces completion evidence for a split violating it. | No valid burn may produce completion evidence for a split that violates this bound. | — | none |
| DBTC-SPEC-39/L2026 | proof-obligation | explicit | 39.7 Provenance conservation: transfer, split, merge and burn preserve total origin-attributed dBTC except explicit valid issuance and explicit withdrawal burns. | Transfer, split, merge, and burn operations preserve the total origin-attributed dBTC quantity | — | none |

### DBTC-SPEC-41 — 41 Final Protocol Invariant

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-41/L2107 | invariant | explicit | Final invariant: the dBTC is never the Bitcoin key, the Bitcoin key is never the ownership proof, and the preimage is never sufficient by itself; authority comes from valid state and a valid transition. | The dBTC is never the Bitcoin key. | — | none |

### STOR-001 — 1 What a storage node is

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-001/L60 | authority | explicit | A node must hold no key and must sign nothing. | A node MUST hold no key and MUST sign nothing. | DSM-HL-011/L747 | none |
| STOR-001/L61 | prohibition | explicit | A node must not validate a protocol rule, evaluate a guard, compute a balance or a leader, compare values, or decide whether a transition is valid. | A node MUST NOT validate a protocol rule, evaluate a guard, compute a balance, compute a leader | — | none |
| STOR-001/L62 | prohibition | explicit | Payloads are opaque to the node apart from content addressing, and the node must not vary what it stores by what a payload would parse as. | Economic and protocol payloads MUST be opaque to the node apart from content addressing. | — | none |
| STOR-001/L63 | prohibition | explicit | No protocol-relevant node path may read a clock; ordering inside the node uses logical ticks. | No protocol-relevant path in the node MAY read a clock. | — | none |
| STOR-001/L64 | invariant | explicit | Inter-node gossip is state synchronisation only: no leader election, Raft, Paxos or vote. | Inter-node gossip is state synchronisation only. | — | none |
| STOR-001/L68 | obligation | explicit | Every addition to the node asks whether storage needs to know what it means; if so, it is in the wrong layer. | does storage need to know what this means? If yes, the addition is in the wrong layer. | SOFI-002-2/L386 | none |

### STOR-002 — 2 What a node never does

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-002/L75.a | prohibition | explicit | A node must not decide asset ownership, validate a burn as economic authority, hold a mint key or plaintext reusable vault key, sign a Bitcoin exit, turn an invalid transition valid, or choose a successor. | A node MUST NOT decide who owns an asset | DBTC-SPEC-24/L1279 | none |
| STOR-002/L75.b | invariant | explicit | A malicious or unavailable node may degrade availability but must not gain authority from the bytes it stores. | It MUST NOT gain authority from the bytes it stores. | — | none |

### STOR-003 — 3 Fault model

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-003/L82 | safety-assumption | explicit | A node may crash and omit messages. | A node may crash and may omit messages. | — | none |
| STOR-003/L83 | safety-assumption | explicit | A node never equivocates, alters, reorders or permanently loses what it holds, across restart, restoration and storage migration. | A node never equivocates, never alters content it holds, never reorders what it holds for a key | DSM-HL-080/L3998 | none |
| STOR-003/L84 | safety-assumption | explicit | Restoring a node from a snapshot that predates a held value is a safety violation, not an availability event. | Restoring a node from a snapshot that predates a value it held is a safety violation | — | none |
| STOR-003/L85 | safety-assumption | explicit | Misresponses about immutable objects are detectable by hash and affect availability only. | Misresponses about immutable objects are detectable by hash and affect availability only. | — | none |
| STOR-003/L86 | obligation | explicit | A store outside the fault model fails closed. | A store that falls outside this model fails closed. | — | none |
| STOR-003/L90 | liveness-boundary | explicit | Failing to reach a cell's leader or two other members is a liveness failure and the cell waits; violating durable memory is a safety failure. | Failure to reach a cell's leader, or two other members, is a liveness failure | — | none |
| STOR-003/L94 | invariant | explicit | The durable-memory assumptions bind a role (seat), not a machine: memory survives the machine through handover, and total loss is handled by the loss rule, never by treating a new machine's empty memory as history. | Items 2 and 3 bind a *role* (§11), not a machine. | — | none |

### STOR-004 — 4 What storage facts are

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-004/L101 | evidence | explicit | Core derives exactly three storage facts (LeaderHeld, Final, Stored) from raw reads and uses nothing else from storage; registered is not validated. | Core derives exactly three storage facts from raw reads | SOFI-013/L689 | none |
| STOR-004/L105 | prohibition | explicit | A storage fact not established from the reads in hand is never read as its negation; a verifier records nothing for a presentation it does not accept, and nothing a node returns is a verdict. | A verifier records nothing for a presentation it does not accept. | DSM-HL-005/L295 | none |

### STOR-005 — 5 Immutable objects

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-005/L116 | invariant | explicit | An immutable payload P in namespace N is stored at H(DSM/storage-object ∥ N ∥ H(N ∥ P)), computed by the node. | is stored at `addr = H(DSM/storage-object | DSM-HL-011/L772 | none |
| STOR-005/L117 | obligation | explicit | A caller-supplied address is checked against the computed one and never used as the key. | A caller-supplied address is checked against the computed one and never used as the key. | — | none |
| STOR-005/L118 | invariant | explicit | There is no update or overwrite path; the path is absent, not a path that refuses. | There is no update path and no overwrite path. | — | none |
| STOR-005/L119 | obligation | explicit | Identical replays are re-acknowledged; different bytes at the same address are reported as corruption. | Replaying identical bytes re-acknowledges. | — | none |
| STOR-005/L120 | obligation | explicit | On read the node recomputes the address before serving, and the client re-hashes regardless. | On read, the node recomputes the address before serving. | — | none |
| STOR-005/L121 | invariant | explicit | Stored(o) holds when three members of S return the exact bytes of o. | holds when three members of `S` return the exact bytes of | SOFI-010/L646 | none |

### STOR-006 — 6 Keyed cells

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-006/L128 | obligation | explicit | Put at a key stores the writer's bytes after everything already held there. | Put at a key stores the bytes a writer sends for that key after everything already held there. | — | none |
| STOR-006/L129 | obligation | explicit | Get returns everything held at a key in arrival order, or that it holds none. | Get returns everything held at the key, in the order it arrived, or that it holds none. | — | none |
| STOR-006/L130 | prohibition | explicit | No member refuses, replaces or compares anything held at a key, except that a node may refuse a write addressed to an account that has not met the spend-gate; there is no write authorization. | No member refuses, replaces or compares anything held at a key, except that a node MAY refuse | DSM-HL-011/L758 | none |
| STOR-006/L131 | obligation | explicit | Any party may carry bytes to members not yet reached. | Any party MAY carry bytes to members not yet reached. | — | none |

### STOR-007 — 7 Indexes

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-007/L138 | obligation | explicit | Anyone may append a held object's content address under any locator; appends are never removed, reads return append order paged, and the member interprets nothing. | Anyone MAY append the content address of an object the member already holds under any locator. | SOFI-011/L656 | none |

### STOR-008 — 8 Mirror, spool, and identity storage

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-008/L145 | obligation | explicit | The tip mirror holds a public head and encrypted per-relationship leaves keyed by device and relationship. | A public head and encrypted per-relationship leaves, keyed by device and relationship. | — | none |
| STOR-008/L146 | obligation | explicit | The inbox spool delivers unilaterally to an offline counterparty; envelopes are strictly versioned, insertion ordered, acknowledged per routing key, and never opened by the node. | Unilateral delivery to an offline counterparty. | — | none |
| STOR-008/L147 | dependency-boundary | explicit | Identity and recovery storage (genesis anchoring, device-tree indexing, recovery capsules) is imported as substrate; recovery is out of scope. | Recovery is out of scope for this round | — | none |
| STOR-008/L151 | invariant | explicit | Nothing can be sent to a party that has not pre-established the sender as a contact; relationships are created by mutual pre-add, never by first contact. | Nothing can be sent to a party that has not pre-established the sender as a contact. | DSM-HL-011/L788 | none |
| STOR-008/L153 | invariant | explicit | A message is sent to a relationship, addressed by its chain id (the hash of the two device ids), never to a genesis account. | A message is sent to a relationship, never to a genesis account. | — | none |
| STOR-008/L154 | obligation | explicit | The sender's device sends only over a relationship it has pre-added. | The sender's device sends only over a relationship it has pre-added. | — | none |
| STOR-008/L155 | obligation | explicit | The recipient's device reads only relationships it has pre-added and accepts a message only if signed by the other device of that relationship. | The recipient's device reads only relationships it has pre-added | — | none |
| STOR-008/L156 | obligation | explicit | The DSM §11 envelope checks are performed by the devices at both ends. | are performed by the devices at both ends. | — | none |
| STOR-008/L160 | prohibition | explicit | The node never verifies who is writing, not even that the writer is one of the relationship's devices, because a node that can check can block; bytes written under a never-pre-added relationship are never read and are accepted. | The node does not verify who is writing | — | none |

### STOR-009 — 9 Leader and finality

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-009/L167 | authority | explicit | The writer and Core compute a cell's leader with SoFi's shuffle; a node never computes one and does not know which cells it leads. | The writer and Core compute a cell's leader as | — | none |
| STOR-009/L168 | invariant | explicit | A leader seed derives from committed state only; availability, caller identity and node ids never enter it. | The seed `s` is derived from committed state only. | — | none |
| STOR-009/L169 | invariant | explicit | The set a cell's leader is drawn from is the set committed in the state that seeds the cell; an offline member is still in it. | is the storage set committed in the state that seeds the cell. | — | none |
| STOR-009/L170 | prohibition | explicit | A verifier reads a cell only after every check decidable from evidence in hand has passed; an Invalid transition never causes a storage read. | A verifier reads a cell only after every check it can decide from evidence already in hand has passed. | DSM-HL-009/L558 | none |
| STOR-009/L174 | invariant | explicit | Final(K, x) holds iff x is the first object naming K at the leader and at least two other members hold x; Core evaluates it from raw reads, never a node. | x is the first object naming K at the leader | SOFI-008/L602 | none |
| STOR-009/L177 | invariant | explicit | A value the leader does not hold is never final, and at most one value is final at a cell. | A value the leader does not hold is never final. | — | none |
| STOR-009/L179 | liveness-boundary | explicit | If the leader is unreachable the cell waits; no other member stands in. | If the leader is unreachable, the cell waits. No other member stands in. | — | none |
| STOR-009/L183 | invariant | explicit | A cell's leader is a function of the set committed when the cell was seeded and is never re-derived over a later set, registry or binding. | It MUST NOT be re-derived over any later set, registry, or binding. | — | none |

### STOR-009-1 — 9.1 Pending challenges counted in the leader's ByteCommits

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-009-1/L190 | transition | explicit | When a result is pending on one party, any party may write a challenge to the pending cell's leader; the challenged party answers with the missing piece, or a drop claim competes, and the first to reach the leader wins. | any party MAY write a challenge to the pending cell's leader | — | none |
| STOR-009-1/L193 | invariant | explicit | A drop claim counts only if the leader's ByteCommit chain shows at least X ByteCommits closed after the first one including the challenge. | A drop claim counts only if the leader | — | none |
| STOR-009-1/L194 | invariant | explicit | Once a drop claim wins, the pending result is dropped for every verifier and later evidence for it is ignored; in SoFi a dropped trade is Void. | Once a drop claim wins, the pending result is dropped for every verifier | SOFI-024/L1560 | none |
| STOR-009-1/L195 | liveness-boundary | explicit | If the leader is unreachable its chain does not advance, the deadline does not arrive, and the cell waits. | If the leader is unreachable, its chain does not advance and the deadline does not arrive. | — | none |
| STOR-009-1/L196 | invariant | explicit | A challenge applies only where the missing piece can come from the challenged party alone; anything a relayer can complete is completed by relaying. | A challenge applies only where the missing piece can come from the challenged party alone. | — | none |

### STOR-010 — 10 Storage sets

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-010/L213 | invariant | explicit | A storage set is five member ids committed in state, identified by storage_set_id over member ids only, never endpoints. | A storage set is five member ids committed in state | SOFI-006/L508 | none |
| STOR-010/L214 | invariant | explicit | A vault's set is the network's pinned set, and vault genesis is accepted only if its storage_set_id equals it. | A vault's set is the network's pinned set. | SOFI-019-8/L1291 | none |
| STOR-010/L218 | invariant | explicit | Every party has its own storage set for its own objects and cells: traders' to the trader's set, an owner's to the owner's set. | Every party has its own storage set for its own objects and cells. | — | none |
| STOR-010/L219 | authority | explicit | A party's set is assigned from the active registry by Fisher–Yates; the party never chooses a member. | A party's set is assigned from the active registry by Fisher–Yates. | — | tension(DSM-HL-063/L3100) |
| STOR-010/L220 | obligation | explicit | A party may opt out of a member; the replacement is drawn by Fisher–Yates and may itself be a poor performer. | A party MAY opt out of a member. | — | none |
| STOR-010/L221 | obligation | explicit | A party pays for storage with credits. | A party pays for storage with credits (§17). | — | none |
| STOR-010/L223 | invariant | explicit | Open: where the economic-root register's owner-committed set is committed in device state is not specified. | Where that set is committed in device state is not specified. | — | ambiguous |

### STOR-011 — 11 Member ids are seats

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-011/L230 | invariant | explicit | A member id names a seat: a stable logical position with its ordered memory (every key's arrival log and every immutable object under it). | names a **seat** | — | none |
| STOR-011/L231 | invariant | explicit | A seat is served by one operator at a time, and which operator occupies it is not committed in any party's state. | A seat is served by one operator at a time | — | none |
| STOR-011/L232 | invariant | explicit | A committed set never changes; every cell's leader is a seat and is fixed forever, whichever machine occupies it. | Once `S` is committed, it never changes. | STOR-009/L183 | none |
| STOR-011/L233 | invariant | explicit | Open: operator endpoints are resolved outside committed state; whether by network configuration or a committed object is undecided. | Operator endpoints are resolved outside committed state. | — | ambiguous |

### STOR-011-1 — 11.1 Two separate Fisher–Yates selections

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-011-1/L244 | invariant | explicit | Seat assignment (which operator occupies a seat, drawn from the registry) and leader selection (which seat leads a cell, drawn from the five seats) share the Fisher–Yates primitive and nothing else. | Fisher–Yates is used for two unrelated purposes. | — | none |
| STOR-011-1/L254 | obligation | explicit | The two selections use distinct domain tags for their seeds and draw functions (seat-bind/v1, rebind/v1 and seat-fy-prf/v1 for assignment; SoFi's seeds and fy-prf/v1 for leaders), so neither can influence the other. | The two selections MUST use distinct domain tags for their seeds and for their draw functions | — | none |
| STOR-011-1/L255 | invariant | explicit | Replacing the operator in a seat leaves the seat and every cell it led unchanged. | Seat assignment never changes a leader | — | none |
| STOR-011-1/L256 | prohibition | explicit | Leader selection never reads which operator occupies a seat. | Leader selection never reads which operator occupies a seat. | — | none |

### STOR-012-1 — 12.1 Initial binding

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-012-1/L279 | transition | explicit | At set creation each seat is bound to an operator drawn by seat assignment with seed H(DSM/storage/seat-bind/v1; creating state commitment ∥ seat), excluding operators already seated. | When a set is created, each seat is bound to an operator | — | none |

### STOR-012-2 — 12.2 Retirement triggers

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-012-2/L291 | authority | explicit | A seat's binding ends only by the owning party's opt-out (party sets only, never a vault's pinned set) or a network cut for under-performance; no owner action is ever required for a cut, and there is no other trigger. | No owner action is ever required for a network cut. There is no other trigger. | — | none |

### STOR-012-3 — 12.3 Retirement records

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-012-3/L298 | invariant | explicit | A retirement is an immutable record naming one or two seats of a set and, per seat, handover or loss; a network cut's record is the registry successor removing the operator. | A retirement is recorded as an immutable object naming **one or two** seats | — | none |
| STOR-012-3/L299 | invariant | explicit | A record's survivors are the seats it does not name; it is effective once every survivor's current operator holds it (every survivor, not a count). | A record is **effective** once every survivor's current operator holds it. | — | none |
| STOR-012-3/L300 | transition | explicit | A record never waits on a seat it names; if a survivor is unreachable and to be replaced, a new record naming both seats is issued, and records only add. | A record never waits on a seat it names. | — | none |
| STOR-012-3/L303 | evidence | explicit | A verifier that finds a record at none of the members it read proceeds as if no such record is effective; one that finds it anywhere must confirm it at every survivor or wait, never proceeding as if it were not effective. | It MUST NOT proceed as though the record were not effective. | — | none |
| STOR-012-3/L304 | liveness-boundary | explicit | Three or more seats out at once is outside the model: no cell can advance, the set waits, and safety is unaffected. | **More than two seats out at once is outside the model.** | — | none |
| STOR-012-3/L308 | theorem | explicit | Retirement convergence: with at most two seats named, every finality read touches a survivor, so no two verifiers act on different occupants of one seat. | A record names at most two seats, so every finality read touches at least one survivor. | — | none |

### STOR-012-4 — 12.4 Rebinding

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-012-4/L319 | obligation | explicit | A replacement is drawn by seat assignment from the registry, excluding seated operators. | The replacement operator is drawn by the seat-assignment selection (§11.1) from the active registry | — | none |
| STOR-012-4/L320 | prohibition | explicit | The rebind seed must not be computable by the party before the retirement is effective; it is H(DSM/storage/rebind/v1; role ∥ H(record) ∥ D), with D the survivors' first ByteCommit digests that include the record. | The seed MUST NOT be computable by the party before the retirement is effective. | — | none |
| STOR-012-4/L321 | invariant | explicit | Under per-write credits opting out carries no payment; the unpredictable seed is the defence against steering a seat by repeated opt-outs, and whether opting out should cost anything is open. | Under per-write credits, opting out carries no payment. | — | ambiguous |

### STOR-012-5 — 12.5 Handover

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-012-5/L328 | obligation | explicit | A live retiring operator must transfer the role's full memory (every key's arrival log in order and every immutable object) to the new operator. | When a retiring operator is live, it MUST transfer the role's memory to the new operator | — | none |
| STOR-012-5/L329 | obligation | explicit | The new operator's commitments for the role continue from the retiring operator's last ByteCommit covering it, so reordering during handover is detectable. | The new operator's commitments for the role MUST continue from the retiring operator's last ByteCommit | — | none |
| STOR-012-5/L330 | liveness-boundary | explicit | Until handover completes, the retiring operator serves the role, and its stake is not released until every role it served is handed over. | Until handover completes, the role is served by the retiring operator. | — | none |
| STOR-012-5/L335 | obligation | explicit | An operator must durably replicate a role's memory before acknowledging a write to that role. | An operator MUST durably replicate a role's memory before a write to that role is acknowledged. | — | none |

### STOR-012-6 — 12.6 Loss

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-012-6/L342 | transition | explicit | If a role's memory is lost without handover, the record carries a loss marker, and each survivor records it in its own ordered memory; material held before it is pre-loss material. | If a role's memory is lost with no handover, the retirement record carries a loss marker. | — | none |
| STOR-012-6/L344 | transition | explicit | For a cell whose leader role was lost, the claims held pre-loss by at least two survivors decide it: none means nothing was realized and the new operator leads; one is the winner; two or more freeze the cell with no winner. | and resolves `K` as follows: | — | none |
| STOR-012-6/L352 | prohibition | explicit | For a cell with qualifying pre-loss material, the new operator's arrival log is never used as the leader's order. | the new operator's arrival log MUST NOT be used as the leader's order | — | none |
| STOR-012-6/L356 | theorem | explicit | The survivor rule never contradicts a pre-loss final result; it resolves to it or freezes the cell, and freezing requires the signer to have equivocated. | If `Final(K, x)` held before the loss | — | none |
| STOR-012-6/L358 | invariant | explicit | Open: the consequences of a frozen cell for DSM, SoFi and dBTC, and whether it triggers the tripwire, are undecided. | What a frozen cell means for DSM acceptance, SoFi resolution, and dBTC | — | ambiguous |

### STOR-013 — 13 The operator registry

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-013/L368 | invariant | explicit | The active registry is the sorted list of operator ids, stored as an immutable object, advancing by a pure function of the prior registry and hash-referenced capacity, performance and applicant evidence. | The registry advances by a pure function of the prior registry and input objects referenced by hash | — | none |
| STOR-013/L369 | transition | explicit | Each registry successor is a keyed cell on the network's pinned set keyed by the prior registry's address; anyone may write a candidate, non-recomputing objects are not candidates, and the first candidate at the leader wins under the ordinary finality rule. | Each registry successor is a keyed cell on the network's pinned set | — | none |
| STOR-013/L370 | prohibition | explicit | Pruning is computed from committed evidence only; locally measured latency or uptime never enters it. | Pruning MUST be computed from committed evidence only | — | none |
| STOR-013/L371 | invariant | explicit | Growth selects new operators by the salted applicant ranking anchored in the genesis commit-reveal, so no party can bias selection. | Growth selects new operators by the salted applicant ranking | — | none |
| STOR-013/L372 | invariant | explicit | A new operator's grace period from pruning is counted in ByteCommit cycles, never in time. | A new operator is protected from pruning for a grace period counted in ByteCommit cycles | — | none |
| STOR-013/L373 | authority | explicit | An operator below the performance bar is never admitted and is cut when it falls below it; cadence regularity is part of the score. | an operator that does not meet the performance bar is never admitted | — | none |
| STOR-013/L375 | invariant | explicit | Open: which performance measures are expressible over committed evidence is undecided. | Which performance measures are expressible over committed evidence is not decided here. | — | ambiguous |

### STOR-014 — 14 ByteCommit

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-014/L382 | obligation | explicit | Each cycle a node emits an unsigned ByteCommit with its node id, a cycle counter (never time), the SMT root over what it holds, bytes used, and the previous digest; it is stored under a deterministic address and mirrored. | Each cycle, a node emits an unsigned ByteCommit | — | none |
| STOR-014/L384 | evidence | explicit | A verifier checks a ByteCommit's chain link and root itself; it is never accepted by counting mirrors. | A verifier checks the chain link and the root itself. | — | none |
| STOR-014/L385 | evidence | explicit | Up and Down capacity signals reference windows of accepted ByteCommits and are checked against them. | Up and Down capacity signals reference windows of accepted ByteCommits | — | none |
| STOR-014/L389 | obligation | explicit | Each keyed-cell entry is committed with its per-key arrival index, so handover and pre-loss partitioning are checkable. | Each keyed-cell entry is committed with its per-key arrival index | — | none |

### STOR-015 — 15 Stake and exit

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-015/L397 | invariant | explicit | An operator stakes through a stake DLV, which unlocks only on a mirrored DrainProof of two consecutive accepted ByteCommits with zero bytes used. | The stake unlocks only when a DrainProof is mirrored | — | none |
| STOR-015/L401 | theorem | explicit | Because retention never depends on payment, an operator's memory empties only after every role is handed over, so a DrainProof proves completed handover and a refusing operator never recovers its stake. | A DrainProof therefore proves completed handover | — | none |

### STOR-016 — 16 The PaidK spend-gate

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-016/L412 | invariant | explicit | A device is receive-only after genesis until it has paid a flat rate to three distinct operators; spending is then enabled permanently with no renewal. | A device is receive-only after genesis until it has paid a flat rate to K = 3 distinct storage operators. | DSM-HL-011/L808 | none |
| STOR-016/L414 | authority | explicit | A node enforces the spend-gate itself: it stores the device-signed receipts, counts distinct operators, and may refuse writes addressed to a device that has not met it. | A node enforces the gate itself | — | none |
| STOR-016/L415 | dependency-boundary | explicit | PaidK is also the join event driving DJTE, evaluated by verifiers over the same receipts; emissions are out of scope. | is also the join event that drives DJTE | — | none |

### STOR-017 — 17 Subscriptions

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-017/L422 | invariant | explicit | Storage is paid on-chain with credits, a balance leaf in the party's own committed state. | Storage is paid on-chain with credits. | DSM-HL-062/L2962 | none |
| STOR-017/L423 | invariant | explicit | The credit price is fixed in token units as a committed network parameter and charged by storage actually used; operators do not set prices and compete on performance. | The credit price is fixed in token units as a committed network parameter | — | none |
| STOR-017/L424 | transition | explicit | A sender-authored, state-advancing transition consumes the credits for its storage inside that transition, and the receiver checks the debit as part of acceptance; receiving never debits. | consumes the credits for the storage it uses, inside that transition | — | none |
| STOR-017/L425 | transition | explicit | Credits are refilled by paying operators, with the payment receipts as evidence, through the spend-gate path. | Credits are refilled by paying operators. | — | none |
| STOR-017/L426 | prohibition | explicit | Credits are counted in storage used, never in time, so no clock enters any protocol path. | Credits are counted in storage used, never in time | — | none |
| STOR-017/L427 | liveness-boundary | explicit | A party with exhausted credits cannot act, which is liveness only, never invalidity; before acting the client checks its own balance. | A party whose credits are exhausted cannot act. | — | none |
| STOR-017/L428 | liveness-boundary | explicit | Paying and getting through are separate: a write goes through once the cell's leader and two others hold it. | Paying and getting through are separate | — | none |
| STOR-017/L432 | authority | explicit | A node may refuse a write addressed to an account that has not met the spend-gate; whether nodes also refuse exhausted-credit writes is open. | A node MAY refuse a write addressed to an account that has not met the spend-gate (§16). | — | ambiguous |
| STOR-017/L433 | prohibition | explicit | Any refusal is keyed on the addressed account, never the connected writer, so relayers are admitted and the node never checks the writer. | Any refusal is keyed on the account the write is addressed to, never on who is connected. | — | none |
| STOR-017/L434 | prohibition | explicit | Refusal never applies to DLVs and never depends on payload content or what else is held at a key. | Refusal never applies to DLVs (§18) | — | none |
| STOR-017/L435 | invariant | explicit | A refusal is indistinguishable from unavailability: liveness only, never validity; it can stall only the cells the refusing node leads, until opt-out or cut. | a refusal is indistinguishable from unavailability | — | none |

### STOR-018 — 18 DLV exemption

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-018/L443 | obligation | explicit | Creating a DLV consumes the creator's credits like any write. | Creating a DLV consumes the creator's credits like any write. | — | none |
| STOR-018/L444 | invariant | explicit | After creation, a DLV's objects, cells and writes to them never depend on anyone's credits or payment, the owner's included, and a lapse never removes or cancels a DLV. | never depend on anyone's credits or payment, the owner's included | — | none |
| STOR-018/L446 | authority | explicit | A DLV's storage set is the network-pinned set, and its succession is driven by the network, never by the owner. | its succession is driven by the network (§12.2), never by the owner | — | none |

### STOR-019 — 19 Retention

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-019/L453 | prohibition | explicit | A node must not delete, expire or age out held bytes because of lapsed payment, owner inactivity or owner death; the only way a role's memory empties is handover. | A node MUST NOT delete, expire, or age out held bytes | — | none |
| STOR-019/L455 | prohibition | explicit | Reads for verification cost no credits; receiving value and verifying provenance cost the reader nothing. | Reads for verification cost no credits. | — | none |
| STOR-019/L456 | obligation | explicit | Pruning is by a sliding window of logical age (positions, generations or ByteCommit cycles, never time); nothing is pruned until the window and exemptions are specified, and no rule may make a claimed slot read as empty or prune live DLV or dBTC backing material. | **Pruning (Owner direction; Open).** | — | ambiguous |

### STOR-020 — 20 Owner independence

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-020/L463 | invariant | explicit | No safety property, and no party's liveness other than the owner's own, depends on the owner continuing to exist: retention is not tied to owner activity, operator exit is by handover, and retirement, the survivor rule and frozen-cell consequences are verifier rules, never owner actions. | No safety property, and no party's liveness other than the owner's own, may depend on the owner continuing to exist. | DBTC-SPEC-25/L1324 | none |

### STOR-021 — 21 Repair

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-021/L478 | obligation | explicit | After a prune or exit, any client may restore missing replicas of immutable objects, accepted by hash only. | any client MAY restore missing replicas of immutable objects | — | none |
| STOR-021/L479 | invariant | explicit | Keyed-cell arrival order is not repairable by clients; it moves only by handover and, if lost, the cell is resolved by the loss rule. | Keyed-cell arrival order is not repairable by clients. | — | none |

### STOR-022 — 22 Proof obligations

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-022/L490 | proof-obligation | explicit | History invariance: a handover changes no LeaderHeld or Final fact for any cell. | History invariance: a handover changes no | — | none |
| STOR-022/L491 | proof-obligation | explicit | Survivor-rule soundness: the loss rule never selects a value other than the pre-loss final value and freezes only when two survivor-held objects name one cell. | Survivor-rule soundness: under §3 | — | none |
| STOR-022/L492 | proof-obligation | explicit | Retirement convergence: with at most two seats named per record, no two verifiers act on different occupants of one seat. | Retirement convergence: with at most two seats named per record | — | none |
| STOR-022/L493 | proof-obligation | explicit | Registry determinism: verifiers holding the same winning candidate and inputs compute the same registry. | Registry determinism: any two verifiers holding the same winning registry candidate | — | none |
| STOR-022/L494 | proof-obligation | explicit | Rebind unpredictability: the party cannot compute the rebind seed before its retirement is effective. | Rebind unpredictability: the party cannot compute | — | none |
| STOR-022/L495 | proof-obligation | explicit | Leader immutability: no binding, registry or retirement event changes the leader of any committed cell. | Leader immutability: no binding, registry, or retirement event changes | — | none |

---

## Findings

Findings 4–6 record owner direction given in chat on 2026-09-22. They are not extracted requirements. They need spec text before they bind.

| # | Type | IDs | Finding |
|---|---|---|---|
| 1 | tension | DSM-HL-005/L290, SOFI-001-5/L332 | **Resolved, owner ruling: three-valued Accept withdrawn.** Acceptance stays binary: a transition satisfies the full predicate or does not execute. Fetching and retrying evidence belong to the network layer beneath the protocol; Unavailable is that layer's status and never a predicate value, and nothing is marked Invalid while it is still being retried. Applied as DSM Amendment A1 and SoFi Amendments S1 and S3. |
| 2 | tension | DSM-HL-011/L747.b, DSM-HL-011/L788, DSM-HL-011/L808, SOFI-009/L631 | **Resolved: DSM Amendments A2, A3.** The node "never refuses a value", yet §11 gives it spool admission gates and a spend-gate that counts operator receipts, and SoFi §9 says anyone may write. Proposed resolution: name admission as a carve-out. It is content-blind, never depends on what else the node holds for the same key, and to the protocol a refusal is indistinguishable from unavailability (liveness, never validity). Replay-protected ids apply to the spool only, never to keyed cells. The spend-gate (one-time, protocol-level, feeds emissions) must be distinguished in the spec from the monthly subscription (finding 6). |
| 3 | ambiguity | DSM-HL-009/L529, DSM-HL-012/L937 | **Resolved: DSM Amendment A4 (authenticate first, then read the register, then the other checks).** Register-read order. Proposed resolution: keep Figure 2. Leader derivation needs the validated previous root, so authentication must precede the read. Reword §9 to "before any precommitment, guard, linearity or policy check". State that the verdict is order-independent, and that the only binding order rule is: no storage read before the presentation is authenticated. |
| 4 | scope (blocking) | DSM-HL-080/L3998, SOFI-006/L506, SOFI-006/L527, SOFI-046/L2376, DSM-HL-011/L821 | **Resolved: accepted as `DSM_Storage_Node_Specification.md` Part III.** **Storage-set succession is unspecified.** DSM assumes durable member memory "including after storage migration"; SoFi freezes membership per vault and reserves `membership-handover/v1`. A historical coordinate's leader is fixed by the set committed at creation and must never be re-derived over a later set. Succession cannot be an owner transition: the owner may be offline or dead, and the transition would itself need a cell possibly led by the lost member. Proposed direction: (a) member ids are durable roles (slot plus ordered log), and S in committed state never changes; (b) planned retirement is a role handover beneath S, with the log moving with the id and the ByteCommit chain continuing; (c) a write counts as held by the leader only once the role log is replicated; (d) permanent loss is an irrevocable loss marker recorded in each survivor's own ordered log. For pre-loss material, a claim held by ≥2 survivors is a candidate: one candidate resolves the cell (provably never contradicts a final result), and two or more mean provable equivocation and the cell is frozen. After loss, the new role machine leads only cells with no qualifying pre-loss material. Open for owner: endpoint resolution (network config vs committed) and whether frozen cells trigger the tripwire. Also a gap: where the device register's committed set lives in device state is unspecified. |
| 5 | requirement (owner) | DBTC-SPEC-25/L1324, SOFI-019-7/L1275 | **Recorded in the storage spec §20.** **Owner independence.** No safety property, and no party's liveness other than the owner's own, may depend on the owner continuing to exist. dBTC Property 25.1 and SoFi's absent LP already follow this; owner-only Close (§19.7) affects only the owner's own funds. Consequences: storage retention is never tied to owner activity; operator exit is by role handover, never by dropping held cells; frozen-cell resolution and the tripwire are verifier rules, never owner actions. |
| 6 | requirement (owner) | DSM-HL-011/L808 | **Recorded in the storage spec §16–§19 and DSM Amendment A2.** **Storage fees.** Not in the pinned corpus. Monthly subscription, per node, off-chain, with competitive pricing chosen per operator. Each party pays for its own nodes: traders' objects go to traders' nodes, the owner's to the owner's. DLVs are exempt: creating one requires paid-up storage, but after creation a DLV and writes to it never depend on anyone's subscription, and lapse never removes one. Retention of anything others rely on never depends on payment. A party below its redundancy threshold simply cannot act; that is liveness only, and a lapse mid-trade is a stall (Pending), never an invalidity. Because finality needs each cell's leader and the leader is unpredictable, the threshold is effectively every member of the party's committed set. **Subscription checks stay entirely outside Core and outside the node's clock-free protocol path**, because a month is clock time. The client-side check is an SDK/app-layer precondition against status reported by each node, never a local flag. This must be distinguished in the spec from the one-time spend-gate. |
| 7 | requirement (owner) | — | **Resolved: superseded by `DSM_Storage_Node_Specification.md`.** **Legacy storage-node spec as a source.** `.github/instructions/storagenodes.instructions.md` (Oct 2025) is not in the pinned corpus. Owner direction: its mechanisms may be adopted where useful, and the pinned specs win on conflict. Candidates for finding 4: (a) the registry add/prune rule, a pure function of committed inputs (ByteCommit-referenced Up/Down signals), as the shape of the no-vote performance cut; (b) salted applicant ranking plus the genesis commit-reveal pattern for fair entry, and for an opt-out redraw seed the party cannot predict; (c) hash-only client-written repair for immutable objects on prune or exit; (d) stake DLV plus DrainProof: a node can only drain after handing over its leader roles, so stake release becomes the incentive for cooperative handover; (e) cycle counters, not time, for performance windows and new-operator grace. Not adopted (conflict with pinned specs): "no leaders"; node MUST-reject rules; N=6/K=3 per-object global placement; ByteCommit acceptance by mirror count; its Fisher–Yates variant (SoFi §7.1 governs); the DLVCreateV3/OpenV3 model. Also: its `applyTo: '**'` frontmatter may make other agents treat it as binding during extraction. |
| 8 | tension | DSM-HL-062/L2962, STOR-017/L422 | **Resolved: owner ruling, credits adopted at a fixed network price per storage used; subscription removed (storage spec §17, PR #967).** DSM §62's aside prices storage traffic with prepaid credit bundles (one credit per accepted sender-authored transition, refills through the spend-gate, receiving never debits). The storage spec (§17, owner decision) prices storage by an off-chain monthly subscription per node. Either the credit model is superseded, or the two coexist with a stated division (for example, credits as the protocol-level spam floor and subscriptions as the operators' commercial price). |
| 9 | tension | DSM-HL-063/L3100, STOR-010/L214 | **Resolved: DSM Amendment A5, the vault set is assigned, never chosen (PR #967).** DSM §63 describes a vault's storage set as owner-chosen ("The LP commits a storage-member set S"; "an owner-chosen storage set"). SoFi §6 and the storage spec §10 make a vault's set the network-pinned set, and the owner's rule is that no party chooses its members. DSM §63's wording should be amended to match, or the rule stated differently. |
| 10 | tension | SOFI-005-3/L471, SOFI-054/L2587 | **Resolved: SoFi notes added (PR #967).** Two SoFi statements are superseded but unamended. §5.3 says a registered fulfillment MAY stay Pending forever, while Amendment S1 lets a pending position end through the challenge rule (it then resolves Void). The closing section "What remains open" says nothing is open and that member replacement is not part of this work, while the storage spec now specifies it. Both should carry an amendment or note pointing to S1 and to the storage spec. |
---

## Coverage

| Anchor | Line | Title | Status |
|---|---|---|---|
| DSM-PRE | 1 | Front matter; Abstract | restated-only: abstract summarises Parts I–II |
| DSM-HL-001 | 59 | 1 The Central Question | extracted (2) |
| DSM-HL-001-1 | 88 | 1.1 Candidate Futures Versus Realized Futures | extracted (1) |
| DSM-HL-002 | 117 | 2 The Entire DSM Idea in One Diagram | no-normative-content: overview diagram of the cycle; formalised in §5 and Part II |
| DSM-HL-003 | 154 | 3 Six Answers Before the Mathematics | restated-only: summary table; each answer extracted where earned (DSM-HL-009, DSM-HL-011) |
| DSM-HL-004 | 181 | 4 The Two Halves of an Agreement | extracted (9) |
| DSM-HL-005 | 265 | 5 The Six Questions Every Transition Must Answer | extracted (6) |
| DSM-HL-006 | 305 | 6 DSM Does Not Need Global Ordering | extracted (2) |
| DSM-HL-007 | 346 | 7 Concrete Double-Spend Example | excluded: example (restates DSM-HL-004/L247) |
| DSM-HL-008 | 384 | 8 Both Candidates Can Look Valid | extracted (2) |
| DSM-HL-009 | 454 | 9 Same Balance, Two Counterparties | extracted (23) |
| DSM-HL-010 | 663 | 10 A Transition Cannot Cross Relationships | extracted (3) |
| DSM-HL-011 | 736 | 11 Storage Nodes | extracted (40) |
| DSM-HL-012 | 900 | 12 Online DSM | extracted (2) |
| DSM-HL-013 | 961 | 13 DSM Is Not a Payment Channel | extracted (2) |
| DSM-HL-014 | 1020 | 14 Determinism | extracted (3) |
| DSM-HL-014-1 | 1051 | 14.1 Determinism Is Broader Than Arithmetic | extracted (1) |
| DSM-HL-015 | 1097 | 15 Canonical Encoding | extracted (2) |
| DSM-HL-015-1 | 1121 | 15.1 Canonical Equality | extracted (2) |
| DSM-HL-015-2 | 1135 | 15.2 Why This Matters Everywhere | extracted (1) |
| DSM-HL-016 | 1173 | 16 Domain Separation | extracted (1) |
| DSM-HL-017 | 1189 | 17 Cryptographic Hashes | extracted (1) |
| DSM-HL-018 | 1209 | 18 Forward-Only Hash Chaining | extracted (2) |
| DSM-HL-019 | 1232 | 19 Bilateral Relationships | extracted (2) |
| DSM-HL-020 | 1280 | 20 Relationship State as a Vector | restated-only: formalised in DSM-HL-021 |
| DSM-HL-021 | 1294 | 21 Relationship Projections | extracted (1) |
| DSM-HL-022 | 1339 | 22 Why Bilateral State Matters | extracted (1) |
| DSM-HL-023 | 1364 | 23 Why a Device Needs a Compact Commitment | extracted (1) |
| DSM-HL-024 | 1379 | 24 Ordinary Merkle Trees | no-normative-content: Merkle-tree primer; the rule is DSM-HL-027 |
| DSM-HL-025 | 1419 | 25 Sparse Merkle Trees | extracted (1) |
| DSM-HL-026 | 1463 | 26 Relationship Keys | extracted (2) |
| DSM-HL-027 | 1506 | 27 Updating One SMT Leaf | extracted (1) |
| DSM-HL-028 | 1540 | 28 Merkle Proofs | extracted (2) |
| DSM-HL-029 | 1603 | 29 The DSM State Object | extracted (9) |
| DSM-HL-030 | 1657 | 30 The Layered Root | extracted (4) |
| DSM-HL-031 | 1703 | 31 Canonical State Chaining | extracted (2) |
| DSM-HL-032 | 1736 | 32 Bitcoin Chain Versus DSM State Chain | extracted (1) |
| DSM-HL-033 | 1754 | 33 Logical Generations | extracted (1) |
| DSM-HL-034 | 1767 | 34 Precommitment | extracted (1) |
| DSM-HL-035 | 1781 | 35 Candidate Structure | extracted (3) |
| DSM-HL-036 | 1835 | 36 Candidate Forks Are Allowed | extracted (2) |
| DSM-HL-037 | 1857 | 37 Precommitment Chaining | extracted (3) |
| DSM-HL-038 | 1908 | 38 Guards | extracted (3) |
| DSM-HL-039 | 1945 | 39 Guard Families | extracted (1) |
| DSM-HL-040 | 1973 | 40 Guards Alone Are Not the Exclusion Mechanism | extracted (2) |
| DSM-HL-041 | 2002 | 41 Linear Resources | extracted (1) |
| DSM-HL-042 | 2026 | 42 Resource Descriptors | extracted (2) |
| DSM-HL-043 | 2036 | 43 Resource-Consumption Keys | extracted (2) |
| DSM-HL-044 | 2086 | 44 Why Branch-Specific Exclusion Keys Would Be Wrong | extracted (2) |
| DSM-HL-045 | 2104 | 45 Conflict Classes | extracted (1) |
| DSM-HL-046 | 2115 | 46 The Consumed Set | extracted (2) |
| DSM-HL-047 | 2148 | 47 The Consumed Set Can Also Be an SMT | extracted (1) |
| DSM-HL-048 | 2166 | 48 Bitcoin UTXOs Versus DSM Linear Resources | restated-only: comparison; the generalised statement is DSM-HL-041 and Theorem 1 (DSM-HL-052) |
| DSM-HL-049 | 2206 | 49 The Complete Realization Predicate | extracted (1) |
| DSM-HL-050 | 2221 | 50 Potential and Realized Morphisms | no-normative-content: interpretive framing of DSM-HL-049 |
| DSM-HL-051 | 2237 | 51 Realized Histories | extracted (2) |
| DSM-HL-052 | 2251 | 52 The Core Uniqueness Theorem | extracted (4) |
| DSM-HL-053 | 2327 | 53 Tripwire | extracted (1) |
| DSM-HL-054 | 2372 | 54 Safety and Liveness | extracted (1) |
| DSM-HL-055 | 2400 | 55 Concurrency Without Global Ordering | extracted (1) |
| DSM-HL-056 | 2435 | 56 Token Conservation | extracted (1) |
| DSM-HL-057 | 2483 | 57 Why Conservation Is Not Enough | extracted (1) |
| DSM-HL-058 | 2507 | 58 Deterministic Limbo Vaults | extracted (2) |
| DSM-HL-059 | 2554 | 59 Smart Commitments | extracted (6) |
| DSM-HL-060 | 2659 | 60 Multi-Party Workflows Through External Commitments | extracted (4) |
| DSM-HL-061 | 2734 | 61 CPTA and Deterministic Policy | extracted (7) |
| DSM-HL-062 | 2847 | 62 Deterministic Emissions (DJTE) | extracted (7) |
| DSM-HL-063 | 2969 | 63 Sovereign Finance (SoFi) | extracted (19) |
| DSM-HL-064 | 3110 | 64 dBTC: Bitcoin as a DSM Asset | extracted (15) |
| DSM-HL-065 | 3329 | 65 Recovery as a Linear Generation | extracted (1) |
| DSM-HL-066 | 3353 | 66 Offline Bearer DSM | extracted (1) |
| DSM-HL-067 | 3367 | 67 Offline Origin | excluded: out of scope (offline); boundary recorded at DSM-HL-066 |
| DSM-HL-068 | 3406 | 68 The Committed Software Counter | excluded: out of scope (offline/hardware); boundary recorded at DSM-HL-066 |
| DSM-HL-069 | 3418 | 69 Hardware Counter Versus Software Authority | excluded: out of scope (offline/hardware); boundary recorded at DSM-HL-066 |
| DSM-HL-070 | 3442 | 70 The Observer Model, Inverted | excluded: out of scope (offline/hardware); boundary recorded at DSM-HL-066 |
| DSM-HL-071 | 3489 | 71 Three-Factor Offline Identity | excluded: out of scope (offline/hardware); boundary recorded at DSM-HL-066 |
| DSM-HL-072 | 3538 | 72 Two Offline Recipients | excluded: out of scope (offline); boundary recorded at DSM-HL-066 |
| DSM-HL-073 | 3634 | 73 Conflict-Local Finality as a State Property | extracted (1) |
| DSM-HL-074 | 3662 | 74 Bitcoin Confirmation Versus DSM Finality | restated-only: DSM-HL-073 |
| DSM-HL-075 | 3682 | 75 End-to-End Worked Example | excluded: example |
| DSM-HL-076 | 3808 | 76 Why Every Piece Is Necessary | extracted (2) |
| DSM-HL-077 | 3860 | 77 Architecture Comparison | excluded: comparison |
| DSM-HL-078 | 3884 | 78 Produced and Discarded, or Never Producible | extracted (3) |
| DSM-HL-079 | 3970 | 79 What Bitcoin Optimizes For | excluded: comparison; the verifier's question restates DSM-HL-031 |
| DSM-HL-080 | 3984 | 80 Security Assumptions | extracted (14) |
| DSM-HL-081 | 4019 | 81 Formal Verification | extracted (7) |
| DSM-HL-082 | 4102 | 82 One Mathematical Picture of DSM | extracted (1) |
| DSM-HL-083 | 4165 | 83 Intuitive Analogy | no-normative-content: analogy |
| DSM-HL-084 | 4197 | 84 Final Summary | restated-only: summary of Parts I-II |
| DSM-HL-085 | 4249 | 85 The Core DSM Statement | extracted (1) |
| SOFI-PRE | 1 | Front matter (before SOFI-PREAMBLE) | no-normative-content: front matter and summary paragraph, restated in SOFI-PREAMBLE |
| SOFI-PREAMBLE | 34 | Read this first: if it exists, it is valid | extracted (23) |
| SOFI-001 | 273 | 1 How to read this document | no-normative-content: heading only |
| SOFI-001-1 | 275 | 1.1 Code references | excluded: code references |
| SOFI-001-2 | 293 | 1.2 Normative words | no-normative-content: defines normative words |
| SOFI-001-3 | 298 | 1.3 Boxes | no-normative-content: defines box types |
| SOFI-001-4 | 309 | 1.4 Notation | extracted (4) |
| SOFI-001-5 | 330 | 1.5 Three valued predicates | extracted (4) |
| SOFI-002 | 353 | 2 The layer rule | extracted (2) |
| SOFI-002-1 | 360 | 2.1 Who owns what | extracted (4) |
| SOFI-002-2 | 384 | 2.2 The storage question | extracted (1) |
| SOFI-002-3 | 389 | 2.3 Distinct facts | extracted (5) |
| SOFI-003 | 415 | 3 How value moves | extracted (4) |
| SOFI-004 | 434 | 4 What SoFi settles | extracted (2) |
| SOFI-005 | 443 | 5 Fault model | no-normative-content: heading only |
| SOFI-005-1 | 445 | 5.1 Storage nodes | extracted (3) |
| SOFI-005-2 | 456 | 5.2 Traders and other callers | extracted (1) |
| SOFI-005-3 | 461 | 5.3 Safety and liveness | extracted (6) |
| SOFI-005-4 | 475 | 5.4 Boundaries that remain | extracted (4) |
| SOFI-005-5 | 484 | 5.5 Checked arithmetic | extracted (1) |
| SOFI-006 | 503 | 6 The committed set | extracted (3) |
| SOFI-007 | 531 | 7 The leader of a cell | extracted (2) |
| SOFI-007-1 | 542 | 7.1 The shuffle | extracted (4) |
| SOFI-007-2 | 555 | 7.2 The two SoFi seeds | extracted (2) |
| SOFI-008 | 578 | 8 Writing a cell | extracted (11) |
| SOFI-009 | 629 | 9 Who may write | extracted (2) |
| SOFI-010 | 639 | 10 Content addressed objects | extracted (2) |
| SOFI-011 | 651 | 11 Indexes | extracted (2) |
| SOFI-012 | 673 | 12 Everything a member does | extracted (2) |
| SOFI-013 | 687 | 13 How Core reads storage | extracted (2) |
| SOFI-014 | 714 | 14 Registries | no-normative-content: heading only |
| SOFI-014-1 | 716 | 14.1 Domain tags | extracted (3) |
| SOFI-014-2 | 775 | 14.2 Object classes | extracted (3) |
| SOFI-014-3 | 819 | 14.3 Signed objects | extracted (2) |
| SOFI-015 | 826 | 15 Derivations | extracted (10) |
| SOFI-016 | 884 | 16 Setup | extracted (5) |
| SOFI-017 | 924 | 17 The operation | extracted (2) |
| SOFI-017-1 | 943 | 17.1 Stage 1: the trader precommit P | extracted (11) |
| SOFI-017-2 | 996 | 17.2 Stage 2: policy fulfillment Gj | extracted (10) |
| SOFI-017-3 | 1046 | 17.3 Stage 3: the trader fulfillment F | extracted (1) |
| SOFI-017-4 | 1077 | 17.4 Fulfillment ingress | extracted (5) |
| SOFI-017-5 | 1097 | 17.5 The exercise | extracted (2) |
| SOFI-018 | 1126 | 18 Settlement preimage and E | no-normative-content: heading only |
| SOFI-018-1 | 1128 | 18.1 The preimage | extracted (2) |
| SOFI-018-2 | 1156 | 18.2 Inputs after E | extracted (1) |
| SOFI-018-3 | 1161 | 18.3 Choosing the form of E | extracted (2) |
| SOFI-018-4 | 1169 | 18.4 Bounds | extracted (1) |
| SOFI-019 | 1184 | 19 The DLV data model | no-normative-content: heading only |
| SOFI-019-1 | 1186 | 19.1 Leaves | extracted (3) |
| SOFI-019-2 | 1205 | 19.2 Cores and the batch fold | extracted (1) |
| SOFI-019-3 | 1215 | 19.3 Closed write sets | extracted (3) |
| SOFI-019-4 | 1228 | 19.4 Route digest and leg rules | extracted (3) |
| SOFI-019-5 | 1241 | 19.5 Static economics | extracted (4) |
| SOFI-019-6 | 1264 | 19.6 Advancing the lineage | extracted (1) |
| SOFI-019-7 | 1272 | 19.7 Close authority | extracted (2) |
| SOFI-019-8 | 1283 | 19.8 Vault genesis | extracted (4) |
| SOFI-020 | 1300 | 20 Validation predicates | extracted (1) |
| SOFI-020-1 | 1308 | 20.1 RouteValidation | extracted (3) |
| SOFI-020-2 | 1340 | 20.2 FulfillmentConformance | extracted (10) |
| SOFI-021 | 1367 | 21 Exercise and atomicity | extracted (5) |
| SOFI-021-1 | 1383 | 21.1 Registration and realizability are separate | extracted (4) |
| SOFI-022 | 1403 | 22 The predecessor rule | extracted (3) |
| SOFI-023 | 1429 | 23 Consumption and the walk | no-normative-content: heading only |
| SOFI-023-1 | 1431 | 23.1 Successor resolution | extracted (2) |
| SOFI-023-2 | 1440 | 23.2 Consumed route | extracted (2) |
| SOFI-023-3 | 1460 | 23.3 Trader parent compatibility | extracted (1) |
| SOFI-023-4 | 1470 | 23.4 Routes with more than one leg | extracted (1) |
| SOFI-023-5 | 1479 | 23.5 Impossibility and skips | extracted (4) |
| SOFI-023-6 | 1514 | 23.6 The walk | extracted (3) |
| SOFI-024 | 1527 | 24 Resolution of a trader position | extracted (6) |
| SOFI-025 | 1563 | 25 Crash and recovery | extracted (1) |
| SOFI-026 | 1585 | 26 The stack | extracted (1) |
| SOFI-027 | 1613 | 27 Routes | excluded: code references (route table) |
| SOFI-028 | 1631 | 28 Creating a vault | extracted (1) |
| SOFI-029 | 1646 | 29 Setting up with a vault | extracted (1) |
| SOFI-030 | 1655 | 30 Finding the head of a vault | extracted (1) |
| SOFI-031 | 1671 | 31 A trade and a multihop route | extracted (2) |
| SOFI-032 | 1704 | 32 Closing a vault | extracted (1) |
| SOFI-033 | 1710 | 33 Relaying | extracted (1) |
| SOFI-034 | 1715 | 34 Every Core SoFi function, placed | excluded: code references (function placement); rule restated in SOFI-035 T1 |
| SOFI-035 | 1761 | 35 Rules | extracted (5) |
| SOFI-036 | 1789 | 36 The unlock preimage, traced | restated-only: rules T2-T4 applied per evidence item (SOFI-035) |
| SOFI-037 | 1850 | 37 Gates | extracted (6) |
| SOFI-038 | 1911 | 38 What enters the transition | extracted (1) |
| SOFI-039 | 1929 | 39 Requirements | extracted (4) |
| SOFI-040 | 1979 | 40 Step 1: demolition | excluded: historical implementation plan (Part VIII) |
| SOFI-040-1 | 1985 | 40.1 Why the node code goes, verified at 817123c | excluded: historical implementation plan (Part VIII) |
| SOFI-040-2 | 1995 | 40.2 Storage node | excluded: historical implementation plan (Part VIII) |
| SOFI-040-3 | 2038 | 40.3 Core wire material | excluded: historical implementation plan (Part VIII) |
| SOFI-040-4 | 2074 | 40.4 Gates | excluded: historical implementation plan (Part VIII); the root-register gate is retired by Amendment S2 |
| SOFI-041 | 2144 | 41 Step 2: stop and inspect | excluded: historical implementation plan (Part VIII) |
| SOFI-041-1 | 2169 | 41.1 Reachability at 817123c | excluded: historical implementation plan (Part VIII) |
| SOFI-042 | 2199 | 42 Step 3: the formal floor | no-normative-content: heading; obligations extracted in SOFI-042-1 to SOFI-042-4 |
| SOFI-042-1 | 2203 | 42.1 Delete first | extracted (1) |
| SOFI-042-2 | 2212 | 42.2 Then the invariants | extracted (3) |
| SOFI-042-3 | 2236 | 42.3 Two properties the floor must prove | extracted (2) |
| SOFI-042-4 | 2255 | 42.4 Files and counts | extracted (1) |
| SOFI-043 | 2271 | 43 Step 4: the Core seam | excluded: historical implementation plan (Part VIII) |
| SOFI-043-1 | 2275 | 43.1 Starting point in the tree | excluded: historical implementation plan (Part VIII) |
| SOFI-044 | 2289 | 44 Step 5: rebuild | excluded: historical implementation plan (Part VIII) |
| SOFI-044-1 | 2340 | 44.1 Device scenarios for R14 | excluded: historical implementation plan (Part VIII) |
| SOFI-045 | 2358 | 45 Step 6: cutover | excluded: historical implementation plan (Part VIII) |
| SOFI-046 | 2375 | 46 Not in this work | extracted (4) |
| SOFI-047 | 2398 | 47 What a token policy is | extracted (4) |
| SOFI-048 | 2434 | 48 Two kinds of supply | extracted (4) |
| SOFI-049 | 2468 | 49 What each rule governs | extracted (3) |
| SOFI-050 | 2492 | 50 The mandatory baseline | extracted (1) |
| SOFI-051 | 2502 | 51 Native supply | extracted (5) |
| SOFI-052 | 2533 | 52 Externally backed supply | extracted (3) |
| SOFI-053 | 2557 | 53 Raising supply | extracted (4) |
| SOFI-054 | 2574 | 54 What changes in the tree | excluded: implementation plan; its rules restate SOFI-048 to SOFI-052 |
| DBTC-PRE | 1 | Title block (before DBTC-SPEC-01) | no-normative-content: title block |
| DBTC-SPEC-01 | 20 | 1 Scope, Status, and Normative Language | no-normative-content: heading only |
| DBTC-SPEC-01-01 | 23 | 1.1 Scope | extracted (1) |
| DBTC-SPEC-01-02 | 46 | 1.2 Normative language | no-normative-content: defines normative words |
| DBTC-SPEC-01-03 | 53 | 1.3 Specification status | extracted (2) |
| DBTC-SPEC-02 | 66 | 2 Architectural Principle | extracted (4) |
| DBTC-SPEC-03 | 111 | 3 Relationship to DSM and Sovereign Finance | no-normative-content: heading only |
| DBTC-SPEC-03-01 | 114 | 3.1 DSM substrate | extracted (5) |
| DBTC-SPEC-03-02 | 139 | 3.2 Sovereign Finance boundary | extracted (2) |
| DBTC-SPEC-03-03 | 162 | 3.3 DLV compatibility | extracted (1) |
| DBTC-SPEC-04 | 175 | 4 Conformance Classes | extracted (4) |
| DBTC-SPEC-05 | 250 | 5 Clocklessness and External Bitcoin Finality | extracted (4) |
| DBTC-SPEC-06 | 273 | 6 Canonical Encoding and Domain Separation | extracted (2) |
| DBTC-SPEC-06-01 | 308 | 6.1 Required domains | extracted (2) |
| DBTC-SPEC-07 | 341 | 7 The dBTC Asset | extracted (3) |
| DBTC-SPEC-08 | 381 | 8 Bitcoin-Backed Origin DLV | no-normative-content: heading only |
| DBTC-SPEC-08-01 | 384 | 8.1 Origin output | extracted (2) |
| DBTC-SPEC-09 | 443 | 9 Origin Admission and dBTC Issuance | extracted (3) |
| DBTC-SPEC-10 | 484 | 10 What Moves During an Ordinary dBTC Transfer | extracted (3) |
| DBTC-SPEC-11 | 551 | 11 Withdrawal Is a DSM Consumption First | extracted (1) |
| DBTC-SPEC-11-01 | 572 | 11.1 Withdrawal intent | extracted (2) |
| DBTC-SPEC-12 | 625 | 12 The dBTC Burn | extracted (3) |
| DBTC-SPEC-13 | 687 | 13 DLV Completion Evidence | extracted (3) |
| DBTC-SPEC-14 | 759 | 14 Knowledge Is Not Possession | extracted (2) |
| DBTC-SPEC-15 | 812 | 15 Encrypted Bitcoin Execution Authority | no-normative-content: heading only |
| DBTC-SPEC-15-01 | 815 | 15.1 Purpose | extracted (2) |
| DBTC-SPEC-15-02 | 843 | 15.2 Fulfillment-gated opening | extracted (2) |
| DBTC-SPEC-16 | 892 | 16 Current Bitcoin Fulfillment Script Profile | extracted (2) |
| DBTC-SPEC-16-01 | 919 | 16.1 Refund branch | extracted (3) |
| DBTC-SPEC-17 | 932 | 17 Constructing the Bitcoin Withdrawal | extracted (2) |
| DBTC-SPEC-18 | 960 | 18 Full Withdrawal | extracted (2) |
| DBTC-SPEC-19 | 991 | 19 Partial Withdrawal and Successor Vault | extracted (3) |
| DBTC-SPEC-19-01 | 1048 | 19.1 Successor identity | extracted (1) |
| DBTC-SPEC-19-02 | 1068 | 19.2 Fresh successor authority | extracted (4) |
| DBTC-SPEC-19-03 | 1115 | 19.3 Successor activation | extracted (2) |
| DBTC-SPEC-20 | 1136 | 20 Why the Parent Cannot Remain the Authority | extracted (2) |
| DBTC-SPEC-21 | 1163 | 21 No Separate dBTC Double-Spend System | extracted (4) |
| DBTC-SPEC-22 | 1204 | 22 Online dBTC | extracted (2) |
| DBTC-SPEC-23 | 1231 | 23 Offline dBTC | extracted (2) |
| DBTC-SPEC-24 | 1260 | 24 Storage Nodes | extracted (3) |
| DBTC-SPEC-25 | 1299 | 25 Original Depositor Independence | extracted (2) |
| DBTC-SPEC-26 | 1326 | 26 Multi-Origin Balances | extracted (3) |
| DBTC-SPEC-27 | 1363 | 27 Fee Accounting | extracted (2) |
| DBTC-SPEC-28 | 1384 | 28 Conservation | extracted (2) |
| DBTC-SPEC-29 | 1421 | 29 Crash Safety and Replay | extracted (3) |
| DBTC-SPEC-30 | 1466 | 30 Concurrent Local Invocation | extracted (1) |
| DBTC-SPEC-31 | 1485 | 31 Security Properties | extracted (9) |
| DBTC-SPEC-32 | 1534 | 32 What a Device Compromise Means | extracted (1) |
| DBTC-SPEC-33 | 1559 | 33 What Is Deliberately Not Introduced | extracted (1) |
| DBTC-SPEC-34 | 1588 | 34 What Is Deliberately Not Claimed | extracted (1) |
| DBTC-SPEC-35 | 1609 | 35 End-to-End Protocol | restated-only: end-to-end walk of the rules above |
| DBTC-SPEC-35-01 | 1612 | 35.1 Deposit: BTC to dBTC | restated-only: deposit walk (DBTC-SPEC-08 to DBTC-SPEC-09) |
| DBTC-SPEC-35-02 | 1633 | 35.2 Transfer: dBTC to dBTC | restated-only: transfer walk (DBTC-SPEC-10) |
| DBTC-SPEC-35-03 | 1650 | 35.3 Full withdrawal: dBTC to BTC | restated-only: full withdrawal walk (DBTC-SPEC-11 to DBTC-SPEC-18) |
| DBTC-SPEC-35-04 | 1677 | 35.4 Partial withdrawal: dBTC to BTC plus successor vault | restated-only: partial withdrawal walk (DBTC-SPEC-19 to DBTC-SPEC-20) |
| DBTC-SPEC-36 | 1718 | 36 Complete Causal Architecture | restated-only: causal diagram of the rules above |
| DBTC-SPEC-37 | 1748 | 37 Implementation Mapping | excluded: informative implementation mapping (§1.3) |
| DBTC-SPEC-37-01 | 1753 | 37.1 Existing DLV fulfillment machinery | excluded: informative implementation mapping |
| DBTC-SPEC-37-02 | 1778 | 37.2 Existing Bitcoin HTLC machinery | excluded: informative implementation mapping |
| DBTC-SPEC-37-03 | 1795 | 37.3 Existing DLV state model | excluded: informative implementation mapping |
| DBTC-SPEC-37-04 | 1804 | 37.4 Existing proof carrier | excluded: informative implementation mapping |
| DBTC-SPEC-37-05 | 1811 | 37.5 Existing successor machinery | excluded: informative implementation mapping |
| DBTC-SPEC-37-06 | 1818 | 37.6 Narrow implementation change | excluded: informative implementation mapping |
| DBTC-SPEC-38 | 1843 | 38 Required Conformance Tests | extracted (1) |
| DBTC-SPEC-38-01 | 1848 | 38.1 Origin admission | extracted (1) |
| DBTC-SPEC-38-02 | 1863 | 38.2 DSM ownership | extracted (1) |
| DBTC-SPEC-38-03 | 1878 | 38.3 DLV fulfillment | extracted (1) |
| DBTC-SPEC-38-04 | 1897 | 38.4 Full withdrawal | extracted (1) |
| DBTC-SPEC-38-05 | 1912 | 38.5 Partial withdrawal | extracted (1) |
| DBTC-SPEC-38-06 | 1937 | 38.6 Storage | extracted (1) |
| DBTC-SPEC-38-07 | 1950 | 38.7 Crash and recovery | extracted (1) |
| DBTC-SPEC-38-08 | 1967 | 38.8 Online/offline separation | extracted (1) |
| DBTC-SPEC-39 | 1980 | 39 Proof Obligations | extracted (7) |
| DBTC-SPEC-40 | 2028 | 40 Comparison of Authority Models | excluded: comparison |
| DBTC-SPEC-41 | 2045 | 41 Final Protocol Invariant | extracted (1) |
| DBTC-SPEC-42 | 2133 | 42 Conclusion | restated-only: conclusion |
| STOR-PREAMBLE | 10 | Read this first | no-normative-content: scope, authority and status markers |
| STOR-001 | 55 | 1 What a storage node is | extracted (6) |
| STOR-002 | 70 | 2 What a node never does | extracted (2) |
| STOR-003 | 77 | 3 Fault model | extracted (7) |
| STOR-004 | 96 | 4 What storage facts are | extracted (2) |
| STOR-005 | 111 | 5 Immutable objects | extracted (6) |
| STOR-006 | 123 | 6 Keyed cells | extracted (4) |
| STOR-007 | 133 | 7 Indexes | extracted (1) |
| STOR-008 | 140 | 8 Mirror, spool, and identity storage | extracted (9) |
| STOR-009 | 162 | 9 Leader and finality | extracted (8) |
| STOR-009-1 | 185 | 9.1 Pending challenges counted in the leader's ByteCommits | extracted (5) |
| STOR-010 | 208 | 10 Storage sets | extracted (7) |
| STOR-011 | 225 | 11 Member ids are seats | extracted (4) |
| STOR-011-1 | 239 | 11.1 Two separate Fisher–Yates selections | extracted (4) |
| STOR-012 | 271 | 12 Binding and succession | no-normative-content: heading only |
| STOR-012-1 | 274 | 12.1 Initial binding | extracted (1) |
| STOR-012-2 | 281 | 12.2 Retirement triggers | extracted (1) |
| STOR-012-3 | 293 | 12.3 Retirement records | extracted (6) |
| STOR-012-4 | 314 | 12.4 Rebinding | extracted (3) |
| STOR-012-5 | 323 | 12.5 Handover | extracted (4) |
| STOR-012-6 | 337 | 12.6 Loss | extracted (5) |
| STOR-013 | 362 | 13 The operator registry | extracted (7) |
| STOR-014 | 377 | 14 ByteCommit | extracted (4) |
| STOR-015 | 391 | 15 Stake and exit | extracted (2) |
| STOR-016 | 407 | 16 The PaidK spend-gate | extracted (3) |
| STOR-017 | 417 | 17 Storage credits | extracted (11) |
| STOR-018 | 438 | 18 DLV exemption | extracted (3) |
| STOR-019 | 448 | 19 Retention | extracted (3) |
| STOR-020 | 458 | 20 Owner independence | extracted (1) |
| STOR-021 | 473 | 21 Repair | extracted (2) |
| STOR-022 | 485 | 22 Proof obligations | extracted (6) |
| STOR-023 | 497 | 23 Conflicts for the owner | no-normative-content: conflict list (carried in the findings table) |
| STOR-023-1 | 500 | 23.1 With the pinned corpus | no-normative-content: conflict list (carried in the findings table) |
| STOR-023-2 | 512 | 23.2 From the October 2025 specification, not adopted | no-normative-content: list of superseded items not adopted |
| STOR-024 | 526 | 24 Open items | no-normative-content: open-item list (open items extracted where they arise, flagged ambiguous) |
