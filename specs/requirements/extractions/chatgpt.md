# ChatGPT — independent specification extraction

Derived reconciliation input only; not an independent source of protocol truth.

All four pinned files were read in full. The corpus hashes matched before extraction. Owner amendments A1–A5 and S1–S3 govern superseded passages. Storage Open items are explicitly undecided, including Open paragraphs containing normative-looking words. No implementation files, other extractions, outside-folder files, or .github/instructions files supplied requirements.

IDs use the nearest §4 section anchor and the quote's original file-local line number. Repeated-line entries receive .a, .b, etc. Quotes retain source wording on one line; only table pipes are escaped. Requirements summarize the surrounding normative unit; mathematical definitions spanning several lines use a single-line excerpt rather than a reconstructed quotation. Section tables retain derived force where declarative meaning is extracted. Dependency boundaries are not subsystem audits.

## Corpus verification

| File | git hash-object | Lines | Result |
|---|---|---:|---|
| specs/DSM_High_Level_Explainer.md | c21b78c5a37ae0899e1cf3556fe10b0fa4e087a7 | 4296 | matched |
| specs/SoFi_Settlement_Specification.md | 86bce47771a8802b20438afef52e63d64e73e174 | 2592 | matched |
| specs/dBTC_Native_Specification.md | 233a3e72a5b16a023af830f4c8ffaad4ba9391a8 | 2160 | matched |
| specs/DSM_Storage_Node_Specification.md | cb30606704f33ee19db2e5c1669ff7bc6ce04d3b | 543 | matched |

## Worktree record

The following initial status was recorded before corpus extraction. All listed unrelated changes predated this work. Because specs/ is untracked as a directory, ordinary porcelain output does not enumerate this extraction separately.

### Before

```text
 M dsm_client/frontend/src/App.tsx
 M dsm_client/frontend/src/components/screens/AccountsScreen.tsx
 M dsm_client/frontend/src/components/screens/ContactsTabScreen.tsx
 M dsm_client/frontend/src/components/screens/SettingsMainScreen.tsx
 M dsm_storage_node/config/production.toml
 M dsm_storage_node/deploy/generate_node_configs.sh
 M dsm_storage_node/deploy/verify_storage_set_alignment.sh
 M dsm_storage_node/terraform/gcp/main.tf
 M dsm_storage_node/terraform/gcp/outputs.tf
 M dsm_storage_node/terraform/gcp/variables.tf
 D scripts/ca.crt
 D scripts/dsm_env_config.alibaba.toml
 M scripts/push_env_override.sh
?? SHEET-picker.png
?? dsm_client/frontend/src/components/tour/
?? dsm_client/frontend/stateboy-guided-tour.patch
?? dsm_storage_node/terraform/gcp/.terraform.lock.hcl
?? dsm_storage_node/terraform/gcp/.terraform/
?? dsm_storage_node/terraform/gcp/terraform.tfstate
?? scripts/dsm_env_config.gcp_beta.toml
?? series/
?? specs/
?? tstex_modules/
?? update_crypto_guide.py
?? update_sec_guide.py
```

### After

```text
 M dsm_client/frontend/src/App.tsx
 M dsm_client/frontend/src/components/screens/AccountsScreen.tsx
 M dsm_client/frontend/src/components/screens/ContactsTabScreen.tsx
 M dsm_client/frontend/src/components/screens/SettingsMainScreen.tsx
 M dsm_storage_node/config/production.toml
 M dsm_storage_node/deploy/generate_node_configs.sh
 M dsm_storage_node/deploy/verify_storage_set_alignment.sh
 M dsm_storage_node/terraform/gcp/main.tf
 M dsm_storage_node/terraform/gcp/outputs.tf
 M dsm_storage_node/terraform/gcp/variables.tf
 D scripts/ca.crt
 D scripts/dsm_env_config.alibaba.toml
 M scripts/push_env_override.sh
?? SHEET-picker.png
?? dsm_client/frontend/src/components/tour/
?? dsm_client/frontend/stateboy-guided-tour.patch
?? dsm_storage_node/terraform/gcp/.terraform.lock.hcl
?? dsm_storage_node/terraform/gcp/.terraform/
?? dsm_storage_node/terraform/gcp/terraform.tfstate
?? scripts/dsm_env_config.gcp_beta.toml
?? series/
?? specs/
?? tstex_modules/
?? update_crypto_guide.py
?? update_sec_guide.py
```

## Extraction

## DSM_High_Level_Explainer.md

### DSM-HL-001 — 1 The Central Question

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-001/L81 | invariant | derived | A realized history cannot contain two conflicting consumptions of one committed linear resource. | For one committed linear resource, two conflicting consumptions | — | none |

### DSM-HL-001-1 — 1.1 Candidate Futures Versus Realized Futures

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-001-1/L90 | invariant | derived | A parent may commit multiple candidate futures without realizing them. | DSM permits multiple candidate futures. | — | none |

### DSM-HL-003 — 3 Six Answers Before the Mathematics

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-003/L173 | authority | derived | The recipient determines validity from its frontier and committed policies. | \| Who determines whether a transition is valid? \| The recipient. Bob verifies what Alice presents against his own copy of the frontier and the committed policies. No third party is consulted for validity, and no third party could be. (Sections 5, 11, 12) \| | — | none |

### DSM-HL-004 — 4 The Two Halves of an Agreement

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-004/L206 | authority | derived | An absent party's outgoing value requires consent already committed in a vault. | - Online, movement is unilateral (Section 12) and the other party need not be present, so its | — | none |
| DSM-HL-004/L230 | obligation | derived | An online value-moving advance increments its committed position and presents the root with that position. | Position u. In online mode, u is a committed integer position that increments on every value-moving | — | none |

### DSM-HL-005 — 5 The Six Questions Every Transition Must Answer

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-005/L269 | evidence | derived | Acceptance requires proof that the successor belongs to the parent's committed candidate space. | 1. Was s′ actually precommitted by s? | — | none |
| DSM-HL-005/L271 | evidence | derived | Acceptance requires fulfillment of the branch's deterministic guard. | 2. Has the correct deterministic guard been fulfilled? | — | none |
| DSM-HL-005/L273 | invariant | derived | Acceptance preserves the required state structure. | 3. Does s′ preserve the required state structure? | — | none |
| DSM-HL-005/L275 | invariant | derived | Acceptance requires every resource consumed by the branch to be unconsumed. | 4. Are the linear resources required by the branch still unconsumed? | — | none |
| DSM-HL-005/L277 | obligation | derived | Acceptance enforces the committed deterministic policy. | 5. Does the transition obey committed deterministic policy? | — | none |
| DSM-HL-005/L279 | obligation | derived | Acceptance enforces the requirements of the selected operating mode. | 6. Does it satisfy any mode-specific requirements? | — | none |
| DSM-HL-005/L283 | invariant | derived | Acceptance is the conjunction of candidate, guard, structural, linearity, policy and mode predicates. | Accept(s, s′ , w) = CandidateOK(s, s′ ) | — | none |
| DSM-HL-005/L295 | invariant | explicit | Protocol acceptance is binary and execution occurs only when the full predicate holds. | > **Amendment A1 (owner, 2026-09-22) — acceptance stays binary.** A transition either satisfies the full acceptance predicate or it does not execute. There is no third kind of protocol truth. Everything that can be decided from evidence already in hand is evaluated first, and a transition found Invalid there never reaches the network layer (Amendment A4). | — | none |
| DSM-HL-005/L297.a | liveness-boundary | explicit | Missing evidence suspends evaluation and execution while the network layer fetches or retries; it is not a third predicate value. | > - **Evidence that cannot be obtained yet is not a verdict.** If the network evidence the predicate needs is not currently in hand, Accept has not been evaluated. The attempt does not execute and can be retried. Fetching and retrying belong to the network layer beneath the protocol, and Unavailable is never a value of any protocol predicate. Software may report it through an API status such as Pending or Unavailable, so that it retries rather than reporting the transition as invalid. Both layers can end in Invalid. Evidence obtained from the network is checked like anything else and can show the transition Invalid, for example a register cell holding a different root. And when retrying ends without the evidence, the transition is Invalid. Where other parties depend on the outcome, retrying ends only through the challenge rule of `DSM_Storage_Node_Specification.md` §9.1, so every verifier reaches the same result at the same point. | — | none |
| DSM-HL-005/L297.b | obligation | explicit | Fetched evidence undergoes verification and may establish invalidity. | > - **Evidence that cannot be obtained yet is not a verdict.** If the network evidence the predicate needs is not currently in hand, Accept has not been evaluated. The attempt does not execute and can be retried. Fetching and retrying belong to the network layer beneath the protocol, and Unavailable is never a value of any protocol predicate. Software may report it through an API status such as Pending or Unavailable, so that it retries rather than reporting the transition as invalid. Both layers can end in Invalid. Evidence obtained from the network is checked like anything else and can show the transition Invalid, for example a register cell holding a different root. And when retrying ends without the evidence, the transition is Invalid. Where other parties depend on the outcome, retrying ends only through the challenge rule of `DSM_Storage_Node_Specification.md` §9.1, so every verifier reaches the same result at the same point. | — | none |
| DSM-HL-005/L297.c | transition | explicit | When other parties depend on an outcome, retry termination requires the shared storage challenge rule rather than a local timeout. | > - **Evidence that cannot be obtained yet is not a verdict.** If the network evidence the predicate needs is not currently in hand, Accept has not been evaluated. The attempt does not execute and can be retried. Fetching and retrying belong to the network layer beneath the protocol, and Unavailable is never a value of any protocol predicate. Software may report it through an API status such as Pending or Unavailable, so that it retries rather than reporting the transition as invalid. Both layers can end in Invalid. Evidence obtained from the network is checked like anything else and can show the transition Invalid, for example a register cell holding a different root. And when retrying ends without the evidence, the transition is Invalid. Where other parties depend on the outcome, retrying ends only through the challenge rule of `DSM_Storage_Node_Specification.md` §9.1, so every verifier reaches the same result at the same point. | — | tension(SOFI-001-5/L342) |
| DSM-HL-005/L298 | prohibition | explicit | A nonexecuting transition records no negative outcome in state or storage. | > - **Nothing negative is recorded.** A transition that does not execute leaves nothing in state or in storage. | — | tension(SOFI-024/L1560.a) |
| DSM-HL-005/L300 | invariant | explicit | A dependent vault trade proceeds only after its predecessor realizes or becomes provably unrealizable. | > Where something else waits on the outcome, the subsystem derives for itself, from raw reads, whether a transition that has not executed can still execute. SoFi does this for a vault's attempt slots (SoFi §23, §24). The next trade against a vault needs a reliable available balance, so it proceeds only once the trade ahead of it has either realized or can provably never realize. Treating "not yet" as "never" there would let two trades spend the same reserves; treating "never" as "not yet" would stall the vault. A pending outcome can be brought to an end by the challenge rule of `DSM_Storage_Node_Specification.md` §9.1. | — | none |

### DSM-HL-006 — 6 DSM Does Not Need Global Ordering

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-006/L309 | authority | derived | Global ordering is excluded from the state-validity mechanism. | It removes global ordering from the validity mechanism. | — | none |
| DSM-HL-006/L328 | obligation | derived | Application-required ordering is represented as an explicit committed state dependency. | If an application requires a sequence relation, that relation can be encoded as part of state. | — | none |

### DSM-HL-008 — 8 Both Candidates Can Look Valid

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-008/L399 | transition | derived | Acceptance atomically installs the successor root and updated consumed set. | resource has one acceptor, and that acceptor’s accept step is atomic: the successor root and the updated | — | none |
| DSM-HL-008/L419 | theorem | derived | Static candidate uniqueness applies only to selector families; realized-history uniqueness applies to all well-formed families. | The static form of the theorem, where at most one candidate even passes the predicate, is a property | — | none |

### DSM-HL-009 — 9 Same Balance, Two Counterparties

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-009/L488 | invariant | derived | A holder balance resides in the device SMT rather than in individual relationship chains. | Alice’s balance is not stored inside either relationship chain. It is a leaf in Alice’s device SMT, committed | — | none |
| DSM-HL-009/L492 | obligation | derived | A balance resource descriptor identifies its token genesis, policy and holder. | xbal = (cpta-balance, GT , PT , Alice). | — | none |
| DSM-HL-009/L511 | transition | derived | Every online root advance increments the progression counter committed within the root. | Every DSM device root carries a committed progression object u (see the state object in Section 29). In | — | none |
| DSM-HL-009/L519 | obligation | derived | Relationship creation requires mutual pre-add and verification of the other device's committed state. | A relationship is not created by first contact. It is created by both sides taking the counterparty’s | — | none |
| DSM-HL-009/L524 | evidence | derived | A counterparty verifies the signed root chain instead of trusting a mirror's assertion. | Charlie does not trust the mirror. He verifies the signed root chain that produced (ρA , uA ). The | — | none |
| DSM-HL-009/L530 | obligation | derived | Every value-moving root advance is registered at its genesis-device-position cell. | He can ask it because every value-moving advance of a device root has to be registered. The storage | — | none |
| DSM-HL-009/L535 | obligation | derived | The position-cell key derives from genesis, device and position. | where G is the genesis and DevID the device. The cell’s key is derived from those three values, so anyone | — | none |
| DSM-HL-009/L537 | obligation | derived | The position-cell leader seed binds genesis, device, position and the validated preceding root. | seeded from G, DevID, the position and Alice’s validated root at the previous position. No node id and | — | none |
| DSM-HL-009/L540 | evidence | derived | The device signs its root claim and publishes identical bytes leader first and then to replicas. | What Alice writes there is a signed root claim, and only Alice can sign one. She writes it to the leader | — | none |
| DSM-HL-009/L543 | invariant | derived | The first recognized claim naming the cell at its leader determines that position's root. | is Charlie’s to evaluate, from raw reads: the root at position n + 1 is the first claim naming that cell at | — | none |
| DSM-HL-009/L549 | prohibition | derived | An online verifier rejects a presented root contradicted by the position cell. | - The cell holds a root that is not the one Alice is presenting. Alice’s device has already moved past | — | none |
| DSM-HL-009/L552 | evidence | derived | An initially empty position cell must acquire the presented root with verifier-derived finality before acceptance. | - The cell is empty. Charlie will accept only once Alice has registered the Charlie-transfer root at | — | none |
| DSM-HL-009/L558 | obligation | explicit | The receiver completes all decidable local decoding, authentication, candidate, guard, linearity and policy checks before fetching missing network evidence. | > **Amendment A4 (owner, 2026-09-22) — order of checks at acceptance.** The receiver first evaluates everything it can decide from what it already holds: it decodes the presentation, verifies its signatures and the payer's signed root chain, and runs the precommitment, guard, linearity and policy checks as far as the evidence in hand allows. If any of these is Invalid, the transition is Invalid and the network is never touched. Only then does it read the register cell and fetch any other evidence it still needs. This supersedes the order drawn in Figure 2 (§12), which places the register read before the precommitment and guard checks. | — | none |
| DSM-HL-009/L560 | prohibition | explicit | An operation already invalid on available evidence must trigger no network reads. | > - **Why checks on what is in hand come first.** A transition that is invalid on what the receiver already holds never reaches the network part: no storage read is spent on it, and no one's cell is read on its behalf. | — | none |
| DSM-HL-009/L561 | obligation | explicit | Authenticate the preceding payer root before deriving the register leader. | > - **Why authentication comes before the register read.** The cell's leader is derived from the payer's validated root at the previous position, so the receiver cannot even compute which member to ask until that root is verified. | — | none |
| DSM-HL-009/L562 | invariant | explicit | Check ordering changes the work performed but not the conjunctive acceptance result. | > - **The verdict does not depend on the order.** Accept is a conjunction, so every order gives the same result. The order binds only what the receiver does on the way: nothing is fetched from the network for a transition that is already Invalid on what the receiver holds. | — | none |
| DSM-HL-009/L619 | safety-assumption | derived | The leader preserves held bytes and their arrival order across restarts and restores. | It depends on the leader keeping what it holds, in the order it arrived, across restarts and restores, and | — | none |
| DSM-HL-009/L629 | dependency-boundary | derived | When online register access is unavailable, offline acceptance imports its separate anchor and identity-evidence machinery. | If the leader is unreachable, Charlie is not a weaker online verifier. He is, by definition, an offline | — | none |

### DSM-HL-010 — 10 A Transition Cannot Cross Relationships

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-010/L667 | invariant | derived | Distinct relationships share no parent, leaf, resource key or counterparty. | Every relationship is its own hash chain. A ↔ B and A ↔ C do not share a parent, a leaf, a key, or a | — | none |
| DSM-HL-010/L671 | obligation | derived | A relationship transition binds its own chain parent, device-pair leaf key, resource descriptor and counterparty signature. | - its parent hAB,n , which is a node of the A ↔ B chain and of no other chain; | — | none |
| DSM-HL-010/L687 | prohibition | derived | A transition from one relationship cannot be accepted as a transition of another relationship. | Any one of these is fatal. There is no reframing, re-keying, or re-signing that turns a A ↔ B object | — | none |
| DSM-HL-010/L729 | authority | derived | A receipt may serve as cross-relationship evidence but cannot advance a different relationship. | This is scoping, not secrecy. Charlie can be shown the A ↔ B receipt as evidence of something (for | — | none |

### DSM-HL-011 — 11 Storage Nodes

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-011/L747 | prohibition | derived | Storage nodes hold no authority keys and issue no signatures. | A storage node holds no key and signs nothing, ever. It never validates a protocol rule, never evaluates | — | none |
| DSM-HL-011/L750 | authority | derived | Nodes treat economic payloads as opaque and never decide transition validity. | never decides whether a transition is valid. Economic and protocol payloads are opaque to it apart from | — | none |
| DSM-HL-011/L754 | prohibition | derived | Protocol storage paths use logical ticks and never read wall clocks. | protocol-relevant path reads a clock; ordering inside the node uses logical ticks. | — | none |
| DSM-HL-011/L755 | prohibition | derived | Inter-node gossip only synchronizes state and performs no voting or leader election. | Inter-node gossip exists, and it is state synchronisation only: no leader election, no Raft, no Paxos | — | none |
| DSM-HL-011/L758.a | authority | explicit | A node may refuse addressed-account writes for an unmet one-time spend-gate but not for protocol semantics. | > **Amendment A2 (owner, 2026-09-22) — payment is the one refusal.** A node may refuse a write addressed to an account that has not met the one-time spend-gate below. It refuses nothing else, and nothing on protocol grounds. Whether nodes also refuse writes from accounts whose storage credits are exhausted is open (storage spec §17, §24). | — | tension(STOR-001/L61) |
| DSM-HL-011/L758.b | obligation | explicit | Whether exhausted storage credits permit node refusal is open, not a settled permission. | > **Amendment A2 (owner, 2026-09-22) — payment is the one refusal.** A node may refuse a write addressed to an account that has not met the one-time spend-gate below. It refuses nothing else, and nothing on protocol grounds. Whether nodes also refuse writes from accounts whose storage credits are exhausted is open (storage spec §17, §24). | — | ambiguous |
| DSM-HL-011/L760 | obligation | explicit | A party pays all five storage-set members independently of leader-plus-two finality. | > - **Paying and getting through are separate.** A party pays all five members of its storage set. A write goes through once the cell's leader and two other members hold it, so the other members carry what one member refuses. | — | none |
| DSM-HL-011/L761 | liveness-boundary | explicit | A refusing cell leader stalls the cell until replacement and cannot be substituted by a reachable member. | > - **The one exception is a leader.** No member stands in for a cell's leader, so if a member refuses a cell it happens to lead, that cell waits until the party opts the member out or the network cuts it. That is a stall, never a change in validity. | — | none |
| DSM-HL-011/L763 | authority | explicit | Payment enforcement uses the addressed account and never authenticates the relayer. | > - **Enforcement is keyed on the account the write is addressed to, never on who is writing.** Anyone may still carry a paid-up party's bytes, and the node never checks the writer (Amendment A3). | — | none |
| DSM-HL-011/L764 | invariant | explicit | Vault creation consumes creator credits but subsequent vault storage is independent of anyone's payment. | > - **It never applies to DLVs.** Creating a vault consumes its creator's credits like any write; after that, a vault's storage never depends on anyone's payment, because everyone depends on it. | — | none |
| DSM-HL-011/L765.a | obligation | explicit | Charge credits by storage used at a fixed network price and verify the debit at the receiver. | > - **Storage is paid on-chain with credits.** Credits are charged by storage used at a fixed network price, counted in storage and never in time, and checked by the receiver like any debit (storage spec §17). Before acting, a client checks its own credit balance. | — | none |
| DSM-HL-011/L765.b | obligation | explicit | A client checks its own credit balance before acting. | > - **Storage is paid on-chain with credits.** Credits are charged by storage used at a fixed network price, counted in storage and never in time, and checked by the receiver like any debit (storage spec §17). Before acting, a client checks its own credit balance. | — | none |
| DSM-HL-011/L772 | obligation | derived | Compute immutable addresses as H(DSM/storage-object ∥ N ∥ H(N ∥ P)). | addr = H(DSM/storage-object ∥ N ∥ H(N ∥P )), | — | none |
| DSM-HL-011/L774 | obligation | derived | Check supplied addresses but use the independently computed address as the storage key. | computed by the node from the input. A caller-supplied address is checked, never used as the | — | none |
| DSM-HL-011/L775 | prohibition | derived | Immutable storage exposes no update or overwrite path. | key. There is no update path and no overwrite path in the code, not an update path that refuses. | — | none |
| DSM-HL-011/L776 | transition | derived | Identical immutable replays re-acknowledge and differing bytes at one address signal corruption. | Replaying identical bytes re-acknowledges; different bytes at the same address are reported as | — | none |
| DSM-HL-011/L777 | evidence | derived | Both serving node and receiving client recompute immutable content addresses. | corruption. On read the node recomputes the address before serving. The client re-hashes anyway, | — | none |
| DSM-HL-011/L780 | obligation | derived | The tip mirror stores public device heads and encrypted per-relationship leaves. | Per-device tip mirror. A public head and encrypted per-relationship leaves, keyed by device and | — | none |
| DSM-HL-011/L784 | obligation | derived | Spool envelopes are versioned, insertion-ordered and acknowledged by routing key. | Inbox spool. Unilateral delivery for the offline counterparty. Envelopes are strictly versioned, ordered | — | none |
| DSM-HL-011/L788 | authority | explicit | Move canonical encoding, device authentication, replay and recipient checks from nodes to endpoint devices. | > **Amendment A3 (owner, 2026-09-22) — routing exists only through a pre-established contact, and the node never checks the writer.** This replaces the admission gates the source placed at the node (canonical encoding, device authentication, a replay-protected message id, and a recipient key). | — | none |
| DSM-HL-011/L790 | obligation | explicit | Address messages by the pre-added relationship's device-pair hash rather than by a genesis account. | > - **A message goes to a relationship, never to a genesis account.** A relationship is addressed by its chain id, the hash of the two device ids. Nobody can send to a party it has not pre-added: with no relationship there is nothing to address. | — | none |
| DSM-HL-011/L791 | obligation | explicit | Send and read only pre-added relationships and accept only the other relationship device's signature. | > - **Both ends check.** The sender's device sends only over relationships it has pre-added. The recipient's device reads only relationships it has pre-added, and accepts only messages signed by the other device of that relationship. The checks the source listed are performed by the devices at both ends. | — | none |
| DSM-HL-011/L792 | prohibition | explicit | Nodes must not authenticate a writer even as a relationship participant. | > - **The node does not check who is writing,** not even whether the writer is one of the relationship's two devices. A node that can check can block, and blocking is an authority a node must not have. | — | none |
| DSM-HL-011/L793 | invariant | explicit | Unauthorized raw writes cannot bypass recipient pre-add and signature requirements. | > - **What that leaves is worthless to an attacker.** Software that skips the sender-side check can compute a relationship id and write bytes under it, but nothing changes: writing into someone else's relationship needs two victims' ids and fails the recipient's signature check, and writing under one's own id and a victim's is never read, because the victim never pre-added it. | — | none |
| DSM-HL-011/L795 | dependency-boundary | derived | Storage imports identity anchoring, device-tree indexes and recovery capsules solely as bytes under derived keys. | Identity and recovery. Genesis anchoring, device-tree indexing, and recovery capsules, all stored as | — | none |
| DSM-HL-011/L798 | obligation | derived | Emit unsigned, hash-linked ByteCommits of stored SMT roots and mirror them as ordinary objects. | The node’s own commitments. Each cycle a node emits an unsigned ByteCommit: a Sparse Merkle | — | none |
| DSM-HL-011/L801 | evidence | derived | Verifiers independently check ByteCommit roots and links and require two consecutive empty cycles for exit. | by proving two consecutive empty cycles. Verifiers check the chain link and the root themselves; | — | none |
| DSM-HL-011/L808 | transition | derived | Payment to three distinct operators permanently enables the device's one-time spend-gate. | Writes are not free. A device may write only once it has paid a flat rate to K = 3 distinct operators; the | — | none |
| DSM-HL-011/L821 | obligation | derived | Writers and verifiers derive leaders by Fisher–Yates over the committed member set. | and the verifier compute one leader : the first member of a Fisher–Yates shuffle of the owner-committed | — | none |
| DSM-HL-011/L826 | obligation | derived | Publish a cell value to its leader before copying identical bytes to other members. | - The writer writes to the leader first, then the same bytes to the other members. Any party may | — | none |
| DSM-HL-011/L829 | obligation | derived | Members preserve all keyed values in arrival order without replacement or semantic comparison, subject to A2 payment refusal. | - Every member keeps everything it is given for a key, in arrival order. Nothing is refused, replaced | — | none |
| DSM-HL-011/L833 | invariant | derived | Finality requires the first recognized value at the leader and identical copies at two other members. | - The winner at a cell is the first object naming that cell at the leader. The value is final once the | — | none |
| DSM-HL-011/L837 | authority | derived | Verifiers derive winner and finality from raw reads rather than node verdicts. | - The verifier derives both facts from raw reads. No node evaluates them; the other members are | — | none |
| DSM-HL-011/L840 | liveness-boundary | derived | An unreachable leader stalls its cell without fallback election. | - If the leader is unreachable, the cell waits. No other member stands in, because a fallback chosen | — | none |
| DSM-HL-011/L843 | authority | derived | Registration establishes persistence rather than semantic validity. | Registered is not validated. A malicious device can register an arbitrary claim perfectly consistently | — | none |
| DSM-HL-011/L846 | safety-assumption | derived | A snapshot restore predating held bytes violates storage safety. | what arrived, in the order it arrived, and that fact survives restart and restore. Restoring a member from | — | none |
| DSM-HL-011/L849 | liveness-boundary | derived | Hash-detectable immutable-object misresponses affect availability rather than authority. | Byzantine label. Immutable-object misresponses are detectable by hash and affect availability only. The | — | none |

### DSM-HL-012 — 12 Online DSM

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-012/L902 | dependency-boundary | derived | Online uniqueness does not depend on the optional offline hardware subsystem. | Ordinary online DSM does not require hardware to determine transition uniqueness. | — | none |

### DSM-HL-013 — 13 DSM Is Not a Payment Channel

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-013/L975 | authority | derived | Only the relationship counterparty accepts the next step against its retained frontier. | be broadcast anywhere. The only party who accepts a step on A ↔ B is the counterparty, and the | — | none |
| DSM-HL-013/L995 | liveness-boundary | derived | A refusing counterparty may halt progress but cannot forge a signed state or force another party to advance. | hostile counterparty cannot take anything from you and cannot forge a state you did not sign, but they | — | none |

### DSM-HL-014 — 14 Determinism

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-014/L1036 | invariant | derived | Identical canonical verifier inputs produce identical decisions. | Then for identical canonical inputs, | — | none |
| DSM-HL-014/L1040 | prohibition | derived | Storage and ordering services cannot redefine protocol validity. | No storage node gets to declare an invalid object valid. | — | none |

### DSM-HL-014-1 — 14.1 Determinism Is Broader Than Arithmetic

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-014-1/L1077 | obligation | derived | Serialization, hashing, identifiers, candidate digests, guards, descriptors, keys, SMT updates, policies and successor roots must be deterministic. | Thus determinism is distributed throughout the architecture. | — | none |

### DSM-HL-015 — 15 Canonical Encoding

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-015/L1119 | obligation | explicit | Every correct encoder emits the same protocol bytes for the same logical object. | Every correct implementation must generate exactly the same bytes. | — | none |

### DSM-HL-015-1 — 15.1 Canonical Equality

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-015-1/L1130 | invariant | derived | Logical object equality implies canonical byte equality. | If two implementations produce different encodings for the same logical state, they have not implemented the same protocol object. | DSM-HL-015/L1119 | none |

### DSM-HL-016 — 16 Domain Separation

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-016/L1183 | obligation | derived | Different semantic hash operations occupy distinct domain-separated namespaces. | They make semantically different hash operations live in cryptographically different namespaces. | — | none |

### DSM-HL-017 — 17 Cryptographic Hashes

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-017/L1202 | safety-assumption | derived | Hash commitments assume collisions between distinct inputs are negligibly likely. | then, under the collision-resistance assumption, | — | none |

### DSM-HL-018 — 18 Forward-Only Hash Chaining

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-018/L1217 | invariant | derived | Each successor commits the canonical hash of its predecessor. | A successor binds its predecessor: | — | none |

### DSM-HL-019 — 19 Bilateral Relationships

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-019/L1248 | invariant | derived | Each bilateral relationship evolves through its own forward-only chain. | Each relationship has its own forward-only chain. | — | none |
| DSM-HL-019/L1275 | invariant | derived | Updating one relationship does not imply an update to unrelated chains. | An update to one does not imply an update to the others. | DSM-HL-019/L1248 | none |

### DSM-HL-021 — 21 Relationship Projections

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-021/L1316 | transition | explicit | A transition applies the deterministic relationship projection and leaves unrelated projections unchanged. | This means that any valid DSM state transition involving a relationship must agree exactly with the | — | none |

### DSM-HL-022 — 22 Why Bilateral State Matters

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-022/L1346 | authority | derived | Relationship validity depends only on relevant state and explicitly named shared resources or policies. | The validity of A ↔ B is determined from the state relevant to A ↔ B, together with any named | — | none |

### DSM-HL-023 — 23 Why a Device Needs a Compact Commitment

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-023/L1373 | obligation | derived | Commit device relationship state using authenticated sparse Merkle trees. | DSM therefore uses authenticated tree commitments. | — | none |

### DSM-HL-025 — 25 Sparse Merkle Trees

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-025/L1434 | obligation | derived | Empty SMT subtrees use deterministic default hashes. | Empty subtrees have deterministic default hashes. | — | none |
| DSM-HL-025/L1460 | obligation | derived | A 256-bit SMT has logical depth 256. | A real 256-bit SMT has a logical depth of 256. | — | none |

### DSM-HL-026 — 26 Relationship Keys

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-026/L1468 | obligation | derived | Derive the symmetric relationship key by hashing the canonically sorted device pair under DSM/smt-key/v1. | kA↔B = H(DSM/smt-key/v1 ∥ min(DevIDA , DevIDB ) ∥ max(DevIDA , DevIDB )). | — | none |
| DSM-HL-026/L1472 | obligation | derived | Store the current relationship head at its derived SMT key. | The relationship leaf stores its current head: | — | none |

### DSM-HL-027 — 27 Updating One SMT Leaf

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-027/L1517 | invariant | derived | A relationship leaf update preserves all unrelated leaves. | All unrelated leaves remain unchanged. | DSM-HL-021/L1316 | none |

### DSM-HL-028 — 28 Merkle Proofs

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-028/L1546 | evidence | derived | Merkle inclusion verification recomputes the path using sibling hashes and left-right placement and matches the committed root. | The proof supplies the sibling hashes needed to recompute the path. | — | none |

### DSM-HL-029 — 29 The DSM State Object

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-029/L1607 | obligation | derived | Canonical state contains relationship map, progression, candidates, guards, consumed keys, policy, mode evidence and full commitment. | s = (R, u, P, Γ, Σ, Π, Ω, ρ). | — | none |
| DSM-HL-029/L1615 | obligation | derived | The relationship map records each authenticated current head. | It records the current authenticated relationship head. | — | none |
| DSM-HL-029/L1618 | invariant | derived | The progression object advances monotonically under the selected mode. | The object u represents monotonic progression. | — | none |
| DSM-HL-029/L1631 | obligation | derived | The candidate space commits the permitted future candidates. | It commits the currently permitted future candidates. | — | none |
| DSM-HL-029/L1635 | obligation | derived | The guard family binds branches to deterministic fulfillment predicates and required resource sets. | It associates candidate branches with deterministic fulfillment rules and resource sets. | — | none |
| DSM-HL-029/L1642 | obligation | derived | The consumed set records all keys already consumed in the realized lineage. | contains resource-consumption keys already consumed in the realized lineage. | — | none |
| DSM-HL-029/L1646 | obligation | derived | Policy state commits deterministic policy and authority data. | contains deterministic policy and authority data. | — | none |
| DSM-HL-029/L1650 | obligation | derived | Mode evidence contains the selected mode's evidence and may be empty online. | contains mode-specific evidence. In an ordinary online state it may be empty. | — | none |

### DSM-HL-030 — 30 The Layered Root

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-030/L1666 | obligation | derived | Compute the core root over R, u, Σ, Π and Ω before deriving candidate and guard commitments. | ρcore = SMT(R, u, Σ, Π, Ω). | — | none |
| DSM-HL-030/L1672 | obligation | derived | The full root binds the core root and digests of the candidate and guard families. | ρ = H(ρcore ∥ digest(P ) ∥ digest(Γ)). | — | none |
| DSM-HL-030/L1698 | invariant | derived | State-root dependencies form an acyclic graph from core fields to core root to future commitments to full root. | The dependency graph is acyclic. | — | none |

### DSM-HL-031 — 31 Canonical State Chaining

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-031/L1718 | invariant | derived | A state-chain edge denotes deterministic derivability from its committed parent. | “The successor is a valid deterministic transformation of the committed parent.” | — | none |
| DSM-HL-031/L1731 | obligation | derived | Each state commits both current facts and its allowed transition structure. | Every state commits both current facts and its permitted transition structure. | DSM-HL-029/L1607 | none |

### DSM-HL-033 — 33 Logical Generations

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-033/L1757 | prohibition | derived | Logical generations must not be interpreted as wall-clock timestamps. | A generation is not a wall-clock timestamp. | — | none |
| DSM-HL-033/L1763 | invariant | derived | State progression is ordered by dependency rather than universal time. | DSM state progression is ordered by dependency. | — | none |

### DSM-HL-034 — 34 Precommitment

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-034/L1769 | obligation | derived | Commit allowed candidate futures in the parent before any becomes realized. | Precommitment means the parent state commits its allowed candidate future space before one of those | — | none |

### DSM-HL-035 — 35 Candidate Structure

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-035/L1788 | obligation | derived | A candidate binds a successor, branch identifier, guard descriptor, resource-key set and candidate digest. | ci = (si , bi , gi , Ki , di ). | — | none |
| DSM-HL-035/L1803 | obligation | derived | The candidate digest hashes its canonically encoded successor. | di = H(enc(si )). | — | none |
| DSM-HL-035/L1804 | prohibition | explicit | An uncommitted arbitrary successor cannot be inserted into a parent's future space. | The candidate must be bound to the parent. | — | none |

### DSM-HL-036 — 36 Candidate Forks Are Allowed

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-036/L1854 | invariant | derived | Multiple candidate branches never permit multiple consumptions of one linear resource. | One linear resource may be consumed once in a valid realized lineage. | DSM-HL-001/L81 | none |

### DSM-HL-037 — 37 Precommitment Chaining

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-037/L1884 | transition | derived | Every realized successor becomes the parent of a newly committed candidate and guard space. | Each realized successor becomes the parent of the next precommitted future space. | — | none |

### DSM-HL-038 — 38 Guards

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-038/L1911 | obligation | explicit | A candidate realizes only after satisfying its deterministic Boolean guard. | It must satisfy a deterministic guard. | DSM-HL-005/L271 | none |
| DSM-HL-038/L1930 | obligation | explicit | Guards bind parent, branch, resource keys, witness type, witness predicate and conflict class. | A guard should bind: | — | none |

### DSM-HL-039 — 39 Guard Families

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-039/L1951 | obligation | derived | A well-formed guard family verifies deterministically and binds the correct state and branch. | A well-formed guard family requires deterministic verification and correct binding to the state and | — | none |

### DSM-HL-040 — 40 Guards Alone Are Not the Exclusion Mechanism

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-040/L1986 | invariant | explicit | Conflicting branches contend for the same authoritative resource key even when both guards can succeed. | Conflicting branches must contend for the same authoritative linear-resource key. | — | none |

### DSM-HL-041 — 41 Linear Resources

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-041/L2004 | invariant | derived | One committed linear-resource generation produces at most one realized successor within its conflict class. | A linear resource is an object whose committed generation can produce at most one realized successor | — | none |

### DSM-HL-042 — 42 Resource Descriptors

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-042/L2032 | obligation | derived | Derive canonical resource descriptors from committed state. | The descriptor is derived from committed state. | — | none |
| DSM-HL-042/L2033 | prohibition | derived | A branch cannot choose an alternative resource descriptor to evade conflict. | A branch is not free to invent a different descriptor merely to evade conflict. | — | none |

### DSM-HL-043 — 43 Resource-Consumption Keys

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-043/L2040 | obligation | derived | Derive consumption keys from the consume-resource domain, parent core root and canonical resource descriptor. | κres (s, x) = H(DSM/consume resource/v1 ∥ ρcore,s ∥ x). | — | none |
| DSM-HL-043/L2044 | invariant | derived | Branches consuming the same resource from the same parent derive the same key. | If two branches consume the same resource x, then both derive the same: | DSM-HL-040/L1986 | none |

### DSM-HL-044 — 44 Why Branch-Specific Exclusion Keys Would Be Wrong

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-044/L2099 | prohibition | derived | Branch identifiers must not enter the authoritative exclusion key. | DSM therefore derives the exclusion key from the resource, not from the choice of conflicting branch. | DSM-HL-043/L2040 | none |
| DSM-HL-044/L2100 | authority | derived | Branch-local audit or index identifiers have no exclusion authority. | Branch-local identifiers may still exist for audit or indexing, but they are not the authoritative | — | none |

### DSM-HL-045 — 45 Conflict Classes

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-045/L2109 | invariant | derived | A conflict class contains branches sharing the relevant required consumption key. | The branches inside CK (s) are mutually conflicting with respect to the same linear resource. | — | none |

### DSM-HL-046 — 46 The Consumed Set

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-046/L2123 | transition | derived | A valid consumption unions its key into the successor's consumed set. | After a valid transition consuming K: | — | none |
| DSM-HL-046/L2134 | invariant | derived | The consumed set never shrinks across realized transitions. | Σ s ⊆ Σ s′ . | — | none |

### DSM-HL-047 — 47 The Consumed Set Can Also Be an SMT

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-047/L2150 | evidence | derived | An authenticated sparse map may prove a resource absent before execution and present afterwards. | The consumed set may itself be represented as an authenticated sparse map. | — | none |

### DSM-HL-049 — 49 The Complete Realization Predicate

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-049/L2213 | invariant | derived | Realization requires candidate, guard, structural, linearity, policy and mode predicates together. | Realize(s, si , w) = CandidateOK(s, si ) | DSM-HL-005/L283 | none |

### DSM-HL-050 — 50 Potential and Realized Morphisms

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-050/L2228 | transition | derived | A potential morphism becomes realized only when all required predicates hold. | When all required predicates become true, the potential morphism becomes a realized morphism. | — | none |

### DSM-HL-051 — 51 Realized Histories

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-051/L2242 | invariant | derived | Every edge of a realized history is a valid DSM realization. | such that every edge is a valid DSM realization. | — | none |
| DSM-HL-051/L2247 | prohibition | derived | Do not evaluate later consumption against stale snapshots that omit earlier realized consumption. | A branch is not repeatedly evaluated against an old snapshot while ignoring the state created by | — | none |

### DSM-HL-052 — 52 The Core Uniqueness Theorem

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-052/L2258 | theorem | explicit | Two conflicting branches cannot separately consume the same key in one valid history. | Then b1 and b2 cannot both consume K as separate realized transitions in one valid DSM history. | — | none |
| DSM-HL-052/L2295 | theorem | explicit | A deterministic selector allows at most one fulfilled branch even against an untouched parent. | Selector families. Some conflict classes carry a deterministic selector: a vault decision function, a | — | none |
| DSM-HL-052/L2299 | theorem | explicit | For shared-key families, the first atomic acceptance invalidates later conflicting candidates through consumed-set threading. | Shared-key families. Other conflict classes let several guards be true at once. Release, refund, and | — | none |

### DSM-HL-053 — 53 Tripwire

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-053/L2330 | invariant | derived | Tripwire excludes conflicting realized states without assuming hostile serialized bytes cannot exist. | Tripwire does not mean malicious bytes cannot exist. | DSM-HL-052/L2258 | none |

### DSM-HL-054 — 54 Safety and Liveness

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-054/L2374 | liveness-boundary | derived | Safety does not guarantee progress when counterparties, witnesses, data, storage or policy conditions prevent realization. | DSM safety does not imply guaranteed progress. | — | none |

### DSM-HL-055 — 55 Concurrency Without Global Ordering

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-055/L2407 | theorem | derived | Disjoint transitions commute only when neither depends on state modified by the other. | and neither transition depends on state modified by the other, then they may commute: | — | none |

### DSM-HL-056 — 56 Token Conservation

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-056/L2465 | invariant | derived | Ordinary token transfer preserves the sum of sender and recipient balances. | So ordinary transfer is zero-sum. | — | none |

### DSM-HL-057 — 57 Why Conservation Is Not Enough

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-057/L2484 | invariant | derived | Economic safety requires both conservation and resource linearity. | ### 57 Why Conservation Is Not Enough | — | none |

### DSM-HL-058 — 58 Deterministic Limbo Vaults

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-058/L2539 | invariant | derived | All terminal branches of one vault generation consume the same generation resource and exclude a second terminal realization. | Once one terminal branch consumes: | — | none |

### DSM-HL-059 — 59 Smart Commitments

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-059/L2575 | obligation | derived | A smart commitment is a bounded deterministic predicate over committed inputs. | A smart commitment is a bounded deterministic predicate over committed inputs: | — | none |
| DSM-HL-059/L2578 | obligation | derived | A smart commitment binds input and output deltas, invariants, external commitments, encumbrances, intent bounds and evaluation budget. | C = {∆in , ∆out , invariants, external commitments, encumbrances, intent bounds, budget}. | — | none |
| DSM-HL-059/L2595 | obligation | derived | Predicate iteration cardinality is fixed at commit time. | - iteration with a cardinality fixed at commit time. | — | none |
| DSM-HL-059/L2597 | prohibition | derived | Smart commitments permit no recursion, dynamic dispatch or unbounded loops and declare a static evaluation budget. | It cannot use recursion, dynamic dispatch, or unbounded loops, and every predicate family declares a | — | none |
| DSM-HL-059/L2628 | obligation | derived | Clock-like conditions use local accepted-transition budgets rather than timestamps or global heights. | No clocks. Ethereum has block timestamps and heights. DSM has neither, by design. Where a | — | none |
| DSM-HL-059/L2633 | prohibition | derived | Composition references only precommitted candidates, guards and hashed external commitments rather than arbitrary dynamic calls. | No open-ended composition. On Ethereum any contract can call any other. In DSM a commitment | — | none |

### DSM-HL-060 — 60 Multi-Party Workflows Through External Commitments

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-060/L2672 | obligation | derived | External commitments hash external data under DSM/external/v1. | Y = H(DSM/external/v1 ∥ X). | — | none |
| DSM-HL-060/L2673 | authority | derived | Core checks predicates bound to an external commitment and never executes its referenced payload. | DSM never executes X. It verifies only equality, inclusion, signature, or proof predicates bound to Y . | — | none |
| DSM-HL-060/L2710 | invariant | derived | Additional authority changes branch eligibility without permitting duplicate parent consumption. | authority chooses an eligible branch; it cannot multiply the consumed parent. | — | none |
| DSM-HL-060/L2729 | liveness-boundary | derived | Independent bilateral legs are not automatically atomic and require an explicit bundle when all-or-none behavior is needed. | Atomicity across the bilateral legs is not automatic. If Alice’s leg releases and Bob’s does not, that | — | none |

### DSM-HL-061 — 61 CPTA and Deterministic Policy

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-061/L2740 | invariant | derived | Policy authorization does not exempt a transition from resource linearity. | An authorized actor may satisfy a policy condition. That does not exempt the actor from linearity. | — | none |
| DSM-HL-061/L2753 | obligation | derived | Asset policies commit issuance, transfer conditions, operation authority and allowed operations. | A CPTA token is the other way round. The asset is bound to a committed policy describing which | — | none |
| DSM-HL-061/L2758 | invariant | derived | Vault and application transitions must satisfy every involved asset policy in addition to their own policies. | The consequence is that the rules travel with the asset. When a CPTA token enters a limbo vault, | — | none |
| DSM-HL-061/L2776 | transition | derived | Economic validity produces an exact write set, then economic-root admission, then register anti-equivocation. | economic validity → exact write set → economic-root admission → register: anti-equivocation. | — | none |
| DSM-HL-061/L2778 | authority | derived | The economic-root register cannot function as a policy engine. | The register is the last step and only the last step. It is not a policy engine and it decides nothing | — | none |
| DSM-HL-061/L2817 | obligation | derived | Token policy governs that token's movements without requiring an enumeration of trading pairs by default. | A token’s policy says what makes a transfer of that token valid. It does not enumerate trading pairs. | — | none |
| DSM-HL-061/L2825 | obligation | derived | Explicit policies may restrict approved assets, vault policies or credentials. | A more restrictive token can certainly say “only against approved assets,” “only through approved | — | none |
| DSM-HL-061/L2843 | safety-assumption | derived | Commitment enforces the written policy but does not guarantee that the policy itself is well designed. | cuts both ways: a badly written policy is committed just as firmly as a good one. Cryptographic | — | none |

### DSM-HL-062 — 62 Deterministic Emissions (DJTE)

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-062/L2855 | dependency-boundary | derived | The emissions subsystem imports source-vault release under committed token policy; DJTE internals are outside this extraction. | #### Emission is a vault transition, not minting | — | none |
| DSM-HL-062/L2875 | invariant | derived | Externally backed dBTC issuance and withdrawal must keep outstanding units within proven external backing. | External assets are the one exception, and they are logically different. dBTC (Section 64) does mint | — | none |
| DSM-HL-062/L2955 | obligation | derived | A transition binds the receiver's committed parent, index and policy context. | Most of the answer is structural. A transition must bind to a receiver’s committed context (the | — | none |
| DSM-HL-062/L2959 | prohibition | derived | Zero-effect traffic is not representable as a valid transition. | And a zero-effect transition is not a transition, so “send nothing a million times” is not representable. | — | none |
| DSM-HL-062/L2962 | invariant | derived | Receiving value must not debit the receiver's storage credits. | the spend-gate. Receiving never debits, so a victim’s credits cannot be drained remotely. There is no | — | none |
| DSM-HL-062/L2966 | obligation | derived | Storage-used pricing supersedes the earlier one-credit-per-transition description. | > **Note (2026-09-22).** Credits are the storage payment mechanism: charged by storage used, at a fixed network price in token units (storage spec §17). | — | none |

### DSM-HL-063 — 63 Sovereign Finance (SoFi)

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-063/L2986 | invariant | derived | Vault funding removes ordinary spendable value without retaining a second spendable copy. | There is no second spendable copy. The LP owns and controls the vault by committing its policies at | — | none |
| DSM-HL-063/L2989 | obligation | derived | Vault creation commits bounded market, fee, size-limit and release policies. | - PM : the bounded market policy (the invariant, fees, and a per-transition size ceiling); | — | none |
| DSM-HL-063/L2993 | authority | derived | The vault owner is bound by the same committed release policy as other participants. | Once funded, the LP is bound by those policies exactly as a trader is. The owner cannot reach into | — | none |
| DSM-HL-063/L2999 | authority | derived | Only prefunded executable vault policy supplies an absent owner's outgoing authority. | A funded vault is the authority, committed in advance. The value is already inside an executable | — | none |
| DSM-HL-063/L3028 | obligation | derived | A vault exercise binds signed fulfillment, signed precommit, settlement preimage and policy witnesses by hash. | shuffle of S seeded from the vault id and Rn (Section 11). A trader who exercises writes one object to | — | none |
| DSM-HL-063/L3052 | invariant | derived | Winning a successor cell alone cannot move reserves. | Reaching the leader first settles who may consume the parent. It does not move the reserves. Reserves | — | none |
| DSM-HL-063/L3053 | transition | derived | Reserve advancement requires trader registration, precommit conformance, exact-parent route validity and every leg final with a live attempt and canonical parent. | move only when the trader’s position resolves: its fulfilment is registered at its own position cell, the | — | none |
| DSM-HL-063/L3057 | invariant | derived | A Void route consumes no legs and leaves trader balances unchanged. | operation. If any leg cannot resolve that way, the position resolves Void : no leg is consumed, nothing | — | none |
| DSM-HL-063/L3063 | liveness-boundary | derived | Any relayer can finish a registered fulfillment without further trader discretion. | A trader who registers and walks away leaves nothing locked. There is no write authorization, so any | — | none |
| DSM-HL-063/L3069 | invariant | derived | An aggregated route consumes every bound vault parent or none. | - Independent vaults, atomic aggregation. A large trade may draw from several LPs’ vaults at | — | none |
| DSM-HL-063/L3073 | obligation | derived | Deterministic pricing and allocation use checked integers and produce identical routes from identical states. | - Deterministic pricing. Allocation and pricing are checked integer arithmetic; two conforming | — | none |
| DSM-HL-063/L3080 | obligation | derived | Perpetual funding uses trade activity, liquidation uses committed branches and reference prices use co-signed verified trade windows. | - Perpetuals and liquidation. Funding is denominated in trade activity rather than elapsed time, | — | none |
| DSM-HL-063/L3084 | prohibition | derived | SoFi validity contains no timestamp, height or duration. | - Clockless. No timestamp, height, or duration appears in any validity rule. | — | none |
| DSM-HL-063/L3102 | liveness-boundary | derived | Market execution is online and requires the relevant leaders and replicas to be reachable. | Two costs are explicit in the specification. First, a market trade is online: it needs the vault’s storage | — | none |
| DSM-HL-063/L3107 | obligation | explicit | Every vault commits the network-pinned storage set and no owner or trader chooses members. | > **Amendment A5 (owner, 2026-09-22) — a vault's storage set is assigned, never chosen.** A vault's storage set is the network's pinned set (SoFi §6; storage spec §10). No owner, liquidity provider or trader chooses storage members. Where this section says the LP commits a storage-member set or calls it owner-chosen, read: the vault commits the network's pinned set. | — | none |

### DSM-HL-064 — 64 dBTC: Bitcoin as a DSM Asset

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-064/L3201 | authority | derived | Live DSM state supplies economic ownership while Bitcoin material supplies only constrained execution. | Economic authority is ownership of live dBTC state in a device root: it is what transfers, what is | — | none |
| DSM-HL-064/L3213 | evidence | derived | Origin admission verifies the actual Bitcoin transaction, inclusion, script, amount, network and profile confirmation depth. | Origin. A real Bitcoin output is locked in an HTLC under a dBTC vault profile. The admitting device | — | none |
| DSM-HL-064/L3215 | invariant | derived | Issue exactly the admitted Bitcoin quantity with stable origin provenance. | depth the profile chose, the way a full node would. Exactly that quantity enters DSM as dBTC, | — | none |
| DSM-HL-064/L3216 | liveness-boundary | derived | After origin admission the depositor has no continuing authorization or availability role. | bound to its origin lineage v. After admission the depositor has no continuing role: it signs nothing | — | none |
| DSM-HL-064/L3219 | transition | derived | Ordinary dBTC transfer consumes the source, credits the recipient and preserves provenance through DSM. | Transfer. A dBTC transfer is an ordinary DSM economic transition (Section 9): the sender’s balance leaf | — | none |
| DSM-HL-064/L3220 | prohibition | derived | Ordinary dBTC transfers carry no Bitcoin spend, key or vault execution material and require no Bitcoin per-hop settlement. | is consumed, the recipient is credited, provenance is preserved. It carries nothing Bitcoin-specific: | — | none |
| DSM-HL-064/L3225 | obligation | derived | A withdrawal commits exact amount, destination, fee and successor intent before burning live dBTC. | Withdrawal. The holder constructs an exact intent W (amount, destination, fee, successor) and commits | — | none |
| DSM-HL-064/L3226 | transition | derived | A withdrawal burn replaces spendable dBTC with a nonspendable completion object bound to intent. | cW . Live dBTC is verified and consumed in a burn bound to cW : spendable state becomes a | — | none |
| DSM-HL-064/L3230 | obligation | derived | Derive the DLV unlock from lock, committed parameters and burn-completion evidence and check its Bitcoin SHA-256 commitment. | skVn = H(DSM/dlv-unlock ∥ Ln ∥ Cn ∥ σ),           SHA256(skVn ) = hf,n , | — | none |
| DSM-HL-064/L3232 | authority | derived | The opened execution capsule signs only the exact committed transaction. | and it opens a sealed execution capsule that signs exactly the committed transaction Tn and no | — | ambiguous |
| DSM-HL-064/L3238 | invariant | derived | Hashlock equality is necessary but cannot substitute for verified consumption. | of its evidence. The hash equality is the last check, not the first, and it is never independently sufficient. | — | none |
| DSM-HL-064/L3278 | invariant | derived | Withdrawal requires live state, state authority, valid burn, valid completion and the matching DLV preimage together. | Withdrawable = LiveState ∧ StateAuthority ∧ ValidBurn ∧ ValidCompletion ∧ Preimage. | — | none |
| DSM-HL-064/L3280 | safety-assumption | derived | Changing the lock, parameters or completion evidence changes the unlock derivation except with negligible probability. | The secret is derived from one specific burn’s evidence. Substituting the lock, the parameters or the | — | none |
| DSM-HL-064/L3288 | transition | derived | A partial withdrawal creates payout and fresh successor backing in the same Bitcoin transaction. | If the holder wants only part out, the committed transaction pays the destination and, in the same | — | ambiguous |
| DSM-HL-064/L3290 | invariant | derived | A spent parent and its successor cannot both count as live backing. | origin lineage. The spent parent is terminal; parent and successor are never both live backing. A successor | — | none |
| DSM-HL-064/L3291 | obligation | derived | Enforce the immutable profile successor floor in the burn predicate. | cannot be left at dust: the floor is fixed in the vault profile and enforced by the burn predicate, so a split | — | none |
| DSM-HL-064/L3293 | prohibition | derived | Do not convert protected successor collateral into extra fees. | The remainder is never trimmed into fee, because the successor is collateral for outstanding dBTC the | — | none |
| DSM-HL-064/L3302 | prohibition | derived | Storage cannot establish dBTC ownership, validate burns as authority, hold mint or plaintext vault keys, sign exits or choose successors. | It decides nothing: it does not determine who owns dBTC, validate a burn, hold a mint key or a plaintext | — | none |
| DSM-HL-064/L3321 | safety-assumption | derived | Withdrawal inherits the selected Bitcoin confirmation-depth and deep-reorganization boundary. | Withdrawal is online by design and inherits Bitcoin’s own settlement assumptions: the confirmation | — | none |
| DSM-HL-064/L3323 | safety-assumption | derived | Compromise sufficient to produce an accepted DSM burn compromises the associated dBTC. | of “knowledge is not possession” is that possession is whatever DSM says it is: an attacker who | — | none |

### DSM-HL-065 — 65 Recovery as a Linear Generation

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-065/L3334 | dependency-boundary | derived | Recovery is imported only as a terminal branch family consuming one recovery generation. | All three terminal alternatives consume: | — | none |

### DSM-HL-066 — 66 Offline Bearer DSM

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-066/L3362 | dependency-boundary | derived | Offline mode imports physical-origin evidence separately from software resource linearity; dedicated hardware rules remain out of scope. | DSM keeps these questions separate. | — | none |

### DSM-HL-073 — 73 Conflict-Local Finality as a State Property

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-073/L3643 | invariant | derived | Conflict-local finality means consumed resources cannot realize a conflicting successor within the same valid lineage. | The consumed committed resource cannot produce another conflicting realized successor inside | — | none |

### DSM-HL-076 — 76 Why Every Piece Is Necessary

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-076/L3829 | invariant | derived | Resource exclusion depends on forcing conflicting branches to derive the same key. | Resource keys work only if conflicting branches are forced to derive the same key. | DSM-HL-040/L1986 | none |
| DSM-HL-076/L3832 | invariant | derived | Consumed state must be authenticated and monotonically carried forward. | The consumed set is useful only if it is cryptographically authenticated and carried forward monotonically. | DSM-HL-046/L2134 | none |
| DSM-HL-076/L3850 | obligation | derived | Independent online recipients require the economic-root register in addition to lineage-local uniqueness. | a stale root, requires one more piece on top of the kernel: the economic-root register, one cell per position | — | none |

### DSM-HL-078 — 78 Produced and Discarded, or Never Producible

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-078/L3893 | obligation | derived | The realization predicate must be the only construction path into protocol state. | In DSM a transition that breaks a rule is never producible. The realization predicate of Part II is the | — | none |

### DSM-HL-080 — 80 Security Assumptions

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-080/L3986.a | safety-assumption | derived | Security assumes collision resistance and signature unforgeability. | DSM’s guarantees depend on explicit assumptions. | — | none |
| DSM-HL-080/L3986.b | safety-assumption | derived | Security assumes canonical serialization and correct relationship-key and resource-descriptor derivation. | DSM’s guarantees depend on explicit assumptions. | — | none |
| DSM-HL-080/L3986.c | safety-assumption | derived | Security assumes correct SMT verification and monotonic consumed-set updates. | DSM’s guarantees depend on explicit assumptions. | — | none |
| DSM-HL-080/L3986.d | safety-assumption | derived | Offline physical-identity claims additionally import the fused-hardware and measurement boundary without proving it in the kernel. | DSM’s guarantees depend on explicit assumptions. | — | none |
| DSM-HL-080/L3993 | safety-assumption | derived | Security assumes correct shared-key derivation for conflicting branches. | 6. conflicting branches deriving the same authoritative resource key; | — | none |
| DSM-HL-080/L3996 | safety-assumption | derived | Security assumes a faithful implementation of the deterministic transition predicate. | 9. faithful implementation of the deterministic transition predicate; | — | none |
| DSM-HL-080/L3998 | safety-assumption | derived | Durable member memory survives restart, restoration and migration without alteration, reorder or loss. | 11. durable member memory: a storage member never alters, reorders or loses what it holds for a | DSM-HL-009/L619 | none |
| DSM-HL-080/L4001 | safety-assumption | derived | Leader derivation uses committed state and member set without availability or caller choice. | 12. leader derivation: the writer and the verifier compute a cell’s leader from the owner-committed | DSM-HL-011/L821 | none |
| DSM-HL-080/L4004 | liveness-boundary | derived | Lack of the leader or two copies stalls a cell while memory violations compromise safety. | Failure to reach a cell’s leader, or two other members, is a liveness failure: the cell waits. Violation of | DSM-HL-011/L840 | none |
| DSM-HL-080/L4008 | obligation | derived | Use BLAKE3 hashing, SPHINCS+ signatures and Kyber key encapsulation at DSM-native boundaries. | The concrete primitives behind the first two assumptions are post-quantum: BLAKE3 for hashing, | — | none |

### DSM-HL-081 — 81 Formal Verification

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DSM-HL-081/L4034 | proof-obligation | derived | The guarded model establishes absence of key-scoped realized forks by threading consumed keys and checking absence. | - the theorem that no valid realized history contains a key-scoped realized fork. | — | none |
| DSM-HL-081/L4053 | proof-obligation | derived | Storage-cell models check leader-required finality, single finality, deterministic leader choice and nonoccupancy by unrecognized bytes with weakening controls. | - a storage-cell model, in which members keep every value in arrival order and one leader per cell is | — | none |
| DSM-HL-081/L4060 | theorem | derived | Canonical recognition implies validity while recomputation of signer randomizers is outside the claimed converse. | Section 4 and the whole of Section 78 rest on: for arbitrary bytes from an adversary, constructible implies | — | tension(SOFI-PREAMBLE/L48) |
| DSM-HL-081/L4072 | safety-assumption | derived | Model checking consumed-set threading does not establish resource-descriptor injectivity or key-derivation correctness. | The TLA+ module treats resource keys as given inputs and guard well-formedness as an opaque flag. It | — | none |
| DSM-HL-081/L4079 | safety-assumption | derived | Storage-cell proofs assume durable memory rather than proving it. | The storage-cell model covers the rule that decides a cell; it does not cover the members’ durable | — | none |
| DSM-HL-081/L4085 | obligation | explicit | Production code must refine the proved abstract model through conformance checks and enforcement boundaries. | A production implementation must faithfully refine the abstract model. The artifacts prove that the | — | none |

## SoFi_Settlement_Specification.md

### SOFI-PREAMBLE — Read this first: if it exists, it is valid

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-PREAMBLE/L42 | invariant | explicit | Core constructs no state unless every governing rule is satisfied. | A state change that breaks a rule cannot be made. It is not rejected afterwards; it never comes into existence. | DSM-HL-005/L283 | none |
| SOFI-PREAMBLE/L47 | prohibition | explicit | Storage nodes hold no keys and sign nothing. | A storage node holds no key and signs nothing, ever. The client signs its own transitions, because movement | DSM-HL-005/L283 | none |
| SOFI-PREAMBLE/L48 | authority | explicit | The sender signs its unilateral transition and hashes bind exact object bytes and dependencies. | is unilateral: the sender advances its own state and signs it. Everything else is bound by hashed preimages: | DSM-HL-005/L283 | tension(SOFI-008/L599) |
| SOFI-PREAMBLE/L56 | prohibition | explicit | Do not give storage identity keys, attestations or certificate authority roles. | Giving a storage node a key of any kind, including an identity key, a signature, a certificate of what it holds, or | DSM-HL-005/L283 | none |
| SOFI-PREAMBLE/L196 | authority | explicit | One Core constructor is the sole path for creating or adjusting protocol state. | 1. The constructor is the only door. One transition function in Core makes every state. Nothing else creates, | DSM-HL-005/L283 | none |
| SOFI-PREAMBLE/L198 | prohibition | explicit | Core accepts no externally supplied authoritative roots, resource keys, entropy, verdicts or default evidence. | 2. Every input comes from committed state and passes through Core. No state is built from roots, keys, | DSM-HL-005/L283 | none |
| SOFI-PREAMBLE/L200 | obligation | explicit | Construction uses canonical encoding, domain separation and checked arithmetic without clocks or outside randomness. | 3. Everything is deterministic and canonical. One byte encoding per object, domain separated hashes, no | DSM-HL-005/L283 | none |
| SOFI-PREAMBLE/L202 | obligation | explicit | Every production-path module and evidence item must contribute to the constructor. | 4. Every module on the path is used, and every piece of evidence is consumed by the constructor | DSM-HL-005/L283 | none |
| SOFI-PREAMBLE/L204 | prohibition | explicit | SDK, storage and app layers must not duplicate Core's semantic validity checks. | 5. Nothing downstream checks what construction guarantees. Not the SDK, not storage, not the app. | DSM-HL-005/L283 | none |

### SOFI-001-4 — 1.4 Notation

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-001-4/L315 | obligation | derived | SoFi domain hashes use BLAKE3 over the exact DSM/sofi/ tag, a zero byte and the canonical payload. | \| `H(tag; x)` \| BLAKE3(tag ∥ 0x00 ∥ x), the domain hash of `CORE/crypto/blake3.rs:167` (`dsm_domain_hasher`). Every SoFi tag starts with `DSM/sofi/`; formulas write only the part after that prefix. \| | DSM-HL-015/L1119 | none |
| SOFI-001-4/L316 | obligation | derived | Concatenated derivation fields are fixed-width values or one canonical encoding without added length prefixes. | \| `x1 ∥ x2` \| Concatenation. Every part is either fixed width (32-byte digests, 8-byte integers) or a single canonical encoding, so no length prefixes are added (`CORE/sofi/derive.rs:42`). \| | DSM-HL-015/L1119 | none |
| SOFI-001-4/L317 | obligation | derived | Encode u64 and u32 derivation integers big-endian in eight and four bytes. | \| `u64be(n)`, `u32be(n)` \| Big-endian encodings of n in 8 and 4 bytes. \| | DSM-HL-015/L1119 | none |
| SOFI-001-4/L318 | invariant | derived | Distinct well-formed objects have distinct class-bound canonical binary encodings. | \| `CCB(x)` \| The canonical binary encoding of object x under its class number (`CORE/ccb/`). Two distinct well-formed objects never share an encoding. \| | DSM-HL-015/L1119 | none |

### SOFI-001-5 — 1.5 Three valued predicates

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-001-5/L338.a | invariant | explicit | Core predicates return only Valid or Invalid over evidence actually in hand. | > **Amendment S3 (owner, 2026-09-22) — Unavailable is not a predicate value.** Core predicates are binary: Valid or Invalid, evaluated only over evidence Core has in hand. Obtaining that evidence, including retrying when it cannot be fetched, belongs to the network layer beneath Core. "Unavailable" is that layer's report that it is still fetching; it never sits beside Valid and Invalid, and nothing is marked Invalid while it is still being retried. | DSM-HL-015/L1119 | none |
| SOFI-001-5/L338.b | authority | explicit | The network layer owns evidence acquisition and retry status without turning Unavailable into protocol truth. | > **Amendment S3 (owner, 2026-09-22) — Unavailable is not a predicate value.** Core predicates are binary: Valid or Invalid, evaluated only over evidence Core has in hand. Obtaining that evidence, including retrying when it cannot be fetched, belongs to the network layer beneath Core. "Unavailable" is that layer's report that it is still fetching; it never sits beside Valid and Invalid, and nothing is marked Invalid while it is still being retried. | DSM-HL-015/L1119 | none |
| SOFI-001-5/L340 | obligation | explicit | Evaluate all decidable conjuncts first and request no network work for an already-invalid operation. | > - Core first evaluates every conjunct it can decide from evidence already in hand. If any is Invalid, the conjunction is Invalid and the network layer is never asked for anything. Only an operation that nothing in hand shows to be Invalid goes on to the network layer for the evidence it still needs, and the conjunction is Valid only once every conjunct has been evaluated Valid. | DSM-HL-015/L1119 | none |
| SOFI-001-5/L341 | obligation | explicit | Interpret older Unavailable ladder rungs as ongoing network fetching rather than predicate results. | > - The rule above, and the rows of Section 24 that name Unavailable (rungs 4 and 6), are read in that sense: Unavailable there means the network layer is still fetching. It is not a result. | DSM-HL-015/L1119 | none |
| SOFI-001-5/L342 | transition | explicit | Fetched evidence can invalidate a position and challenge-terminated missing evidence resolves the position Void. | > - Evidence obtained from the network is evaluated like any other and can make the conjunction Invalid. When fetching ends without the evidence, which for a trader position happens only through the challenge rule of `DSM_Storage_Node_Specification.md` §9.1, the position resolves Void (Amendment S1). | DSM-HL-015/L1119 | tension(DSM-HL-005/L297.c) |

### SOFI-002 — 2 The layer rule

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-002/L356 | authority | explicit | Only the complete deterministic Core construction predicate establishes admissibility. | There are no validators. A state transition becomes admissible only by satisfying the complete deterministic | DSM-HL-078/L3893 | none |

### SOFI-002-1 — 2.1 Who owns what

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-002-1/L366 | authority | derived | Core SoFi validates objects, derives commitments and folds exact economic results without accepting storage verdicts. | \| Core SoFi \| `CORE/sofi/` \| Constructs and validates P, Gj, F and E; computes BindExt; folds T◦ and every Vj◦; produces the exact accepted economic result. Never reads a storage verdict as a truth value. \| | DSM-HL-078/L3893 | none |
| SOFI-002-1/L367 | authority | derived | The generic Core state machine owns entropy and successor mechanics without depending on SoFi types. | \| Core state machine \| `CORE/core/state_machine/` \| Entropy evolution, random walk material, generic transition construction, canonical successor machinery. Never names a SoFi type. \| | DSM-HL-078/L3893 | none |
| SOFI-002-1/L368 | authority | derived | The SDK packages Core-accepted results without a second validation, root derivation or entropy source. | \| SDK adapter \| `SDK/sdk/` \| Packages a result Core already accepted into Core’s generic transition input. Never validates a second time, never computes a second root, never supplies its own entropy. \| | DSM-HL-078/L3893 | none |

### SOFI-002-2 — 2.2 The storage question

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-002-2/L386 | prohibition | derived | An addition requiring storage to understand payload semantics belongs outside the storage layer. | Every addition to the implementation answers one question before it is written: does storage need to know what this | DSM-HL-078/L3893 | none |

### SOFI-002-3 — 2.3 Distinct facts

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-002-3/L393 | invariant | derived | Keep finality, reachability, canonicality, consumption, realization, resolution, skipping, registration and validation as distinct facts. | StorageFinal ≠ StorageReachable ≠ Canonical ≠ Consumed ≠ TraderRealized | DSM-HL-078/L3893 | none |
| SOFI-002-3/L405 | invariant | derived | Publishing a precommit has no economic or exercise effect. | \| Trader precommit P \| Signed by the trader. Noneconomic: publishing or storing it is never exercise, and abandoning it has no effect. \| | DSM-HL-078/L3893 | none |
| SOFI-002-3/L406 | authority | derived | Policy fulfillment is deterministic evidence without an issuer, consent role or lock. | \| Policy fulfillment Gj \| A noneconomic, deterministic witness that the operation fulfills the precommitted policy of one referenced DLV state. It is never consent, approval, acceptance or a lock. It has no issuer. \| | DSM-HL-078/L3893 | none |
| SOFI-002-3/L407 | authority | derived | Only the trader signs fulfillment that exercises the complete precommit. | \| Trader fulfillment F \| Signed by the trader. References P and the complete policy fulfillment set. The exercise. \| | DSM-HL-078/L3893 | none |

### SOFI-003 — 3 How value moves

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-003/L426 | transition | explicit | The trader carries policy evidence in its own transition and the vault successor follows from that same operation. | A trader unlocks a DLV by carrying, in its own transition, the evidence that the vault’s committed criteria are met. | DSM-HL-005/L283 | none |
| SOFI-003/L428 | prohibition | explicit | A SoFi vault operation requires no party signature other than the trader's. | follows from the same operation. No party other than the trader signs. | DSM-HL-005/L283 | none |

### SOFI-004 — 4 What SoFi settles

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-004/L436 | obligation | derived | SoFi creation, setup, trades, routes and close execute online. | SoFi settles five operations, all online. An owner creates a vault and, later, closes it. A trader sets up a relationship | DSM-HL-005/L283 | none |
| SOFI-004/L438 | invariant | derived | One external commitment binds every hop of an all-or-none route through distinct vaults. | vaults in which each hop’s output token is the next hop’s input token. A multihop route is one operation with one | DSM-HL-005/L283 | none |

### SOFI-005-1 — 5.1 Storage nodes

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-005-1/L449 | safety-assumption | explicit | Storage may crash or omit but must not equivocate, alter or permanently lose held bytes and must fail closed outside that model. | A storage node may crash and may omit messages. It never equivocates, never alters content it holds, and never | DSM-HL-080/L3998 | none |

### SOFI-005-2 — 5.2 Traders and other callers

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-005-2/L458 | safety-assumption | derived | Safety must tolerate arbitrary callers, malformed bytes, relayers and attempts to occupy coordinates with useless values. | Traders are arbitrary. Any caller may speak raw HTTP to a node, send malformed bytes, relay other people’s objects, | DSM-HL-080/L3998 | none |

### SOFI-005-3 — 5.3 Safety and liveness

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-005-3/L465 | liveness-boundary | derived | Eventual resolution assumes obtainable evidence, reachable required members, fair completion writes and recursively resolvable predecessors. | 1. the evidence needed for validation eventually becomes available; | DSM-HL-080/L3998 | none |
| SOFI-005-3/L470 | liveness-boundary | derived | Progress is not guaranteed against an adversary winning every future write. | No liveness is claimed against an adversary who wins every future write forever. If required evidence never appears, | DSM-HL-080/L3998 | none |

### SOFI-005-4 — 5.4 Boundaries that remain

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-005-4/L477 | liveness-boundary | derived | An identity can split its own registers and a position can remain pending after its vault keys become skippable. | - An identity can split its own registers (self split). | DSM-HL-080/L3998 | none |
| SOFI-005-4/L480 | liveness-boundary | derived | Fulfillment can lose contention because policy witnesses never prepare-lock parents. | - A fulfillment may resolve Void under contention. Policy fulfillment witnesses do not lock parents, so success | DSM-HL-080/L3998 | none |

### SOFI-005-5 — 5.5 Checked arithmetic

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-005-5/L486 | obligation | derived | Position, attempt and generation arithmetic must report overflow rather than wrap. | The position q, the attempt index a and the vault generation use checked arithmetic. Overflow is an error, never a | DSM-HL-080/L3998 | none |

### SOFI-006 — 6 The committed set

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-006/L506 | obligation | explicit | Commit exactly five storage member IDs sorted by raw bytes and hash only those IDs into storage_set_id. | Every vault commits its storage set in its own state. The set is the sorted list of member ids S = (m1 < m2 < | DSM-HL-011/L833 | tension(SOFI-017-1/L982) |
| SOFI-006/L507 | invariant | explicit | Offline members remain in the committed set. | · · · < m5 ), compared as raw bytes. A member that is offline is still in S. The set is identified by one hash, | DSM-HL-011/L833 | none |

### SOFI-007 — 7 The leader of a cell

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-007/L538 | authority | explicit | Only writers and Core derive cell leaders and nodes do not know which cells they lead. | The writer and Core compute the leader. A storage node never does: it does not know which cells it leads, and | DSM-HL-011/L821 | none |
| SOFI-007/L539 | prohibition | explicit | Leader seeds exclude availability, caller identity and node IDs. | it never compares its value with anyone else’s. Availability, the caller’s identity and node ids never enter a seed, | DSM-HL-011/L821 | none |

### SOFI-007-1 — 7.1 The shuffle

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-007-1/L546 | obligation | derived | Sort the committed set by raw bytes and reject duplicate member IDs before shuffling. | 1. Sort S ascending by raw bytes. A duplicate member id is refused. | DSM-HL-011/L821 | none |
| SOFI-007-1/L547 | obligation | derived | Fisher–Yates iterates descending indices and swaps each position with an unbiased draw from zero through that index. | 2. For i from n − 1 down to 1: draw j uniformly from 0 . . . i and swap positions i and j. | DSM-HL-011/L821 | none |
| SOFI-007-1/L549 | obligation | derived | Generate draw words from fy-prf/v1 over seed, u32be index and u32be counter and reject below 2^64 mod range. | 3. A draw for range = i + 1 reads words w = u64be first 8 bytes of H(fy-prf/v1; s ∥ u32be(i) ∥ u32be(ctr)) for | DSM-HL-011/L821 | none |
| SOFI-007-1/L552 | obligation | derived | A shuffle counter exhausts with a defined error and never wraps. | 4. ctr is 32 bits. Exhausting it is a defined error, never a wrap. | DSM-HL-011/L821 | none |
| SOFI-007-1/L553 | obligation | derived | Select the member at shuffle position zero as leader. | 5. The leader is position 0 of the result. | DSM-HL-011/L821 | none |

### SOFI-007-2 — 7.2 The two SoFi seeds

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-007-2/L561 | obligation | derived | All successor attempts for one vault parent share H(storage-seed/v4; vault ∥ parent) as seed. | \| DLV successor cells of vault v at parent Rn \| `sv = H(storage-seed/v4; v ∥ Rn)`, `storage_seed`, `CORE/sofi/derive.rs:230` \| K(a) for every attempt a \| | DSM-HL-011/L821 | none |
| SOFI-007-2/L564 | obligation | derived | Both position cells use H(DSM/economic/position-seed/v1; genesis ∥ device ∥ u64be(next position) ∥ validated parent root). | s(q) = H(DSM/economic/position-seed/v1; G ∥ DevID ∥ u64be(q) ∥ Rp ), | DSM-HL-011/L821 | none |

### SOFI-008 — 8 Writing a cell

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-008/L598 | obligation | explicit | Compute a cell key and leader before publishing. | 1. Compute K and its leader. | DSM-HL-011/L833 | none |
| SOFI-008/L599 | transition | explicit | Write to the leader first and recognize only the first object that names the cell as its winner. | 2. Write x to the leader. Like every member, it keeps everything it is given, in the order it arrives. The winner | DSM-HL-011/L833 | tension(SOFI-PREAMBLE/L48) |
| SOFI-008/L601 | obligation | explicit | Replicate identical winner bytes to the other committed members. | 3. Write the same bytes x to the other members of S. | DSM-HL-011/L833 | none |
| SOFI-008/L603 | obligation | explicit | Any party may complete missing copies. | 5. Members not reached get x later. Any party MAY carry the bytes to them. | DSM-HL-011/L833 | none |
| SOFI-008/L608 | invariant | explicit | Finality requires the first recognized leader-held object plus the same object at two other set members. | Final(K, x) ⇐⇒ x is the first object naming K at the leader ∧ { m ∈ S \ {leader} : m holds x } ≥ 2. | DSM-HL-011/L833 | none |
| SOFI-008/L610 | authority | explicit | Core derives finality from raw member reads and no node evaluates it. | Core evaluates this from raw reads. No node evaluates it. | DSM-HL-011/L833 | none |
| SOFI-008/L614 | evidence | explicit | A different recognized leader-held winner suffices to prove a candidate cannot finalize at that cell. | 3. LeaderHeld(K, y) with y ≠ x, where y is the first object naming K at the leader, already settles that x is never | DSM-HL-011/L833 | none |
| SOFI-008/L616 | liveness-boundary | explicit | An unreachable leader has no fallback and its cell waits. | 4. If the leader is unreachable, the cell waits for it. No other member stands in, because a fallback chosen by who | DSM-HL-011/L833 | none |
| SOFI-008/L620 | obligation | explicit | A previously held competing value cannot block copying the winner to another member. | No member refuses, replaces or compares anything. A value another member already holds for K can therefore | DSM-HL-011/L833 | none |

### SOFI-009 — 9 Who may write

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-009/L631 | authority | derived | Any carrier may write signed or deterministically derived objects without write authorization. | Anyone. There is no write authorization, because every object carries its own authority (Read this first): signed | DSM-HL-011/L833 | none |
| SOFI-009/L633 | obligation | derived | Publish fulfillment and root-claim position cells together at their common leader. | them. The trader’s two position cells, Kful (q) and Kroot (q), are written together at their leader. | DSM-HL-011/L833 | none |

### SOFI-010 — 10 Content addressed objects

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-010/L641 | obligation | derived | Persist exact canonical object bytes under storage content addresses and recompute protocol identities separately. | Precommits, fulfillments, policy fulfillment witnesses, setup bodies, settlement preimages, vault genesis preimages | DSM-HL-011/L833 | none |
| SOFI-010/L646 | evidence | explicit | Stored(o) requires three members to return precisely the bytes of o. | Stored(o) holds when three members of S return the exact bytes of o. | DSM-HL-011/L833 | none |

### SOFI-011 — 11 Indexes

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-011/L653 | obligation | derived | Index precommits, preimages, genesis preimages, setup bodies, policy witnesses and auxiliary candidates under their specified protocol locators. | A protocol object is found by its protocol identity, which is not its storage address. An index maps a locator to the | DSM-HL-011/L833 | none |
| SOFI-011/L656 | obligation | explicit | Anyone may append an already-held object's address under a locator and index entries are never removed. | Anyone MAY append the content address of an object the member already holds under any locator. Appends | DSM-HL-011/L833 | none |
| SOFI-011/L657 | obligation | explicit | Index reads return paged append order and Core fetches and verifies candidate identities. | are never removed. A read returns the addresses in append order, paged. The member interprets nothing: Core | DSM-HL-011/L833 | none |
| SOFI-011/L658 | liveness-boundary | explicit | An exhausted index scan budget reports missing evidence rather than invalidity. | fetches each candidate, recomputes its identity, and keeps the one that verifies. A scan that exceeds its budget | DSM-HL-011/L833 | none |

### SOFI-012 — 12 Everything a member does

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-012/L678 | obligation | derived | Node operations consist of content-addressed puts, append-only keyed puts, index appends and ordered raw reads. | \| Put object \| Store the bytes under the hash of the bytes. The reader recomputes the hash. \| | DSM-HL-011/L833 | none |
| SOFI-012/L683 | prohibition | derived | Members perform no semantic decoding, comparison, derivation or decisions. | A member never checks, decodes, compares, derives or decides anything. | DSM-HL-011/L833 | none |

### SOFI-013 — 13 How Core reads storage

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-013/L689 | authority | derived | Core uses only LeaderHeld, Final and Stored as storage facts. | Core turns raw member reads into three storage facts and uses nothing else from storage. A member signs nothing; | DSM-HL-011/L833 | none |
| SOFI-013/L707 | evidence | derived | Fulfillment registration requires finality of both fulfillment and its recomputed resolution claim. | FulfillmentRegistered(F )               Final(Kful (q), F ) and Final(Kroot (q), Cq ) | SOFI-017-4/L1093 | none |
| SOFI-013/L708 | evidence | derived | Economic-root registration is finality at the economic-root coordinate. | EconomicRootRegistered(q, C)            Final(Kroot (q), C) | DSM-HL-011/L833 | none |
| SOFI-013/L709 | evidence | derived | Setup registration derives only from Stored of the exact setup body. | SetupRegistered(σ)                      Stored of the setup body | SOFI-016/L915 | none |
| SOFI-013/L710 | evidence | derived | StorageFinalE derives from a final exercise whose precommit carries E. | StorageFinalE(K, E)                     Final(K, X) for an exercise X whose P carries E (Section 17.5) | SOFI-017-5/L1111 | none |

### SOFI-014-1 — 14.1 Domain tags

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-014-1/L718.a | obligation | derived | Use the exact registered domain strings in the §14.1 registry without substituting semantically similar tags. | Every tag below is a constant in CORE/common/domain_tags/dsm/misc/sofi.rs. The string is exact; formulas in this | DSM-HL-015/L1119 | none |
| SOFI-014-1/L718.b | prohibition | derived | The retired route-outcome/v2 domain cannot be reused. | Every tag below is a constant in CORE/common/domain_tags/dsm/misc/sofi.rs. The string is exact; formulas in this | DSM-HL-015/L1119 | none |
| SOFI-014-1/L760 | prohibition | derived | Reserved membership-handover, trade-digest and reference-window domains cannot be reused for other purposes. | Reserved, never used for anything else | DSM-HL-015/L1119 | none |

### SOFI-014-2 — 14.2 Object classes

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-014-2/L777 | prohibition | derived | Object class numbers remain permanently assigned and are never reassigned. | Class numbers are constants in CORE/ccb/mod.rs (lines 204 to 290). A class number is never reassigned. | DSM-HL-015/L1119 | none |
| SOFI-014-2/L794 | prohibition | derived | Burned object classes 0x0043 through 0x0049 must never identify another object. | 0x0043     to    burned                                        never assigned to any object | DSM-HL-015/L1119 | none |

### SOFI-014-3 — 14.3 Signed objects

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-014-3/L821 | obligation | derived | Signed objects carry body class, canonical body, signature algorithm and signature. | A signed SoFi body travels in SignedSofiObject = (body_class, body_ccb, signature_alg, signature), CORE/sofi/ | DSM-HL-015/L1119 | none |
| SOFI-014-3/L822 | obligation | derived | Compute object identities from canonical body bytes rather than signed envelopes. | wire/objects.rs:638. Identities are always computed over the canonical body bytes, never over the envelope, so a | DSM-HL-015/L1119 | none |
| SOFI-014-3/L823 | obligation | derived | Conforming production signing derives its SPHINCS+ randomizer deterministically from the signing PRF secret and message. | second valid signature over the same body is the same object. Signing is deterministic: the SPHINCS+ randomizer is | DSM-HL-015/L1119 | tension(SOFI-PREAMBLE/L48) |

### SOFI-015 — 15 Derivations

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-015/L831 | obligation | derived | Derive the vault identifier from owner genesis, owner device and creation position using vault-id/v1. | v                       H(vault-id/v1; Go ∥ DevIDo ∥ u64be(pcreate ))                                   vault_id :50 | DSM-HL-016/L1183 | none |
| SOFI-015/L832 | obligation | derived | Derive vault state keys from vault ID and leaf values from class-canonical leaves under the §15 domains. | vault state key         H(vault-state-key/v1; v)                                                        :63 | DSM-HL-016/L1183 | none |
| SOFI-015/L838 | obligation | derived | Hash the branch-specific route digest preimage under route-digest/v1. | Xroute                  H(route-digest/v1; CCB(RouteDigestPreimage))                                    :89 | DSM-HL-016/L1183 | none |
| SOFI-015/L839 | obligation | derived | Derive genesis and creation locators and relationship keys using exactly their §15 committed inputs. | vault genesis locator   H(vault-genesis-locator/v1; v)                                                  :94 | DSM-HL-016/L1183 | none |
| SOFI-015/L842 | obligation | derived | Setup identity binds trader genesis, device, position and vault. | σ                       H(setup-id/v1; G ∥ DevID ∥ u64be(p) ∥ v)                                        :118 | DSM-HL-016/L1183 | none |
| SOFI-015/L843 | obligation | derived | Relationship genesis hashes the setup ID and each next leaf hashes the preceding leaf with E. | h0                      H(rel-genesis/v1; σ)                                                            :126 | DSM-HL-016/L1183 | none |
| SOFI-015/L845 | obligation | derived | Derive the relationship index from trader genesis, device and vault. | relationship index      H(rel-index/v1; G ∥ DevID ∥ v)                                                  :136 | DSM-HL-016/L1183 | none |
| SOFI-015/L847 | obligation | derived | Use separate setup-ref and setup-sign domains for setup identity and signature message. | ρ                       H(setup-ref/v1; CCB(SetupBody))                                                 :141 | DSM-HL-016/L1183 | none |
| SOFI-015/L849 | obligation | derived | Parent ClaimRef hashes the exact accepted economic claim envelope. | ClaimRefp               digest of the exact economic root claim envelope                                :152,            and | DSM-HL-016/L1183 | none |
| SOFI-015/L853 | obligation | derived | Derive precommit identity and signing message from canonical P under their distinct domains. | PrecommitId             H(trader-precommit-id/v1; CCB(P ))                                              :159 | DSM-HL-016/L1183 | none |
| SOFI-015/L855 | obligation | derived | Policy fulfillment identity hashes canonical Gj without auxiliary proof material. | PolicyFulfillmentIdj    H(dlv-policy-fulfillment/v1; CCB(Gj ))                                          :169 | DSM-HL-016/L1183 | none |
| SOFI-015/L856 | obligation | derived | Derive fulfillment identity and signature message from canonical F using their distinct domains. | FulfillmentId           H(fulfillment-id/v1; CCB(F ))                                                   :174 | DSM-HL-016/L1183 | none |
| SOFI-015/L859 | obligation | derived | Derive fulfillment and economic-root keys from genesis, device and economic position under separate domains. | Kful (q)                H(fulfillment/v1; G ∥ DevID ∥ u64be(q))                                         :184 | DSM-HL-016/L1183 | none |
| SOFI-015/L860 | obligation | derived | Recompute Cq from identity, position, fulfillment ID and both precommitted possible roots. | Cq                      (G, DevID, q, FulfillmentId, Rrealize , Rvoid ), class 0x003A                   :193 | DSM-HL-016/L1183 | none |
| SOFI-015/L863 | obligation | derived | Derive attempt zero from vault and parent and later attempts from attempt-zero key plus checked u64 attempt. | K (0)                   H(succ-cell/v2; v ∥ Rn )                                                        :215 | DSM-HL-016/L1183 | none |
| SOFI-015/L866 | obligation | derived | Core and settlement digests hash their exact canonical objects under distinct trader, vault and settlement domains. | c T ◦ , c V ◦ , b◦      H(trader-core/v3;        CCB(T ◦ )),        H(dlv-core/v3;    CCB(V ◦ )),       :237, :242, :247 | DSM-HL-016/L1183 | none |
| SOFI-015/L869 | obligation | derived | Single-leg E binds vault, parent, setup reference, trader core, vault core, settlement and route digest. | E, single leg           H(atomic-ext/v4; v ∥ Rn ∥ ρ ∥ cT ◦ ∥ cV ◦ ∥ b◦ ∥ Xroute )                       :256 | DSM-HL-016/L1183 | none |
| SOFI-015/L870 | obligation | derived | Multivault E binds trader core, settlement, route digest and the canonical hashed leg set. | H(Γ)                    H(route-leg-set/v1; CCB(Γ))                                                     :280 | DSM-HL-016/L1183 | none |
| SOFI-015/L882 | prohibition | derived | E excludes attempts, availability, routing order, member identity and witnesses. | No attempt index, availability view, routing order, member identity or witness enters E. | DSM-HL-016/L1183 | none |

### SOFI-016 — 16 Setup

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-016/L886 | obligation | derived | A trader establishes one setup per vault before its first operation. | A trader sets up once per vault before its first operation against that vault. | DSM-HL-063/L3028 | none |
| SOFI-016/L904 | invariant | derived | Setup equality is equality of the canonical body reference despite alternate envelopes. | Equality of setups is equality of ρ. Alternative valid envelopes over one body are the same setup. The setup body is | DSM-HL-063/L3028 | none |
| SOFI-016/L908 | evidence | explicit | Core validates canonical setup encoding, reference, signature, accepted claim and identity-relationship rules. | SetupValid(setup) is semantic and belongs to Core: canonical body encoding, ρ, the signature over msetup , | DSM-HL-063/L3028 | none |
| SOFI-016/L910 | invariant | explicit | Setup semantic validity and setup durability are separate and acceptance requires both. | SetupRegistered(setup) is a durability fact that Core derives from storage reads. | DSM-HL-063/L3028 | none |
| SOFI-016/L915 | evidence | explicit | SetupRegistered requires its exact body from three members. | SetupRegistered(σ) ⇐⇒ Stored(the setup body): three members of S return its exact bytes (Section 13). | DSM-HL-063/L3028 | none |
| SOFI-016/L919 | transition | explicit | The first relationship-gated operation proves trader h0 and vault noninclusion and advances both to h1. | On the first relationship gated DLV operation, the operation proves the trader leaf h0 and the DLV side non | DSM-HL-063/L3028 | none |
| SOFI-016/L920 | transition | explicit | Later relationship operations advance both sides with H(rel-leaf/v1; preceding leaf ∥ E). | inclusion, and both sides become h1 . On every later operation both sides advance hj → H(rel-leaf/v1; hj ∥ | DSM-HL-063/L3028 | none |

### SOFI-017 — 17 The operation

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-017/L926 | invariant | derived | A route is one trader operation with deterministic effects across referenced vaults rather than independent transactions. | A route is one unilateral trader operation with deterministic effects across the one or more DLV states it references. It | DSM-HL-063/L3028 | none |
| SOFI-017/L936 | obligation | explicit | Construct dependencies in order from exact registered parent through pre-E closure, settlement, E, P, witnesses, F and Cq without a back edge. | ExactRegisteredParentClaim → CE     → B ◦ → E → P → G1 . . . Gn → F → Cq . Nothing depends back on | DSM-HL-063/L3028 | none |

### SOFI-017-1 — 17.1 Stage 1: the trader precommit P

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-017-1/L950 | obligation | derived | P carries trader identity, position, exact parent reference, E, canonical legs, realized and void roots, set ID and signing key. | genesis, device_id               G, DevID             the trader | DSM-HL-063/L3028 | none |
| SOFI-017-1/L969 | invariant | explicit | P occupies no economic position and may be relayed or abandoned without effect. | P is published as a content addressed object and anyone MAY relay it. P occupies no economic position: it installs | DSM-HL-063/L3028 | none |
| SOFI-017-1/L974 | obligation | explicit | Before publication P's identity and position must match its trader core. | 1. G, DevID and p equal those of T ◦ . | DSM-HL-063/L3028 | none |
| SOFI-017-1/L975 | evidence | explicit | P resolves the exact accepted registered predecessor and agrees with the typed pre-E parent reference. | 2. ParentClaimRef resolves to the exact registered predecessor claim at p that Core has accepted, and matches | DSM-HL-063/L3028 | none |
| SOFI-017-1/L978 | prohibition | explicit | An unresolved conditional position cannot supply a predecessor root. | 3. The parent root. An unresolved conditional position has selected no root and is not a predecessor. Ex- | DSM-HL-063/L3028 | none |
| SOFI-017-1/L982 | obligation | explicit | Before publication recompute E, legs, both roots, committed set and the parent's signing-key binding. | 4. E recomputes from P (E). | DSM-HL-063/L3028 | tension(SOFI-006/L506) |
| SOFI-017-1/L989 | prohibition | explicit | Core must not construct, sign, publish, fulfill, register or admit a child of an unresolved conditional position. | Core MUST NOT construct, sign, publish, fulfill, register or admit a child of an unresolved conditional position. | DSM-HL-063/L3028 | none |

### SOFI-017-2 — 17.2 Stage 2: policy fulfillment Gj

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-017-2/L1006 | obligation | derived | Each policy witness binds precommit ID, E, vault, exact parent and exact shadow-core digest. | precommit_id                      PrecommitId         the precommit | DSM-HL-063/L3028 | none |
| SOFI-017-2/L1018 | invariant | derived | A policy fulfillment is unique per precommit, E, vault, exact parent and exact shadow. | The body holds identity fields only. There is exactly one policy fulfillment per (P, E, vault, exact parent, exact shadow), | DSM-HL-063/L3028 | none |
| SOFI-017-2/L1024 | authority | explicit | Gj has no issuer signature and derives validity from the exact parent's policy. | Gj has no issuer signature. Its authority comes from deterministic validation against the exact DLV parent | DSM-HL-063/L3028 | none |
| SOFI-017-2/L1025 | invariant | explicit | Parent canonicality and liveness belong to consumption rather than static policy validation. | state named by P and the policy that parent committed. Whether that parent is canonical or live belongs to | DSM-HL-063/L3028 | none |
| SOFI-017-2/L1031 | obligation | derived | Reference E-dependent auxiliary evidence by witness ID, class and content address without a single poisonable candidate slot. | terial that depends on E is referenced as PolicyFulfillmentAuxRef = (PolicyFulfillmentId, class, content address), | DSM-HL-063/L3028 | none |
| SOFI-017-2/L1036 | evidence | explicit | A verifying auxiliary candidate establishes its validity step. | 1. A verifying candidate establishes that one validity step holds. | DSM-HL-063/L3028 | none |
| SOFI-017-2/L1037 | liveness-boundary | explicit | Absent or nonverifying auxiliary candidates leave evidence pending rather than establishing invalidity. | 2. No candidate, or only nonverifying candidates, gives Unavailable, never Invalid. | DSM-HL-063/L3028 | none |
| SOFI-017-2/L1038 | evidence | explicit | Only uniquely derived canonical evidence classes can establish a negative result from one candidate. | 3. Only a class with one uniquely derived canonical encoding can establish a negative result, because only then | DSM-HL-063/L3028 | none |
| SOFI-017-2/L1040 | liveness-boundary | explicit | Per-class and local work budgets limit hostile candidate processing without changing semantic validity. | 4. A per class candidate budget (MAX_POLICY_FULFILLMENT_AUX_CANDIDATES) and a local budget on bytes, | DSM-HL-063/L3028 | none |
| SOFI-017-2/L1043 | obligation | explicit | Count only verifying evidence used by validation toward the normative fetch-byte limit. | 5. Nonverifying candidates never count toward the normative fetch bound MAX_VALIDATION_FETCH_BYTES; | DSM-HL-063/L3028 | none |

### SOFI-017-3 — 17.3 Stage 3: the trader fulfillment F

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-017-3/L1053 | obligation | derived | F carries the precommit ID, complete canonical witness set, canonical per-vault attempts, next position and signing key. | precommit_id                      PrecommitId         the precommit exercised | DSM-HL-063/L3028 | none |
| SOFI-017-3/L1075 | prohibition | derived | F must not duplicate fields already authoritative in P. | F restates no field of P , so there is no second place for the two to disagree. | DSM-HL-063/L3028 | none |

### SOFI-017-4 — 17.4 Fulfillment ingress

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-017-4/L1081 | transition | explicit | Relay F and recomputed Cq atomically at the common position leader and then replicate identical bytes. | Any     caller       MAY    relay    F.           The       writer   putsF    at Kful (q) and Cq              = | DSM-HL-063/L3028 | tension(SOFI-042-2/L2217) |
| SOFI-017-4/L1085 | obligation | explicit | Kful stores F's signed envelope and Kroot stores canonical Cq. | anywhere but Core. Kful (q) holds the signed envelope of F and Kroot (q) holds CCB(Cq ). Because Cq is | SOFI-017-4/L1081 | none |
| SOFI-017-4/L1093 | invariant | explicit | FulfillmentRegistered is derived finality of both coordinates and is never a node-created record. | FulfillmentRegistered(F ) ⇐⇒ Final(Kful (q), F ) ∧ Final(Kroot (q), Cq ). It is a conclusion Core draws from raw | DSM-HL-063/L3028 | tension(DSM-HL-005/L298) |

### SOFI-017-5 — 17.5 The exercise

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-017-5/L1099 | obligation | derived | The exercise carries signed F, signed P, the settlement preimage, every leg witness and every referenced pre-E closure object. | The value written to each successor key of a route is the exercise: one canonical object, class 0x005D (SOFI_EXERCISE, | DSM-HL-063/L3028 | none |
| SOFI-017-5/L1111 | evidence | explicit | Only an exercise whose F names the vault-attempt and whose P names the vault-parent counts at that successor key. | At a successor key K = K (a) of vault v at parent Rn , the value that counts is the first exercise at the leader | DSM-HL-063/L3028 | ambiguous |

### SOFI-018-1 — 18.1 The preimage

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-018-1/L1133 | obligation | derived | The settlement preimage contains settlement, trader core and all vault cores under strict canonical decoding. | P (E)                       SettlementPreimage{settlement, trader_core, dlv_cores},                     CORE/sofi/wire/ | DSM-HL-063/L3028 | none |
| SOFI-018-1/L1135 | obligation | derived | Swap settlement binds endpoints, exact amounts, hop-ordered hops, trader core and vault-ID-sorted core digests. | B ◦ , Swap                  token_in, amount_in, token_out, exact_out, hop ordered hops, cT ◦ , the cV ◦ sorted by | DSM-HL-063/L3028 | none |
| SOFI-018-1/L1138 | obligation | derived | Close settlement binds vault, parent, setup, owner authority, exact reserves, cores and pre-E closure. | B ◦ , Close                 vault_id, parent_root, setup_ref, owner_authority, reserve_a, reserve_b, cT ◦ , cV ◦ , | DSM-HL-063/L3028 | none |
| SOFI-018-1/L1144 | obligation | derived | Pre-E closure contains only E-independent typed references. | CE                          PreEClosureIndex{refs}, CORE/sofi/wire/objects.rs:886, class 0x0041: objects in- | DSM-HL-063/L3028 | none |
| SOFI-018-1/L1152 | prohibition | derived | P, Gj and the settlement, trader-core, vault-core and preimage classes cannot occur inside pre-E closure. | P and every Gj contain E, so neither can ever appear in CE   . The classes of B ◦ , T ◦ , V ◦ and P (E) are forbidden | DSM-HL-063/L3028 | none |

### SOFI-018-2 — 18.2 Inputs after E

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-018-2/L1158 | prohibition | derived | P, witness sets, auxiliary evidence, F and Cq remain post-E validation inputs rather than inputs to E. | These are inputs to validation and are never committed by E: P by PrecommitId; the canonical policy fulfillment | DSM-HL-063/L3028 | none |

### SOFI-018-3 — 18.3 Choosing the form of E

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-018-3/L1165 | obligation | explicit | Use atomic-ext/v4 for Close and one-leg Swap and atomic-ext/multivault/v5 for multi-leg Swap. | A Swap with one leg and every Close use the single leg form (atomic-ext/v4). A Swap with two or more legs | DSM-HL-063/L3028 | none |
| SOFI-018-3/L1166 | transition | explicit | BindExt inserts E and the next relationship leaf into relationship post-state. | uses the route form (atomic-ext/multivault/v5). BindExt inserts the external commitment and hj+1 into | DSM-HL-063/L3028 | none |

### SOFI-018-4 — 18.4 Bounds

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-018-4/L1171 | invariant | derived | Known normative bound violations are Invalid rather than evidence unavailability. | A known bound violation is Invalid, never Unavailable. | DSM-HL-063/L3028 | none |
| SOFI-018-4/L1175 | obligation | derived | A closure has at most 64 references. | \| references in a closure \| 64 \| `MAX_CLOSURE_REFS :211` \| | DSM-HL-063/L3028 | none |
| SOFI-018-4/L1176 | obligation | derived | Each canonical closure object is at most 256 KiB. | \| canonical bytes per object \| 256 KiB \| `MAX_CLOSURE_OBJECT_BYTES :213` \| | DSM-HL-063/L3028 | none |
| SOFI-018-4/L1177 | obligation | derived | Validation includes at most 16 signed authorization envelopes. | \| signed envelopes (P, F, parent envelopes) \| 16 \| `MAX_AUTH_ENVELOPES :215` \| | DSM-HL-063/L3028 | none |
| SOFI-018-4/L1178 | obligation | derived | Unique verifying evidence fetched for validation is bounded by 4 MiB. | \| aggregate unique fetch \| 4 MiB \| `MAX_VALIDATION_FETCH_BYTES :218` \| | DSM-HL-063/L3028 | none |
| SOFI-018-4/L1179 | obligation | derived | Direct provenance fanout is at most 16. | \| direct provenance fanout per transition \| 16 \| `MAX_PROVENANCE_FANOUT :221` \| | DSM-HL-063/L3028 | none |
| SOFI-018-4/L1180 | obligation | derived | The settlement preimage is at most 256 KiB. | \| P(E) \| 256 KiB \| `MAX_SETTLEMENT_PREIMAGE_BYTES :223` \| | DSM-HL-063/L3028 | none |

### SOFI-019-1 — 19.1 Leaves

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-019-1/L1195.a | obligation | derived | Vault state commits owner identity, creation position, policy addresses, set ID, generation, both reserves and status. | \| vault state \| Key `H(vault-state-key/v1; v)`. Fields of `VaultStateLeaf` (`CORE/sofi/wire/objects.rs:1224`): `owner_genesis`, `owner_device_id`, `create_position`, `market_policy`, `fee_policy`, `release_policy`, `storage_set_id`, `generation`, `reserve_a`, `reserve_b`, `status`. Active means both reserves positive; Retired means both zero, and Retired is terminal. \| | DSM-HL-063/L3028 | none |
| SOFI-019-1/L1195.b | invariant | derived | Active vaults have two positive reserves and terminal Retired vaults have two zero reserves. | \| vault state \| Key `H(vault-state-key/v1; v)`. Fields of `VaultStateLeaf` (`CORE/sofi/wire/objects.rs:1224`): `owner_genesis`, `owner_device_id`, `create_position`, `market_policy`, `fee_policy`, `release_policy`, `storage_set_id`, `generation`, `reserve_a`, `reserve_b`, `status`. Active means both reserves positive; Retired means both zero, and Retired is terminal. \| | DSM-HL-063/L3028 | none |
| SOFI-019-1/L1196 | obligation | derived | Vault relationship leaves retain trader identity and current head for deterministic replay. | \| vault relationship \| Key kT,v. Fields of `VaultRelationshipLeaf` (`:1288`): `trader_genesis`, `trader_device_id`, `leaf = hj`. The key material is explicit, so the tree can be rebuilt by replay. \| | DSM-HL-063/L3028 | none |
| SOFI-019-1/L1197 | transition | derived | Setup inserts one previously absent trader relationship at h0 and only resolution advances it. | \| trader relationship \| In the trader’s economic tree as `EconomicLeafState::Relationship` (`CORE/economic/state.rs:308`); `TraderRelationshipLeaf{vault_id, leaf}` (`:1320`). A setup inserts exactly one, with no prior value and `h0 = H(rel-genesis/v1; σ)`. Only resolution advances it. \| | DSM-HL-063/L3028 | none |
| SOFI-019-1/L1201 | obligation | derived | Derive vault ID and omit redundant parent-root and owner-authority-position state fields. | Not stored: vault_id (derived and checked), a parent root (the generation keeps roots unique), and the owner | DSM-HL-063/L3028 | none |
| SOFI-019-1/L1202 | prohibition | derived | All swap input including fees stays in the input reserve and additional liquidity requires close-and-recreate. | authority position. The whole input of a trade, fee included, stays in reserve_in. There is no add liquidity operation: | DSM-HL-063/L3028 | none |

### SOFI-019-2 — 19.2 Cores and the batch fold

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-019-2/L1209 | evidence | derived | Every mutation, read and relationship entry supplies its pre-root path with all 256 siblings. | against the pre root: Mutation{key, pre, post, path}, Read{key, value, path} or Relationship{genesis, | DSM-HL-063/L3028 | none |
| SOFI-019-2/L1211 | obligation | derived | Compute post roots by one batch fold against the common pre-root. | root (batch_fold and verify_batch, CORE/sofi/smt/fold.rs:178 and :197). A single batch is required because | DSM-HL-063/L3028 | none |

### SOFI-019-3 — 19.3 Closed write sets

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-019-3/L1217 | prohibition | derived | Permit no core entries outside the branch's closed write set. | No entry outside these sets is permitted in either branch. | DSM-HL-063/L3028 | none |
| SOFI-019-3/L1220 | transition | derived | Swap debits trader input, credits output and advances each relationship while updating vault reserves and generation. | Swap          T ◦ : debit token_in, credit token_out, one relationship advance per leg. Each Vj◦ : VaultState Active | DSM-HL-063/L3028 | none |
| SOFI-019-3/L1222 | transition | derived | Close credits both exact reserves without debit and retires the vault with zero reserves and matching relationship advancement. | Close         token_a and token_b come from the referenced vault’s market policy. T ◦ : credit token_a by reserve_ | DSM-HL-063/L3028 | none |

### SOFI-019-4 — 19.4 Route digest and leg rules

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-019-4/L1234 | obligation | explicit | Canonical codecs accept arbitrary positive Swap leg counts within the object bound and at least two for Γ. | 1. The canonical codec, decoder and recompute_e accept any number of legs from one upward for Swap (two up- | DSM-HL-063/L3028 | none |
| SOFI-019-4/L1236 | prohibition | explicit | The two-leg admission cap must not restrict canonical constructors or decoders. | 2. The route cap ROUTE_MAX_LEGS = 2 (:184) is admission and builder policy only (admissible, CORE/sofi/ | DSM-HL-063/L3028 | none |
| SOFI-019-4/L1239 | invariant | explicit | Every route references pairwise-distinct vault IDs. | 3. Vault ids within one route are pairwise distinct: each DLV parent is referenced at most once. | DSM-HL-063/L3028 | none |

### SOFI-019-5 — 19.5 Static economics

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-019-5/L1243 | obligation | derived | Per-hop output equals committed constant-product pricing with checked reserve updates. | Swap. Per leg, amount_out equals constant_product_output(amount_in, reserve_in, reserve_out, fee_bps) | DSM-HL-063/L3028 | none |
| SOFI-019-5/L1244 | obligation | derived | Hops must chain, match intent endpoints, satisfy each intermediate token's policy and conserve each token. | (CORE/dlv/route_commit.rs:151), with checked reserve updates; hops chain; the intent endpoints match; the Swap | DSM-HL-063/L3028 | none |
| SOFI-019-5/L1252 | obligation | derived | Close uses no swap pricing and requires exact reserve return, retirement, conservation and owner-local-full-close release authority. | Close. No constant product pricing applies. The Close write sets hold; VaultState goes from Active to Retired with | DSM-HL-063/L3028 | none |
| SOFI-019-5/L1259 | invariant | explicit | Static validity creates no spendable credit. | A static Valid proves pricing, conservation and the legitimacy of the proposed result. It creates no canonical | DSM-HL-063/L3028 | none |
| SOFI-019-5/L1260 | transition | explicit | Only Realized installs the folded root; Void retains the preceding validated root without credit. | or spendable credit. Trader output becomes canonical only when the position resolves Realized and advance_ | DSM-HL-063/L3028 | none |
| SOFI-019-5/L1261 | prohibition | explicit | SoFi introduces no independent credit-source arm and cannot be accepted as a validated peer debit. | resolved installs P.Rrealize . Void installs the previous validated root and creates no credit. No new credit source | DSM-HL-063/L3028 | none |

### SOFI-019-6 — 19.6 Advancing the lineage

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-019-6/L1266 | authority | derived | Only advance_resolved constructs the validated economic root for a SoFi position. | advance_resolved (CORE/sofi/lineage.rs:114) is the only constructor of a validated economic root at q for a SoFi | DSM-HL-063/L3028 | none |
| SOFI-019-6/L1267 | obligation | derived | Advancement verifies consecutive positions, recomputed Cq, exact preceding claim, both roots and the actual validated parent. | position. It checks q = P.p + 1 = previous +1; recomputes Cq from P and F and never reads it from a regis- | DSM-HL-063/L3028 | none |
| SOFI-019-6/L1270 | transition | derived | Realized selects the realization root, Void retains the previous root and Invalid terminates the lineage. | installs the previous root, and Invalid is terminal. | DSM-HL-063/L3028 | none |

### SOFI-019-7 — 19.7 Close authority

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-019-7/L1275 | authority | derived | Close requires origin-owner identity, correctly bound signatures, owner setup and the committed full-close release policy. | branch. A Close is authorized if and only if: P.G equals owner_genesis and P.DevID equals owner_device_id; P | DSM-HL-063/L3028 | none |
| SOFI-019-7/L1280 | prohibition | explicit | DsmSuccessor authority encodes canonically but is semantically Invalid and no producer emits it. | DsmSuccessor decodes and encodes canonically and is always refused by semantic validation as Invalid, never | DSM-HL-063/L3028 | none |

### SOFI-019-8 — 19.8 Vault genesis

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-019-8/L1291 | evidence | explicit | Genesis acceptance recomputes an active generation-zero vault with no relationships and reserves exactly equal to owner funding debits. | All of the following hold: R0 recomputes and V0 holds exactly the initial vault state (generation zero, Active, no | DSM-HL-063/L3028 | none |
| SOFI-019-8/L1293 | obligation | explicit | Genesis binds derived vault ID, inserting position, ordered token pair, network-pinned set and validated owner root. | pcreate the inserting position; token_a < token_b; the storage set is the network’s pinned set; the owner’s root | DSM-HL-063/L3028 | none |
| SOFI-019-8/L1294 | authority | explicit | Genesis storage alone is not acceptance and owner attribution must come from authenticated construction evidence. | at p is validated. Locator writes are attributed to the owner. GenesisStored is only a storage fact. | DSM-HL-063/L3028 | ambiguous |
| SOFI-019-8/L1296 | obligation | explicit | An owner may trade against its own vault under ordinary rules with fees retained in reserves. | An owner MAY trade against its own vault; no special case applies, and the fee stays in the reserves. | DSM-HL-063/L3028 | none |

### SOFI-020-1 — 20.1 RouteValidation

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-020-1/L1313 | invariant | explicit | RouteValidation conjoins every leg's policy fulfillment with trader-side and route-wide validity. | RouteValidation(P, G, E) =       PolicyFulfillmentValid(P, Gj , E) | DSM-HL-063/L3053 | none |
| SOFI-020-1/L1321 | evidence | explicit | Static route validation covers setups, policies, arithmetic, branch effects, conservation, relationships, scope, exact shadows, parent and signatures. | It covers, for every required leg: SetupValid of that leg’s setup; policy fulfillment; arithmetic and reserves; the exact | DSM-HL-063/L3053 | none |
| SOFI-020-1/L1327 | prohibition | explicit | Static route validity cannot depend on attempts, finality, canonicality, liveness or resolution outcome. | RouteValidation never depends on attempt indices, storage finality, canonicality, attempt liveness or any out- | DSM-HL-063/L3053 | none |

### SOFI-020-2 — 20.2 FulfillmentConformance

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-020-2/L1346 | evidence | explicit | Fulfillment conformance requires the exact valid P and checked next position. | 1. the exact referenced P is available and verifies, and q = P.p + 1 with checked arithmetic; | DSM-HL-063/L3053 | none |
| SOFI-020-2/L1347 | evidence | explicit | F's signature uses the same key committed by P. | 2. F is signed, and its key equals the key P committed; | DSM-HL-063/L3053 | none |
| SOFI-020-2/L1348 | invariant | explicit | The witness set equals the complete canonical derived set without missing, extra or foreign IDs. | 3. the policy fulfillment set is complete and canonical: it equals Canon[PolicyFulfillmentIdj (P, j)] over every | DSM-HL-063/L3053 | none |
| SOFI-020-2/L1350 | invariant | explicit | Attempts cover every P leg exactly without holes. | 4. the attempts cover exactly the legs of P , with no numeric holes; | DSM-HL-063/L3053 | none |
| SOFI-020-2/L1351 | evidence | explicit | A nonzero attempt requires permanent storage resolution of its predecessor. | 5. for every aj > 0, the earlier attempt K (aj −1) has a permanent storage resolution; | DSM-HL-063/L3053 | none |
| SOFI-020-2/L1352 | evidence | explicit | Every leg's setup must be registered. | 6. SetupRegistered holds for every leg (Section 13); | SOFI-016/L915 | none |
| SOFI-020-2/L1353 | obligation | explicit | Fulfillment conformance enforces identities, bounds and available verified settlement and closure evidence. | 7. identities and bounds hold; | DSM-HL-063/L3053 | none |
| SOFI-020-2/L1358 | prohibition | explicit | A producer may publish F only after obtaining complete conformance. | A producer MUST obtain Valid before it publishes F . | DSM-HL-063/L3053 | ambiguous |

### SOFI-021 — 21 Exercise and atomicity

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-021/L1371 | transition | explicit | Fulfillment registration is the irreversible exercise boundary after which anyone can finish publication and cell writes. | FulfillmentRegistered(F ) is the exercise. Publishing P is not, and no policy fulfillment witness is. After regis- | SOFI-017-4/L1093 | none |
| SOFI-021/L1375 | prohibition | explicit | Store no route-outcome register. | 1. No outcome register. Nothing stores a route outcome. Core derives completion or permanent defeat from the | DSM-HL-063/L3053 | none |
| SOFI-021/L1377 | authority | explicit | Cell occupancy grants no economic authority. | 2. Occupancy is not admissibility. A value in a successor cell carries no economic authority by being stored, and | SOFI-019-5/L1259 | none |
| SOFI-021/L1379 | invariant | explicit | A route consumes every required leg or none and a losing exercise guarantees no success. | 3. All or none. A route is realized only by the all leg predicate of Section 23. If any required leg cannot resolve to | DSM-HL-063/L3053 | none |
| SOFI-021/L1381 | prohibition | explicit | Policy witnesses must not prepare-lock parents. | 4. No prepare lock. Policy fulfillment witnesses do not lock parents, and success after F is never claimed. | SOFI-005-4/L480 | none |

### SOFI-021-1 — 21.1 Registration and realizability are separate

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-021-1/L1385 | invariant | explicit | Realizability requires an unconsumed compatible trader parent and every referenced vault parent available to E. | P , G and F are realizable only while the trader parent T0 has not been consumed by an incompatible trader transi- | DSM-HL-063/L3053 | none |
| SOFI-021-1/L1387 | invariant | explicit | A fulfillment may register after a vault parent is lost but cannot then realize. | T0 . A fulfillment MAY register after one of its DLV parents was lost; it can then never be realized. | DSM-HL-063/L3053 | none |
| SOFI-021-1/L1390 | transition | explicit | An invalid conformance or route predicate makes the position Invalid; unknown evidence waits and a valid permanently defeated route becomes Void, subject to S1. | If either predicate is Invalid, the position is Invalid. Otherwise, if either is Unavailable, the position is Pending. | DSM-HL-063/L3053 | none |
| SOFI-021-1/L1399 | invariant | explicit | Successor-cell finality and fulfillment registration remain independent and consumption requires both. | StorageFinalE(K, E) and FulfillmentRegistered(F ) are independent: a writer can make E final at a successor | DSM-HL-063/L3053 | none |

### SOFI-022 — 22 The predecessor rule

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-022/L1405 | evidence | derived | A conditional predecessor is usable only after selecting one exact root. | A child needs an exact selected predecessor root. A conditional predecessor becomes usable only when resolution | DSM-HL-063/L3053 | none |
| SOFI-022/L1410 | transition | derived | Children of Realized use its realization root and children of Void use the previous validated root. | \| Realized \| P.Rrealize \| May be constructed against exactly that root \| | DSM-HL-063/L3053 | none |
| SOFI-022/L1415 | invariant | derived | At most one fulfillment per lineage remains unresolved and storage resolution never authorizes a predecessor. | At most one fulfillment per lineage is unresolved in storage at a time. StorageResolved survives only as an input in- | DSM-HL-063/L3053 | none |
| SOFI-022/L1419 | prohibition | explicit | Core fences all descendants of an unresolved conditional predecessor. | Core blocks any descendant economic root while a conditional predecessor is unresolved for the verifier. | DSM-HL-063/L3053 | none |

### SOFI-023-1 — 23.1 Successor resolution

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-023-1/L1435 | evidence | explicit | Core derives successor resolution from raw reads and caches cannot establish it. | For a successor key K, Core derives SuccessorResolution(K) from raw reads: Unresolved, or Final(x) when | DSM-HL-063/L3053 | none |
| SOFI-023-1/L1437 | transition | explicit | A later attempt becomes usable only when its predecessor is skipped. | names it reaches its leader. LeaderHeld(K, x) settles early that no other value will be final at K. A cache never | SOFI-023-2/L1442 | none |

### SOFI-023-2 — 23.2 Consumed route

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-023-2/L1442 | invariant | derived | AttemptLive requires all earlier attempts skipped. | AttemptLive(v, R, a) ⇐⇒ ∀b < a. Skipped(K (b) ) | DSM-HL-063/L3053 | none |
| SOFI-023-2/L1447 | invariant | explicit | ConsumedRoute requires registration, conformance, route validity, compatible trader parent and every canonical live final leg. | ConsumedRoute(F, E) ⇐⇒ FulfillmentRegistered(F ) | DSM-HL-063/L3053 | none |

### SOFI-023-3 — 23.3 Trader parent compatibility

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-023-3/L1462 | evidence | derived | Parent compatibility requires the exact selected trader root and impossibility requires terminal absence or a different root. | TraderParentCompatible(P ) holds when T0 is a single root claim, or when T0 = Cp and position p selected exactly | DSM-HL-063/L3053 | none |
| SOFI-023-3/L1464 | invariant | derived | A pending trader parent establishes neither compatibility nor impossibility. | different from T ◦ .pre_root. Both are objective and monotone. While p is Pending both are false, so that parent | DSM-HL-063/L3053 | none |

### SOFI-023-4 — 23.4 Routes with more than one leg

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-023-4/L1472 | invariant | derived | A final multivault cell is evidence for one whole operation and never an independently executed hop. | Every DLV state P references is a deterministic consequence of one trader operation bound to one E. One final E | SOFI-021/L1379 | none |
| SOFI-023-4/L1475 | transition | derived | Permanent route impossibility skips stranded cells without rollback because they never independently consumed reserves. | tion can never be realized, and it resolves Void once storage has resolved and RouteValidation is Valid. A stranded E | DSM-HL-063/L3053 | none |

### SOFI-023-5 — 23.5 Impossibility and skips

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-023-5/L1483 | invariant | explicit | Fulfillment impossibility follows only from invalid conformance or route impossibility. | FulfillmentImpossible(F, E) ⇐⇒ FulfillmentConformance(F ) = Invalid ∨ RouteImpossible(P (F ), E). | DSM-HL-063/L3053 | ambiguous |
| SOFI-023-5/L1484 | prohibition | explicit | Missing evidence cannot establish impossibility. | Unavailable is never a ground for impossibility; it waits. | DSM-HL-063/L3053 | none |
| SOFI-023-5/L1486 | obligation | derived | RouteImpossible depends on P and E rather than a particular F. | RouteImpossible(P, E) is scoped to P and E only and takes no F , because several candidate fulfillments can refer- | DSM-HL-063/L3053 | none |
| SOFI-023-5/L1488 | evidence | derived | Invalid static validation, orphaned parent, differently consumed parent or impossible trader parent can establish route impossibility. | (i) RouteValidation(P, G, E) = Invalid. Static, monotone and a function of P alone, since the canonical witness set | DSM-HL-063/L3053 | none |
| SOFI-023-5/L1499 | evidence | derived | Structural parent-impossibility arms can skip stranded cells despite unrelated missing validation evidence. | Arms (ii) to (iv) need no validation evidence, so a stranded DLV cell of an impossible operation is skippable even | DSM-HL-063/L3053 | none |
| SOFI-023-5/L1500 | invariant | derived | An impossible trader predecessor terminates the position as Invalid rather than manufacturing Void. | while other evidence is Unavailable. Arm (iv) creates no Void: the position becomes Invalid through the predecessor | DSM-HL-063/L3053 | none |
| SOFI-023-5/L1504 | transition | derived | Single-leg skipping requires finality, canonical parent, live attempt and fulfillment impossibility. | RejectedFinalSingleLeg(K, F, E)         StorageFinalE(K, E) ∧ CanonicalParent ∧ AttemptLive ∧ | DSM-HL-063/L3053 | ambiguous |
| SOFI-023-5/L1506 | transition | derived | Route skipping requires finality and impossibility of the registered fulfillment that names the leg. | RejectedFinalRoute(Kj , F, E)           StorageFinalE(Kj , E) ∧ FulfillmentImpossible(F, E), where F is | DSM-HL-063/L3053 | none |

### SOFI-023-6 — 23.6 The walk

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-023-6/L1516 | obligation | derived | Walk attempts in numeric order, continue past skipped attempts, stop at consumption and otherwise remain unresolved. | For one DLV parent, the walk visits K (0) , K (1) , . . . in order: a skipped key moves to the next attempt, a consumed key | DSM-HL-063/L3053 | none |
| SOFI-023-6/L1517 | invariant | derived | A budgeted walk returns a continuation cursor and chunked execution equals uninterrupted execution. | stops the walk, anything else is unresolved. The walk is budgeted and returns Continue(cursor) when the budget | DSM-HL-063/L3053 | none |
| SOFI-023-6/L1522 | invariant | derived | Dependencies respect increasing positions and construction order from P through witnesses to F. | Dependencies that are structurally earlier are fixed by the constructors: p < q, and P before G before F . A single or | DSM-HL-063/L3053 | none |
| SOFI-023-6/L1523 | evidence | derived | A referenced producer tuple must be storage-reachable so the operation can be reconstructed. | route parent is orphaned once its canonical successor at g + 1 resolves to something else. A producer tuple (v, R, E) | DSM-HL-063/L3053 | none |

### SOFI-024 — 24 Resolution of a trader position

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-024/L1529 | obligation | derived | Resolve positions by the first matching ladder rung and keep nonpending decisions permanent. | Resolution is local to the verifier, deterministic, and permanent once it is not Pending. The first matching row decides. | DSM-HL-063/L3053 | none |
| SOFI-024/L1533 | transition | derived | An unregistered fulfillment remains Pending. | \| 0 \| Pending \| ¬FulfillmentRegistered(q, F) \| | DSM-HL-063/L3053 | none |
| SOFI-024/L1534 | transition | derived | Externally supplied unresolved predecessors wait while terminal or wrong-root predecessors become terminal Invalid. | \| 1 \| Pending \| Defensive: an object supplied from outside names an unresolved conditional predecessor \| | DSM-HL-063/L3053 | none |
| SOFI-024/L1536 | transition | derived | Invalid conformance or route validity terminates the position and fetching-required rungs remain Pending under S3. | \| 3 \| Invalid \| FulfillmentConformance(F) = Invalid; terminal \| | DSM-HL-063/L3053 | none |
| SOFI-024/L1540 | transition | derived | ConsumedRoute resolves Realized. | \| 7 \| Realized \| ConsumedRoute(F, E) \| | DSM-HL-063/L3053 | none |
| SOFI-024/L1541 | transition | derived | Both-valid permanently defeated routes resolve Void and unresolved cases remain Pending. | \| 8 \| Void \| Both predicates Valid and the route is permanently defeated: a reserved key’s leader holds another exercise first, or StorageFinalE(K, X ≠ E); a leg parent is Consumed(X ≠ E); a leg parent is orphaned \| | DSM-HL-063/L3053 | none |
| SOFI-024/L1545 | prohibition | explicit | Registration cannot bypass conformance checks. | No shortcut from registration to conformance exists. Rungs 1 and 2 are defensive: a conforming producer never | DSM-HL-063/L3053 | none |
| SOFI-024/L1555 | invariant | derived | Void performs no mutations and cannot later become Invalid. | established before Void is declared, so no position ever moves from Void to Invalid. A Void position performs zero | DSM-HL-063/L3053 | none |
| SOFI-024/L1556 | invariant | derived | Fulfillment registration and ordinary economic-root registration at one position must agree on Cq. | mutations. Mutual exclusion holds: FulfillmentRegistered(q) ∧ EconomicRootRegistered(q, C) ⇒ C = Cq . | DSM-HL-063/L3053 | none |
| SOFI-024/L1560.a | prohibition | explicit | Realized, Void, Invalid and Pending are verifier-derived results and must never be stored. | > **Amendment S1 (owner, 2026-09-22) — nothing negative is recorded, and Pending can end.** Realized, Void, Invalid and Pending are computed by each verifier from raw reads and are never recorded (DSM Amendment A1). Their job is to tell the next trade against a vault whether the balance ahead of it is settled. A position that stays Pending on one party may be challenged under `DSM_Storage_Node_Specification.md` §9.1: if the challenged party does not answer before the cell's leader has closed X ByteCommits, a drop claim wins at the leader and the position resolves Void. It never executes and moves no balance. The value of X is still open (storage §9.1). | DSM-HL-063/L3053 | tension(DSM-HL-005/L298) |
| SOFI-024/L1560.b | transition | explicit | A party-dependent pending position can be challenged and a winning eligible drop claim resolves it Void without moving balances. | > **Amendment S1 (owner, 2026-09-22) — nothing negative is recorded, and Pending can end.** Realized, Void, Invalid and Pending are computed by each verifier from raw reads and are never recorded (DSM Amendment A1). Their job is to tell the next trade against a vault whether the balance ahead of it is settled. A position that stays Pending on one party may be challenged under `DSM_Storage_Node_Specification.md` §9.1: if the challenged party does not answer before the cell's leader has closed X ByteCommits, a drop claim wins at the leader and the position resolves Void. It never executes and moves no balance. The value of X is still open (storage §9.1). | DSM-HL-063/L3053 | tension(DSM-HL-005/L297.c) |
| SOFI-024/L1560.c | obligation | explicit | The challenge count X remains open rather than an implementation-chosen validity parameter. | > **Amendment S1 (owner, 2026-09-22) — nothing negative is recorded, and Pending can end.** Realized, Void, Invalid and Pending are computed by each verifier from raw reads and are never recorded (DSM Amendment A1). Their job is to tell the next trade against a vault whether the balance ahead of it is settled. A position that stays Pending on one party may be challenged under `DSM_Storage_Node_Specification.md` §9.1: if the challenged party does not answer before the cell's leader has closed X ByteCommits, a drop claim wins at the leader and the position resolves Void. It never executes and moves no balance. The value of X is still open (storage §9.1). | — | ambiguous |

### SOFI-025 — 25 Crash and recovery

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-025/L1568 | transition | derived | Precommit-only or unpublished fulfillment crash states have no economic effect and may be abandoned. | \| P signed or stored, witnesses computed, no F \| nothing economic; the trader may abandon \| nothing \| | DSM-HL-063/L3053 | none |
| SOFI-025/L1571 | transition | derived | After leader receipt relayers can finish copies and after registration can complete all remaining publication. | \| F held by the leader of Kful(q), fewer than two copies \| the race at q is settled for F; relayers complete the copies \| Pending \| | DSM-HL-063/L3053 | none |
| SOFI-025/L1575 | evidence | derived | Even after every cell is final recovery must evaluate the complete consumption predicate. | \| every required cell final \| Core evaluates the full ConsumedRoute; storage finality alone gives no result \| Realized only if the whole conjunction holds \| | DSM-HL-063/L3053 | none |

### SOFI-026 — 26 The stack

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-026/L1609 | authority | explicit | Producers assemble and publish while Core interprets evidence and advances state through its unchanged result. | Producers assemble and publish; Core decides. A producer never interprets a storage read, never skips a Core | DSM-HL-078/L3893 | none |

### SOFI-027 — 27 Routes

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-027/L1615 | obligation | derived | Expose create, setup, findRoute, trade, route, close, relay and resolve through their specified SoFi routes. | The app reaches SoFi only through these routes in SDK/handlers/sofi_routes.rs. | DSM-HL-063/L3028 | none |
| SOFI-027/L1621 | authority | derived | Path-search output carries no economic authority. | \| `sofi.findRoute` \| Path search over walked vault heads \| A hop list; carries no authority \| | DSM-HL-063/L3028 | none |

### SOFI-028 — 28 Creating a vault

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-028/L1637 | transition | derived | Vault creation verifies the owner's signed operation before debiting funds, inserting the creation leaf and registering its position. | 3. The owner’s transition carries SofiVaultCreate through the Core transition: verify_operation (CORE/sofi/ | DSM-HL-063/L3028 | none |
| SOFI-028/L1640 | obligation | derived | Publish the genesis preimage as an object indexed by the derived genesis locator. | 4. The genesis preimage is put as an object and indexed under vault_genesis_locator(v) (CORE/sofi/derive.rs: | DSM-HL-063/L3028 | none |

### SOFI-029 — 29 Setting up with a vault

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-029/L1650 | obligation | derived | Publish and index setup bodies and insert the derived h0 through the Core setup transition. | 2. The setup body is put as an object and indexed under ρ. SetupRegistered holds once it is Stored. | DSM-HL-063/L3028 | none |

### SOFI-030 — 30 Finding the head of a vault

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-030/L1658 | obligation | derived | Discover a vault head by accepted genesis and canonical successor walking rather than advertisements. | 1. Fetch the genesis preimage through its index, accept it, and start at R0 . | DSM-HL-063/L3053 | none |
| SOFI-030/L1667 | transition | derived | A consumed attempt advances to its folded vault root and an unresolved attempt leaves the current head and attempt live. | 3. A consumed attempt names its fulfillment; the consumed route’s Vj◦ post root is Rn+1 . A skipped attempt moves | DSM-HL-063/L3053 | none |

### SOFI-031 — 31 A trade and a multihop route

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-031/L1682 | prohibition | derived | Producers stop drafting progression unless admission, signature and complete route validation succeed. | \| 3 — validate \| `preimage_admissible` (`CORE/sofi/admission.rs:78`); evidence acquired from storage (rebuild step R5); `route_validation` (`CORE/sofi/validation.rs:338`) must return Valid, verifying each core with `verify_batch` (`CORE/sofi/smt/fold.rs:197`) and each leaf pre value with `verify` (`CORE/sofi/smt/tree.rs:402`); `verify_precommit` (`CORE/sofi/signature.rs:215`). Any other result stops the producer. \| | DSM-HL-063/L3053 | none |
| SOFI-031/L1683 | obligation | derived | Publish P, its preimage and closure with required storage durability before exercise. | \| 4 — publish \| P indexed under PrecommitId, P(E) under `preimage_locator(E)` (`CORE/sofi/derive.rs:424`), and every closure object, each put and Stored. \| | DSM-HL-063/L3053 | none |
| SOFI-031/L1685 | obligation | derived | Construct signed F from live walked attempts and complete derived witnesses through Core. | \| 6 — exercise \| `build_fulfillment` picks each hop’s live attempt aj from the walk, advancing with `next_attempt` (`CORE/sofi/wire/mod.rs:341`), builds and signs F; `check_fulfillment_against_precommit` (`CORE/sofi/conformance.rs:100`) must return Valid; Cq comes from `resolution_claim` (`CORE/sofi/derive.rs:193`). The trader’s transition carries `SofiFulfill` through the Core transition, where `verify_operation` checks it. This is the state advancement that holds the key. \| | DSM-HL-063/L3053 | none |
| SOFI-031/L1696 | invariant | explicit | A permanently defeated hop voids the whole route and skips other final but unconsumed route cells. | Every hop lands at its own vault’s cell under that vault’s own leader, and no vault waits for another. The route | SOFI-021/L1379 | none |

### SOFI-032 — 32 Closing a vault

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-032/L1706 | transition | derived | Close follows the one-leg settlement pipeline and returns the exact reserves under release policy. | draft_close builds B ◦ = Close{vault_id, parent_root, setup_ref, reserve_a, reserve_b} as a one hop route against | DSM-HL-063/L3053 | none |

### SOFI-033 — 33 Relaying

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-033/L1712 | obligation | derived | Relaying recomputes keys and completes missing exercises and copies without requiring trader participation. | sofi.relay completes any registered fulfillment whose hops are not all final: it reads F at the position, recomputes | DSM-HL-063/L3053 | none |

### SOFI-034 — 34 Every Core SoFi function, placed

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-034/L1746 | obligation | derived | Validate staged post-tree frontiers before installation and retain only nodes reachable from validated roots. | validate_staged_frontier,                 the trader’s tree store: staged post trees are validated before stage 7, and | DSM-HL-063/L3028 | none |

### SOFI-035 — 35 Rules

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-035/L1765 | obligation | explicit | Every public SoFi item has a production caller or is test-only; unused production items must be wired or removed. | Every public item under CORE/sofi/ is called from production code, or it is test support and lives under | DSM-HL-078/L3893 | none |
| SOFI-035/L1770 | evidence | explicit | Core evidence is real fetched or trader-published bytes with rehashed addresses and strict canonical decoding. | Every evidence item Core consumes is bytes that were fetched from storage by content address or coordinate, or | DSM-HL-078/L3893 | none |
| SOFI-035/L1772 | prohibition | explicit | Do not synthesize evidence, fill defaults or substitute cached verdicts. | Evidence is never defaulted, synthesized, filled in by the SDK, or replaced by a cached verdict. | DSM-HL-078/L3893 | none |
| SOFI-035/L1775 | obligation | explicit | Every unlock evidence item feeds a named conjunctive Core check and unused items are malformed. | Every evidence item in the unlock preimage is consumed by a named Core check, and that check’s verdict is a | DSM-HL-078/L3893 | none |
| SOFI-035/L1781 | invariant | explicit | Installed values equal verified values, including recomputed E, Fold(T°,E) and Cq. | The values Core verified are the values the transition installs. E recomputes from the verified preimage. The | SOFI-019-6/L1267 | none |
| SOFI-035/L1786 | prohibition | explicit | Missing evidence stops publication, exercise and advancement. | A producer that receives Unavailable stops. It never publishes, exercises or advances on Unavailable. | DSM-HL-078/L3893 | none |

### SOFI-037 — 37 Gates

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-037/L1854 | conformance-test | explicit | CI identifies every public SoFi function lacking a production caller and fails the production safety gate. | A CI script fails if any pub fn under CORE/sofi/ has no caller in production code. Production code is every .rs | DSM-HL-078/L3893 | none |
| SOFI-037/L1881 | conformance-test | explicit | Evidence default construction is test-only and a static check rejects production default calls. | Evidence derives Default only under #[cfg(test)] (#[cfg_attr(test, derive(Default))]), so production | DSM-HL-078/L3893 | none |
| SOFI-037/L1891 | conformance-test | explicit | Each evidence item has removal, corruption and deleted-check tests that distinguish pending acquisition from specific invalidity under S3. | For every row of the table above there is a named test that removes the item and asserts Unavailable, and a | DSM-HL-078/L3893 | none |
| SOFI-037/L1897 | conformance-test | explicit | Tests bind installed root and registered Cq to verified inputs and detect every single-byte evidence mutation. | For an accepted operation, a test asserts that the installed root equals Fold(T ◦ , E) computed from the verified | DSM-HL-078/L3893 | none |
| SOFI-037/L1903 | conformance-test | explicit | Withholding each evidence item on the production path prevents publication, exercise and advancement. | On the production path, a test withholds each evidence item in turn and asserts that nothing is published, | DSM-HL-078/L3893 | none |

### SOFI-038 — 38 What enters the transition

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-038/L1922 | obligation | explicit | The Core transition verifies the operation's device key and all operation predicates before advancement. | 1. verify_operation (CORE/sofi/signature.rs:232) checks the operation against the key of the device | DSM-HL-078/L3893 | none |
| SOFI-038/L1925 | obligation | explicit | Derive transition entropy as H(DSM/state-entropy; preceding entropy ∥ operation ∥ relationship tip). | 3. Core derives the entropy en+1 = H(DSM/state-entropy; en ∥ op ∥ hn ) from the relationship tip. | DSM-HL-078/L3893 | none |

### SOFI-039 — 39 Requirements

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-039/L1931 | obligation | derived | One preparation function handles every transition and producers cannot call lower-level advancement. | 1. One function prepares every transition. No SoFi producer calls a lower level advance. | DSM-HL-078/L3893 | none |
| SOFI-039/L1932 | prohibition | derived | The SDK supplies no transition entropy. | 2. The SDK supplies no entropy. The value derived in step 3 is the only entropy of the transition. | DSM-HL-078/L3893 | none |
| SOFI-039/L1933 | invariant | derived | Use the same derived entropy in the relationship tip and both receipt hashes. | 3. That same value goes into the relationship tip and into both receipt hashes, Cpre and the symmetric tip. | DSM-HL-078/L3893 | none |
| SOFI-039/L1934 | obligation | derived | A transfer nonce remains committed within operation bytes. | 4. A transfer nonce, where an operation has one, stays in the operation bytes, where it is already hashed. | DSM-HL-078/L3893 | none |
| SOFI-039/L1937 | conformance-test | explicit | All three SoFi operations have deterministic replay, carried-byte mutation and shared-entropy binding tests. | For each of the three SoFi operations: applying it twice from the same state gives byte identical results; changing | DSM-HL-078/L3893 | none |
| SOFI-039/L1975 | prohibition | explicit | Deletion-induced compile failures must not be repaired by recreating removed protocol rules. | A compile error caused by a deletion is information: a surviving component depended on something this design | DSM-HL-078/L3893 | none |

### SOFI-040-4 — 40.4 Gates

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-040-4/L2107 | conformance-test | explicit | The storage-blindness gate fails on a deliberately injected forbidden SoFi dependency. | Mutation proof: add any one banned token to a node file and the gate fails, naming it. | DSM-HL-078/L3893 | none |
| SOFI-040-4/L2128.a | prohibition | explicit | The root-register node must not decode caller signatures, verify them or check writer attribution. | > **Amendment S2 (owner, 2026-09-22) — this gate is retired.** The root register must not decode or verify caller signatures or check attribution. A node that can check the writer can block, and blocking is an authority a node must not have (§12; DSM Amendment A3). A root claim that is not signed by its device is not a claim; the reader verifies the signature in Core and ignores it. | SOFI-012/L683 | ambiguous |
| SOFI-040-4/L2128.b | evidence | explicit | Core verifies device signatures and ignores unsigned root-claim impostors. | > **Amendment S2 (owner, 2026-09-22) — this gate is retired.** The root register must not decode or verify caller signatures or check attribution. A node that can check the writer can block, and blocking is an authority a node must not have (§12; DSM Amendment A3). A root claim that is not signed by its device is not a claim; the reader verifies the signature in Core and ignores it. | SOFI-012/L683 | none |
| SOFI-040-4/L2141 | conformance-test | explicit | An immutable-store positive control returns exactly the bytes put. | Positive control: bytes put into the immutable store come back byte identical. | DSM-HL-078/L3893 | none |

### SOFI-042-2 — 42.2 Then the invariants

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-042-2/L2217 | invariant | derived | Position installation is atomic with no reachable half-installed fulfillment-root pair. | - PositionPairAtomic: whenever a position is installed, no reachable state contains only one of Kful (q) and Kroot (q); | DSM-HL-078/L3893 | tension(SOFI-017-4/L1081) |

### SOFI-042-3 — 42.3 Two properties the floor must prove

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-042-3/L2238 | proof-obligation | derived | Formal models must not let nonexercises occupy or deaden successor keys. | Under the storage contract of Part II, bytes that are not an exercise naming the key count as nothing (Section 8), | DSM-HL-078/L3893 | none |
| SOFI-042-3/L2242 | proof-obligation | derived | Prove OnlyExercisesCount and exact next-attempt liveness after skipping. | P1, OnlyExercisesCount. At every successor key, the only value that can be Final is an exercise (Section 17.5) whose F | DSM-HL-078/L3893 | none |
| SOFI-042-3/L2246 | proof-obligation | derived | Prove any party can complete a registered fulfillment without trader authorization. | P2, RegisteredFulfillmentCanBeCompletedByAnyone. Once F is registered, any party can write the exercise to every | DSM-HL-078/L3893 | none |

### SOFI-042-4 — 42.4 Files and counts

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-042-4/L2267 | conformance-test | explicit | Formal invariants hold and each weakening violates its named property with no admitted proof holes. | Each invariant holds, and each falsification configuration violates exactly its named property. lean | DSM-HL-078/L3893 | none |

### SOFI-046 — 46 Not in this work

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-046/L2381 | obligation | derived | Use the reserved membership-handover tag for the storage specification's handover encoding. | > **Note (2026-09-22).** Member replacement is now specified in `DSM_Storage_Node_Specification.md` §12; the reserved tag becomes SoFi's encoding of its handover (§12.5). | DSM-HL-011/L833 | none |
| SOFI-046/L2390 | authority | explicit | A token's committed policy defines its asset and does not grant creator ownership under the standard locked policy. | A token policy creates a tokenized asset. It defines the token, its supply and its rules. It is anchored to its | DSM-HL-011/L833 | none |
| SOFI-046/L2392 | invariant | explicit | A DLV commits its owner's liquidity terms and references traded tokens by policy commitments. | A DLV is one owner and what that owner holds and puts up as liquidity, under the owner’s own conditions, | DSM-HL-011/L833 | none |

### SOFI-047 — 47 What a token policy is

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-047/L2400 | obligation | derived | Use one canonical version-three token-policy encoding with big-endian integers. | Rust packs one canonical blob, the only packer for the format (build_policy_v3_bytes, SDK/handlers/token_ | DSM-HL-061/L2753 | none |
| SOFI-047/L2410 | obligation | derived | Policy signer thresholds use one through sixteen keys and authorize only explicitly named operations. | signer set and threshold              the k of n keys, 1 ≤ n ≤ 16; they authorize only what the policy’s own rules | DSM-HL-061/L2753 | none |
| SOFI-047/L2412 | obligation | derived | Token tickers are two through eight characters and decimals range from zero through eighteen. | ticker, alias                         2 to 8 characters; a display name | DSM-HL-061/L2753 | none |
| SOFI-047/L2422 | invariant | explicit | The hash of the whole policy is token identity and any changed policy field creates another token. | The token’s identity is policy_commit, the hash of the whole blob. Any field that differs makes a different token. | DSM-HL-061/L2753 | none |
| SOFI-047/L2423 | authority | explicit | Tickers are display metadata and cannot identify protocol assets. | The ticker is display only; two tokens may share one. | DSM-HL-061/L2753 | none |

### SOFI-048 — 48 Two kinds of supply

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-048/L2436 | invariant | derived | Each token has exactly one immutable supply class without an unlimited option. | Every token belongs to exactly one supply class, fixed in its policy. The two classes bound supply in different ways, | DSM-HL-061/L2753 | none |
| SOFI-048/L2452 | invariant | explicit | Native genesis supply equals unreleased units plus all holder and vault balances plus permanently burned units. | Sgenesis = R +       B+D        at every state. | DSM-HL-061/L2753 | none |
| SOFI-048/L2453 | prohibition | explicit | Native supply cannot be minted after genesis and release is governed by its committed policy. | There is no minting after genesis. Emission is a release under the token’s own committed policy. The policy is | DSM-HL-061/L2753 | none |
| SOFI-048/L2463.a | invariant | explicit | Externally backed outstanding supply never exceeds backing accepted as proven locked. | subject to the exact lock and redeem state DSM commits. The policy fixes the issuance rule, not a reserve: there | DSM-HL-061/L2753 | none |
| SOFI-048/L2463.b | invariant | explicit | External issuance has no pre-existing reserve pool and is admitted only by corresponding proven locks. | subject to the exact lock and redeem state DSM commits. The policy fixes the issuance rule, not a reserve: there | DSM-HL-061/L2753 | none |

### SOFI-049 — 49 What each rule governs

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-049/L2477 | obligation | derived | Evaluate signer authority only on operations named by the token policy. | signer set and threshold       only what the policy’s own rules name             every operation those rules name | DSM-HL-061/L2753 | none |
| SOFI-049/L2478 | obligation | derived | Enforce transferability on transfers, vault creation and both tokens of every SoFi leg. | transferable                   whether the token may move between                every transfer, online and offline; vault | SOFI-019-5/L1244 | none |
| SOFI-049/L2482 | obligation | derived | The recipient issuance allowlist restricts issuance recipients without creating a market restriction. | recipient allowlist            who may receive issuance; it has no mar-          every issuance | DSM-HL-061/L2753 | none |

### SOFI-050 — 50 The mandatory baseline

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-050/L2495 | obligation | explicit | Reject creation unless policy states version, kind, supply class, decimals, transferability and explicit allowlist presence or absence. | Every token policy states: its version and kind; its supply class; its decimals; whether it is transferable; and its | DSM-HL-061/L2753 | none |
| SOFI-050/L2496 | obligation | explicit | Native policies additionally declare genesis supply and release rule while external policies declare the backing rule. | recipient allowlist, or that it has none. A native token’s policy also states its genesis supply and its release rule. | DSM-HL-061/L2753 | none |

### SOFI-051 — 51 Native supply

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-051/L2507 | authority | explicit | The standard issuer cannot edit policy or remove units outside its committed release conditions. | 2. The policy is anchored to the issuer’s state when the token is created, but the issuer does not own it. By | SOFI-046/L2390 | none |
| SOFI-051/L2512 | invariant | explicit | Burned native units never return to unreleased supply. | 4. A burn destroys the units it burns. They never return to the unreleased supply, so the total ever released | DSM-HL-061/L2753 | none |
| SOFI-051/L2517 | prohibition | explicit | Verify each token's actual committed policy without importing defaults or another token's rules. | Every token’s rules are the ones committed in its own policy. A verifier reads that policy and recomputes what | DSM-HL-061/L2753 | none |

### SOFI-052 — 52 Externally backed supply

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-052/L2536 | evidence | explicit | Admit external issuance only for exactly the quantity proven locked under the backing rule. | 1. Issuance is admissible only against a lock that the policy’s backing rule accepts as proven, for exactly the | DSM-HL-061/L2753 | none |
| SOFI-052/L2538 | invariant | explicit | Each external lock admits issuance once through a lock-derived consumption key. | 2. Each proven lock admits its amount once. The lock is a consumed resource: its consumption key is derived | DSM-HL-061/L2753 | none |
| SOFI-052/L2540 | invariant | explicit | Redemption pairs the burn and matching backing release with neither occurring independently. | 3. A redemption burns units in the same transition that releases the matching backing. Backing is never re- | DSM-HL-061/L2753 | tension(DBTC-SPEC-12/L630) |

### SOFI-053 — 53 Raising supply

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-053/L2560 | prohibition | derived | Increasing native genesis supply requires a new token rather than modifying the old policy. | never changes, so a token that needs more supply is a new token. | DSM-HL-061/L2753 | none |
| SOFI-053/L2563 | transition | explicit | A new token's committed conversion releases new units one-for-one while permanently locking the old units. | 2. The new token’s policy commits a conversion rule: it releases the new token for the old one, one for one, and | DSM-HL-061/L2753 | none |
| SOFI-053/L2565 | prohibition | explicit | Supply conversion is a locked policy rule rather than an owner-closeable DLV. | 3. The conversion rule is part of the new token’s policy, so it is anchored and locked like the rest of the policy. | DSM-HL-061/L2753 | none |
| SOFI-053/L2567 | obligation | explicit | The conversion policy identifies the old token by its policy commitment. | 4. The new token’s policy names the old token’s policy_commit; that is the only link between them. | DSM-HL-061/L2753 | none |

### SOFI-054 — 54 What changes in the tree

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| SOFI-054/L2584 | obligation | derived | The former mint-and-burn flag governs burns only. | - The mint and burn flag governs burns only. | DSM-HL-061/L2753 | none |
| SOFI-054/L2586 | conformance-test | derived | Token-policy rule changes have named tests that fail when their checks are removed. | - Each change lands with a named test that fails when the rule is removed. | DSM-HL-061/L2753 | none |

## dBTC_Native_Specification.md

### DBTC-SPEC-01-01 — 1.1 Scope

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-01-01/L42 | dependency-boundary | explicit | dBTC imports DSM identity, bilateral progression, device SMTs, online registers and offline custody without redefining those subsystems. | It does not redefine DSM identity, DSM bilateral state progression, the Per-Device Sparse Merkle Tree, the online economic-root register, the offline anti-cloning profile, SoFi market arithmetic, or Bitcoin consensus. | DSM-HL-066/L3362 | none |

### DBTC-SPEC-01-03 — 1.3 Specification status

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-01-03/L58 | obligation | explicit | Bring implementation into conformance with this specification rather than weakening requirements to match existing code. | Implementation references in Section 37 are informative. Where an existing implementation path differs from this document, conformance requires the implementation to be brought to this specification rather than silently weakening the specification. | DSM-HL-005/L283 | none |

### DBTC-SPEC-02 — 2 Architectural Principle

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-02/L75 | authority | explicit | Keep live-state economic ownership separate from narrowly scoped Bitcoin execution authority. | These must never be conflated. | DSM-HL-064/L3201 | none |
| DBTC-SPEC-02/L79 | invariant | explicit | Ownership requires a currently valid dBTC quantity in DSM state under authority the claimant satisfies. | A party owns a quantity of dBTC only if that quantity exists in a currently valid DSM economic state under authority the party can satisfy. | DSM-HL-064/L3201 | none |
| DBTC-SPEC-02/L83 | authority | explicit | Bitcoin execution material authorizes settlement after valid consumption and cannot prove dBTC ownership. | Bitcoin execution material is cryptographic material used to spend a Bitcoin backing output after a valid dBTC consumption. It is settlement machinery and is not itself evidence of dBTC ownership. | DSM-HL-064/L3201 | none |
| DBTC-SPEC-02/L109 | prohibition | explicit | Vault metadata, ciphertext, keys, hashlocks, receipts and transaction templates cannot alone establish ownership. | No implementation may treat knowledge of a vault identifier, lineage, ciphertext, public key, hash lock, preimage commitment, storage record, or Bitcoin transaction template as sufficient evidence of dBTC ownership. | DSM-HL-064/L3201 | none |

### DBTC-SPEC-03-01 — 3.1 DSM substrate

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-03-01/L121 | safety-assumption | explicit | Accepted DSM states bind canonical predecessors without requiring global transaction sequence. | Accepted DSM state is linked to its predecessor by canonical cryptographic commitment rather than by a global transaction sequence. | DSM-HL-005/L283 | none |
| DBTC-SPEC-03-01/L125 | safety-assumption | explicit | Realization consumes the identified parent and produces only permitted successors. | A realized state transition consumes the identified parent state and produces only the successor or successor set permitted by the transition. | DSM-HL-005/L283 | none |
| DBTC-SPEC-03-01/L129 | safety-assumption | explicit | Authenticated canonical DSM state governs economics and unauthenticated caches have no authority. | Economically relevant state is committed into the applicable authenticated DSM state structure. Unauthenticated caches are not authority. | DSM-HL-005/L283 | none |
| DBTC-SPEC-03-01/L133 | safety-assumption | explicit | DSM Tripwire excludes conflicting accepted successors under its cryptographic assumptions. | Conflicting accepted successors to the same consumed state are excluded under the cryptographic assumptions of DSM’s Tripwire construction. | DSM-HL-005/L283 | none |
| DBTC-SPEC-03-01/L137 | safety-assumption | explicit | Debits, credits, burns, reserves and provenance pass canonical economic conservation checks. | Token debits, credits, burns, reserve movements, and provenance are accepted only through canonical DSM economic transitions satisfying the applicable conservation predicate. | DSM-HL-005/L283 | none |

### DBTC-SPEC-03-02 — 3.2 Sovereign Finance boundary

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-03-02/L152 | dependency-boundary | explicit | Preserve online admitted versus offline allocated dBTC and use only canonical custody-domain transitions at their boundary. | A dBTC implementation must preserve the existing separation between: | DSM-HL-066/L3362 | none |

### DBTC-SPEC-03-03 — 3.3 DLV compatibility

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-03-03/L167 | invariant | derived | Backing may leave a dBTC DLV only through the condition family committed at creation. | > Value is encumbered into a state object and can leave only through a successor or fulfillment satisfying the condition family committed at creation. | DSM-HL-005/L283 | none |

### DBTC-SPEC-04 — 4 Conformance Classes

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-04/L182 | authority | explicit | Class C owns canonical commitments, state and provenance verification, conservation, burn and fulfillment verification and successor arithmetic. | Class C is the deterministic protocol verifier. It: | DSM-HL-064/L3201 | none |
| DBTC-SPEC-04/L200 | authority | explicit | Class K acquires proofs, constructs candidates, invokes embedded Core and orchestrates constrained execution and publication. | Class K performs construction and orchestration. It: | DSM-HL-064/L3201 | none |
| DBTC-SPEC-04/L210 | prohibition | explicit | Class K invokes vault execution only after successful Class C verification. | - *invokes constrained vault execution only after successful verification;* | DSM-HL-064/L3201 | none |
| DBTC-SPEC-04/L224 | authority | explicit | Class N provides non-authoritative storage and indexing of descriptors, sealed material and proof artifacts. | Class N is non-authoritative persistence and indexing. | DSM-HL-064/L3201 | none |
| DBTC-SPEC-04/L246 | prohibition | explicit | Storage must not become a Bitcoin signing federation, custodian, mint or validator set. | Class N must not become a Bitcoin signing committee, threshold signer, custodian, mint, or validator set merely because encrypted vault bytes are stored there. | DSM-HL-064/L3201 | none |
| DBTC-SPEC-04/L248 | authority | explicit | A SoFi persistence barrier cannot acquire Bitcoin signing authority. | If SoFi uses a storage-set write-once origination barrier for a market DLV, that mechanism remains a persistence/exclusivity primitive. It is not Bitcoin signing authority and must not be interpreted as such. | DSM-HL-064/L3201 | none |

### DBTC-SPEC-05 — 5 Clocklessness and External Bitcoin Finality

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-05/L257 | prohibition | explicit | Ownership, burns, unlocks and successor validity must not depend on wall-clock time, elapsed duration or a global DSM sequence. | No dBTC ownership predicate, burn predicate, DLV unlock predicate, or successor validity predicate may depend on wall-clock time, elapsed duration, or a globally shared DSM sequence. | DSM-HL-033/L1757 | none |
| DBTC-SPEC-05/L269 | obligation | explicit | Commit Bitcoin network and minimum confirmation depth in the vault or an immutable network profile. | The Bitcoin network identifier and $d_{\min}$ policy must be committed into the vault profile or resolved from an immutable network profile. | DSM-HL-033/L1757 | none |
| DBTC-SPEC-05/L271 | safety-assumption | derived | DSM does not exclude Bitcoin reorganizations beyond the chosen confirmation-depth assumption. | A reorganization deeper than the accepted Bitcoin depth is an external Bitcoin assumption and is not claimed to be impossible by DSM. | DSM-HL-033/L1757 | none |

### DBTC-SPEC-06 — 6 Canonical Encoding and Domain Separation

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-06/L276 | obligation | derived | Transport dBTC protocol objects through Protobuf while retaining binary identifiers internally. | All security-critical structured objects are converted to canonical commit bytes before hashing or signing. | DSM-HL-015/L1119 | none |
| DBTC-SPEC-06/L284 | obligation | explicit | Canonical encoding fixes integer order, length-delimits variable bytes, fixes field and collection order, explicitly represents absence and includes class and schema. | At minimum, CCB must preserve the existing DSM rules: | DSM-HL-015/L1119 | none |
| DBTC-SPEC-06/L296 | prohibition | explicit | Protocol predicates cannot use floating-point arithmetic. | 6.  floating-point values are forbidden from protocol predicates; | DSM-HL-015/L1119 | none |
| DBTC-SPEC-06/L304 | obligation | derived | Use Base32 Crockford at identifier display boundaries. | Base32 Crockford is the human-display encoding for identifiers. | DSM-HL-015/L1119 | none |
| DBTC-SPEC-06/L306 | prohibition | derived | Hexadecimal text cannot become DSM protocol encoding. | Hexadecimal text is not a protocol encoding. | DSM-HL-015/L1119 | none |

### DBTC-SPEC-06-01 — 6.1 Required domains

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-06-01/L311 | obligation | derived | Retain DSM/dlv-unlock for unlock derivation. | The existing DLV unlock domain is retained: | DSM-HL-015/L1119 | none |
| DBTC-SPEC-06-01/L339 | obligation | explicit | Reuse equivalent registered domain tags and do not create duplicate domain namespaces. | If equivalent registered DSM domains already exist in the implementation, the registered domain is authoritative and duplicate domains must not be created. | DSM-HL-015/L1119 | none |

### DBTC-SPEC-07 — 7 The dBTC Asset

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-07/L346 | invariant | explicit | One dBTC base unit represents one satoshi-equivalent with accepted Bitcoin-origin provenance. | One dBTC base unit represents one satoshi-equivalent unit of DSM economic state whose positive issuance traces to accepted Bitcoin backing. | DSM-HL-064/L3213 | none |
| DBTC-SPEC-07/L369 | obligation | explicit | A wallet may aggregate balances for display but must retain per-origin allocation provenance. | The wallet may display $Q$ as one fungible balance, while the protocol retains the provenance needed to reconcile withdrawals with actual Bitcoin backing. | DSM-HL-064/L3213 | none |
| DBTC-SPEC-07/L373 | prohibition | explicit | No positive dBTC credit may arise from self-asserted minting or a noncanonical source. | A positive dBTC credit must have a canonical source accepted by DSM. No generic self-asserted mint or custom credit source may manufacture dBTC. | DSM-HL-064/L3213 | none |

### DBTC-SPEC-08-01 — 8.1 Origin output

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-08-01/L399 | obligation | explicit | An origin descriptor binds stable origin ID, generation, outpoint, amount, lock, parameter commitment, execution public key, fulfillment hash and Bitcoin and asset profiles. | A dBTC origin DLV is represented abstractly as: | DSM-HL-064/L3213 | none |
| DBTC-SPEC-08-01/L435 | obligation | explicit | The origin policy commits successor rules and any applicable lineage-wide minimum backing. | - *$\Pi_{\mathrm{policy}}$ commits the dBTC policy, successor rules, and any lineage-wide successor minimum backing $B_{\min}$ used by the selected dBTC profile.* | DSM-HL-064/L3213 | none |
| DBTC-SPEC-08-01/L437 | invariant | derived | Partial successors preserve the stable origin identifier while changing generation and outpoint. | The vault identifier remains stable across partial-withdrawal successors: | DSM-HL-064/L3213 | none |

### DBTC-SPEC-09 — 9 Origin Admission and dBTC Issuance

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-09/L448 | evidence | explicit | Class C verifies Bitcoin origins before issuance. | Class C must verify the origin. | DSM-HL-064/L3213 | none |
| DBTC-SPEC-09/L456 | evidence | explicit | Origin acceptance verifies transaction validity under the configured Bitcoin network. | 1.  *the Bitcoin funding transaction is valid under the configured Bitcoin-network verifier;* | DSM-HL-064/L3213 | none |
| DBTC-SPEC-09/L458 | evidence | explicit | Origin acceptance verifies outpoint existence and exact backing amount. | 2.  *the claimed outpoint exists in that transaction;* | DSM-HL-064/L3213 | none |
| DBTC-SPEC-09/L462 | evidence | explicit | Origin acceptance matches the exact script to the committed profile. | 4.  *the output script matches the committed DLV profile;* | DSM-HL-064/L3213 | none |
| DBTC-SPEC-09/L464 | evidence | explicit | Origin acceptance requires chain inclusion at the committed confirmation depth. | 5.  *the transaction is proven included in an accepted Bitcoin chain;* | DSM-HL-064/L3213 | none |
| DBTC-SPEC-09/L468 | evidence | explicit | Recompute origin identity from canonical material and bind the exact origin to one canonical issuance position. | 7.  *the origin identifier recomputes from canonical origin material;* | DSM-HL-064/L3213 | none |
| DBTC-SPEC-09/L472 | evidence | explicit | Origin admission requires the canonical dBTC asset's policy commitment. | 9.  *the dBTC policy commitment matches the canonical dBTC asset.* | DSM-HL-064/L3213 | none |
| DBTC-SPEC-09/L476 | invariant | explicit | Every positive dBTC supply change requires ValidOrigin. | Positive dBTC issuance must satisfy: | DSM-HL-064/L3213 | none |

### DBTC-SPEC-10 — 10 What Moves During an Ordinary dBTC Transfer

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-10/L499 | transition | derived | Ordinary transfer consumes the current source and produces the exact authorized recipient credit and sender remainder with preserved provenance. | The DSM transition consumes Alice’s old economic state and produces the exact authorized successor state: | DSM-HL-064/L3219 | none |
| DBTC-SPEC-10/L527 | prohibition | explicit | Ordinary transfer requires no Bitcoin confirmation, depositor, custodian, signing quorum, mint, global ledger or storage economic verdict. | An ordinary dBTC transfer must not require: | DSM-HL-064/L3219 | none |
| DBTC-SPEC-10/L543 | dependency-boundary | explicit | Transfers use the existing online or offline DSM custody profile rather than a dBTC-specific custody mechanism. | A transfer may be performed through the applicable DSM online or offline custody mechanism. | DSM-HL-064/L3219 | none |
| DBTC-SPEC-10/L547 | invariant | derived | Ordinary ownership transfer creates no Bitcoin successor and backing generation advances only when its outpoint is consumed. | > A successor *Bitcoin* vault is not created merely because ordinary DSM ownership changed. | DSM-HL-064/L3219 | none |

### DBTC-SPEC-11-01 — 11.1 Withdrawal intent

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-11-01/L575 | obligation | derived | Construct canonical withdrawal intent before execution authority becomes usable. | Before the vault execution authority is usable, Class K constructs a canonical withdrawal intent: | DSM-HL-064/L3225 | none |
| DBTC-SPEC-11-01/L621 | evidence | explicit | The burn proof binds the exact withdrawal intent. | The burn proof must bind the exact withdrawal intent. | DSM-HL-064/L3225 | none |
| DBTC-SPEC-11-01/L623 | invariant | explicit | Any change to amount, destination, origin, outpoint, fees or successor construction changes the intent commitment. | Changing the amount, destination, origin, Bitcoin outpoint, fee treatment, or successor construction must change $c_W$. | DSM-HL-064/L3225 | none |

### DBTC-SPEC-12 — 12 The dBTC Burn

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-12/L630 | transition | explicit | A withdrawal burn consumes spendable dBTC and produces a nonspendable withdrawal-completion object. | A withdrawal burn is a canonical DSM transition consuming an actual spendable dBTC quantity and producing a non-spendable withdrawal-completion object. | DSM-HL-064/L3225 | tension(SOFI-052/L2540) |
| DBTC-SPEC-12/L644 | prohibition | explicit | Reject a burn unless the claimant controls the named live source state. | Class C must reject $\mathop{\mathrm{Burn}}(W)$ unless the claimant possesses the live dBTC state identified by $S$ and satisfies the authority required by that state. | DSM-HL-064/L3225 | none |
| DBTC-SPEC-12/L648 | prohibition | explicit | Well-formed burn-proof bytes alone cannot authorize consumption. | A burn proof must not be accepted merely because its bytes are well formed. | DSM-HL-064/L3225 | none |
| DBTC-SPEC-12/L650 | evidence | explicit | Class C verifies inclusion, freshness, authority, origin provenance, exact debit and successor root of the actual burn. | Class C must verify the actual state transition, including source inclusion, freshness, authority, provenance, exact debit, and successor root. | DSM-HL-064/L3225 | none |

### DBTC-SPEC-13 — 13 DLV Completion Evidence

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-13/L696 | evidence | explicit | Completion evidence cryptographically commits both the consumed transition and its exact withdrawal intent. | It must cryptographically commit to the state transition that consumed the dBTC and to the exact withdrawal intent. | DSM-HL-064/L3225 | none |
| DBTC-SPEC-13/L698 | obligation | derived | Derive the unlock as BLAKE3-256 over DSM/dlv-unlock, canonical lock, parameter commitment and verified completion, then check its SHA-256 commitment. | The existing DLV construction derives its unlock value from: | DSM-HL-064/L3225 | ambiguous |
| DBTC-SPEC-13/L731 | evidence | explicit | Unlock acceptance aligns live state, authority, quantity, origin, intent, lock, parameters, completion and fulfillment hash. | A candidate $sk_{V_n}$ is valid only if all of the following align: | DSM-HL-064/L3225 | ambiguous |
| DBTC-SPEC-13/L755 | prohibition | derived | Hashlock equality alone is insufficient for DSM withdrawal authorization. | is necessary but not independently sufficient at the DSM layer. | DSM-HL-064/L3225 | none |

### DBTC-SPEC-14 — 14 Knowledge Is Not Possession

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-14/L784 | invariant | explicit | Withdrawable conjoins live state, correct authority, valid burn, valid completion and matching DLV preimage. | The withdrawal relation is conjunctive: | DSM-HL-064/L3201 | none |
| DBTC-SPEC-14/L800 | prohibition | explicit | Copied lineage, stale state, mismatched authority, foreign completion and other-generation preimages cannot authorize withdrawal. | A copied lineage with no live dBTC is inert. | DSM-HL-064/L3201 | none |

### DBTC-SPEC-15-01 — 15.1 Purpose

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-15-01/L818 | obligation | explicit | The Bitcoin private scalar should not be stored as an ordinary reusable transferable dBTC secret. | The Bitcoin execution key is not the bearer asset and should not reside as an ordinary reusable secret in the transferable dBTC state. | DSM-HL-064/L3201 | none |
| DBTC-SPEC-15-01/L828 | obligation | derived | Represent execution material as a sealed capsule bound to vault, generation, lock, parameters and public execution key. | The scalar is represented outside ordinary dBTC state as a sealed vault execution capsule: | DSM-HL-064/L3201 | ambiguous |
| DBTC-SPEC-15-01/L837 | obligation | explicit | Storage may persist sealed execution capsules. | Storage nodes may persist $E_n$. | DSM-HL-064/L3201 | none |
| DBTC-SPEC-15-01/L841 | invariant | explicit | Possession of a capsule alone provides no usable signing authority. | Possession of $E_n$ alone must provide no usable Bitcoin signing authority. | DSM-HL-064/L3201 | none |

### DBTC-SPEC-15-02 — 15.2 Fulfillment-gated opening

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-15-02/L846 | authority | derived | Opening a capsule requires a verified burn and matching fulfillment preimage and returns only generation-constrained execution authority. | The abstract opening interface is: | DSM-HL-064/L3201 | ambiguous |
| DBTC-SPEC-15-02/L870 | prohibition | explicit | A high-assurance execution path exposes no general-purpose private-key export or signing API. | A conforming high-assurance implementation must not expose $x_n$ through a general-purpose signing or export API after DLV fulfillment. | DSM-HL-064/L3201 | ambiguous |
| DBTC-SPEC-15-02/L872 | authority | explicit | Opened execution authority is usable only for the verified withdrawal intent. | The authority must be usable only by the dBTC vault execution path bound to the verified withdrawal intent. | DSM-HL-064/L3201 | ambiguous |

### DBTC-SPEC-16 — 16 Current Bitcoin Fulfillment Script Profile

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-16/L895 | obligation | explicit | A profile may use the specified dual-hashlock fulfill-and-refund script. | The current dBTC Bitcoin profile may use the existing dual-hashlock DLV script shape: | DSM-HL-064/L3225 | none |
| DBTC-SPEC-16/L915 | invariant | explicit | Bitcoin signature and hashlock witness must bind the same vault generation and withdrawal execution. | The hashlock witness and Bitcoin signature must correspond to the same DLV generation and the same committed withdrawal execution. | DSM-HL-064/L3225 | none |
| DBTC-SPEC-16/L917 | prohibition | explicit | Do not combine one generation's preimage with another generation's authority. | A valid preimage from one generation must not be paired with execution authority from another generation. | DSM-HL-064/L3225 | none |

### DBTC-SPEC-16-01 — 16.1 Refund branch

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-16-01/L922 | prohibition | explicit | Refund branches cannot grant discretionary depositor access. | If a refund branch exists, it must not be a discretionary depositor backdoor. | DSM-HL-064/L3225 | none |
| DBTC-SPEC-16-01/L926 | prohibition | explicit | A live backing vault cannot reveal refund secrets merely for elapsed time or depositor request. | A live dBTC-backed vault must not expose a refund secret merely because a wall clock expired or because the depositor requests one. | DSM-HL-064/L3225 | none |
| DBTC-SPEC-16-01/L928 | evidence | explicit | A refund secret derives from a mutually exclusive condition proved under committed DLV policy. | Any refund secret must derive from a mutually exclusive DSM condition proving that the refund branch is valid under the committed DLV policy. | DSM-HL-064/L3225 | none |
| DBTC-SPEC-16-01/L930 | invariant | explicit | Refund cannot release backing while corresponding live dBTC remains outstanding. | A refund path must never allow Bitcoin backing to leave while corresponding live dBTC remains outstanding. | DSM-HL-064/L3225 | none |

### DBTC-SPEC-17 — 17 Constructing the Bitcoin Withdrawal

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-17/L952 | obligation | explicit | Withdrawal intent binds the exact unsigned transaction digest or enough canonical fields for Core to recompute that body. | The withdrawal intent must bind $c_T$, or must contain sufficient canonical fields from which Class C deterministically recomputes the same transaction body. | DSM-HL-064/L3225 | ambiguous |
| DBTC-SPEC-17/L956 | prohibition | explicit | One burn cannot authorize arbitrary payout amounts or destinations. | The DLV execution authority released by one burn must not authorize an arbitrary Bitcoin destination or amount. | DSM-HL-064/L3225 | none |
| DBTC-SPEC-17/L958 | evidence | explicit | The vault execution routine verifies exact equality with the burn-committed transaction. | The vault execution routine must verify that the candidate transaction equals the transaction committed by the burn. | DSM-HL-064/L3225 | none |

### DBTC-SPEC-18 — 18 Full Withdrawal

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-18/L963 | transition | derived | A full exit burns the backing-paid payout and fee and creates no successor. | A full withdrawal consumes all dBTC backed by the claimant’s selected vault quantity and leaves no dBTC successor for that consumed backing. | DSM-HL-064/L3288 | none |
| DBTC-SPEC-18/L989 | invariant | explicit | A fully spent generation is terminal and cannot advertise live successor backing. | After a valid full withdrawal consumes the backing outpoint, the corresponding DLV generation is terminal and must not advertise a live successor. | DSM-HL-064/L3288 | none |

### DBTC-SPEC-19 — 19 Partial Withdrawal and Successor Vault

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-19/L1026 | obligation | explicit | Declare external fee funding explicitly and adjust conservation accordingly. | If the fee is funded by a separate Bitcoin input, the accounting equation is adjusted accordingly and that external fee source must be explicit. | DSM-HL-064/L3288 | none |
| DBTC-SPEC-19/L1030 | obligation | explicit | Every partial-withdrawal profile commits immutable lineage-wide minimum backing Bmin. | The origin policy $\Pi_{\mathrm{policy}}$ must commit a successor minimum backing $B_{\min}$ for any profile that permits partial withdrawal. That value is a lineage property and must remain immutable across successor generations. | DSM-HL-064/L3288 | none |
| DBTC-SPEC-19/L1032 | invariant | explicit | After all declared fees and anchor treatment a partial successor must retain at least Bmin. | After applying the declared fee and anchor treatment, every partial-withdrawal successor must satisfy: | DSM-HL-064/L3288 | ambiguous |
| DBTC-SPEC-19/L1046 | prohibition | explicit | Core rejects under-floor splits at burn acceptance before completion, unlocking, signing or activation. | Class C must enforce this condition as part of burn acceptance, not merely as a Class K construction-time check. If it fails, the burn is invalid and no completion evidence $\sigma$, DLV unlock value, Bitcoin signature, or successor activation may follow from that attempt. | DSM-HL-064/L3288 | none |

### DBTC-SPEC-19-01 — 19.1 Successor identity

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-19-01/L1051 | transition | derived | Partial succession retains origin v, increments generation exactly once and names the successor output of the actual withdrawal transaction. | The successor retains the same stable origin: | DSM-HL-064/L3288 | none |

### DBTC-SPEC-19-02 — 19.2 Fresh successor authority

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-19-02/L1071 | obligation | explicit | Every successor uses a fresh private execution scalar and corresponding public key. | The successor must use fresh Bitcoin execution authority: | DSM-HL-064/L3288 | none |
| DBTC-SPEC-19-02/L1079 | obligation | derived | Each successor gets fresh generation-bound lock, parameter commitment, fulfillment hash and sealed capsule. | It also receives fresh generation-specific DLV fulfillment material: | DSM-HL-064/L3288 | none |
| DBTC-SPEC-19-02/L1091 | prohibition | explicit | Remainder backing cannot return to the spent parent's execution key. | A partial withdrawal must not return the remainder to the spent parent execution key. | DSM-HL-064/L3288 | none |
| DBTC-SPEC-19-02/L1097 | obligation | explicit | Pin canonical domain-separated successor-key derivation with known-answer vectors. | The exact successor-key derivation must be canonical, domain-separated, and pinned by known-answer test vectors. | DSM-HL-064/L3288 | none |
| DBTC-SPEC-19-02/L1099 | obligation | explicit | Successor derivation binds origin ID, next generation, parent outpoint, exact transaction commitment, successor parameters and fresh material. | It must bind at minimum: | DSM-HL-064/L3288 | ambiguous |
| DBTC-SPEC-19-02/L1113 | prohibition | explicit | A parent scalar alone cannot serve as an unrestricted reusable successor credential. | The parent scalar alone must not constitute an unrestricted reusable successor credential outside the constrained vault transition. | DSM-HL-064/L3288 | none |

### DBTC-SPEC-19-03 — 19.3 Successor activation

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-19-03/L1120 | transition | explicit | A successor may remain pending until accepted Bitcoin inclusion reaches the committed redeemability depth. | Before the Bitcoin transaction reaches the confirmation policy required for redeemability, the successor may be represented as: | DSM-HL-064/L3288 | none |
| DBTC-SPEC-19-03/L1132 | invariant | explicit | Activation changes backing generation without changing economic origin provenance. | Activation changes the Bitcoin backing generation, not the economic origin. | DSM-HL-064/L3288 | none |

### DBTC-SPEC-20 — 20 Why the Parent Cannot Remain the Authority

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-20/L1159 | invariant | explicit | A spent parent and confirmed successor cannot simultaneously count as live backing. | For one realized branch of a dBTC vault lineage, a spent parent Bitcoin generation and its confirmed successor must not both be classified as live backing. | DSM-HL-064/L3288 | none |

### DBTC-SPEC-21 — 21 No Separate dBTC Double-Spend System

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-21/L1190 | invariant | explicit | Arbitrary dBTC-looking bytes cannot authorize release without valid live-state inclusion, authority, provenance and consumption. | Producing arbitrary dBTC-looking bytes cannot authorize Bitcoin release because the claimant must prove actual state inclusion, current-state validity, authority, provenance, and consumption. | DBTC-SPEC-12/L650 | none |
| DBTC-SPEC-21/L1194 | prohibition | explicit | A previous owner cannot withdraw from state already consumed by an accepted successor. | A prior owner who retains an old dBTC state does not regain withdrawal authority after that state has been consumed by an accepted DSM successor. | DBTC-SPEC-12/L644 | none |

### DBTC-SPEC-22 — 22 Online dBTC

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-22/L1209 | evidence | explicit | Online burns prove consumption against the canonical admitted economic root. | A withdrawal from online dBTC must prove the burn against the canonical economic root: | DSM-HL-064/L3219 | none |
| DBTC-SPEC-22/L1213 | evidence | explicit | Online proof establishes predecessor inclusion, authority, exact removal, canonical successor, admitted economic position and intent-bound completion. | The proof must establish: | DSM-HL-064/L3219 | none |
| DBTC-SPEC-22/L1229 | prohibition | explicit | A wallet cache cannot substitute for canonical economic-root proof. | A local wallet cache must not substitute for proof of the canonical $R_{\mathrm{econ}}$ state. | DSM-HL-064/L3219 | none |

### DBTC-SPEC-23 — 23 Offline dBTC

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-23/L1238 | dependency-boundary | explicit | Offline withdrawal imports the existing verifier's live-allocation, genuine authority, current protected state, single consumption, successor and intent checks without treating them as a SoFi root. | A Bitcoin withdrawal from an offline allocation may use an $\mathsf{OfflineBurnProof}$ only if the existing offline verifier proves: | DSM-HL-066/L3362 | none |
| DBTC-SPEC-23/L1254 | prohibition | explicit | Offline burn proofs and admitted online roots cannot substitute for each other. | An offline burn proof must not be treated as an admitted SoFi $R_{\mathrm{econ}}$ root merely because both carry dBTC. | DSM-HL-005/L283 | none |

### DBTC-SPEC-24 — 24 Storage Nodes

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-24/L1265 | obligation | explicit | Vault metadata and proofs may be served by storage so future holders need not contact depositors. | They may be used so that a future dBTC holder can retrieve the vault material even if the original depositor is permanently offline. | DSM-HL-064/L3201 | none |
| DBTC-SPEC-24/L1279 | prohibition | explicit | Nodes cannot decide ownership, validate burns as authority, hold mint or plaintext vault keys, sign exits or choose successors. | A storage node must not: | DSM-HL-064/L3201 | none |
| DBTC-SPEC-24/L1295 | liveness-boundary | explicit | Storage compromise or omission may delay retrieval but must confer no economic authority. | A malicious or unavailable storage service may degrade availability. | DSM-HL-064/L3201 | none |

### DBTC-SPEC-25 — 25 Original Depositor Independence

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-25/L1324 | liveness-boundary | explicit | A current holder's withdrawal cannot require the original depositor to return online. | A valid current dBTC holder’s ability to exercise an ordinary withdrawal must not require the origin depositor to return online. | DSM-HL-064/L3201 | none |

### DBTC-SPEC-26 — 26 Multi-Origin Balances

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-26/L1329 | obligation | explicit | A wallet may hold multiple origin allocations while preserving their independent backing attribution. | A wallet may hold dBTC originating from several Bitcoin-backed DLVs. | DSM-HL-064/L3219 | none |
| DBTC-SPEC-26/L1347 | evidence | explicit | Each Bitcoin backing input requires independently justified consumption from its own origin. | Each input must be independently justified by dBTC consumed from the corresponding origin. | DSM-HL-064/L3219 | ambiguous |
| DBTC-SPEC-26/L1351 | invariant | explicit | A burn cannot consume more dBTC from an origin than the claimant's live allocation from that origin. | For every origin $v_i$: | DSM-HL-064/L3219 | none |
| DBTC-SPEC-26/L1361 | prohibition | explicit | Redeem against a different origin only after an explicit canonical provenance-changing transition. | A holder must not redeem dBTC attributed to origin $v_A$ against unrelated origin $v_B$ unless an explicit canonical protocol transition has changed the provenance relationship. | DSM-HL-064/L3219 | none |

### DBTC-SPEC-27 — 27 Fee Accounting

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-27/L1366 | obligation | explicit | Include Bitcoin fees in conservation arithmetic. | Bitcoin fees consume value and therefore must appear in conservation arithmetic. | DSM-HL-064/L3288 | none |
| DBTC-SPEC-27/L1374 | obligation | explicit | Account explicitly for retained anchor value under the continuing backing policy. | If the anchor remains part of the continuing backing policy, it must be accounted accordingly. | DSM-HL-064/L3288 | ambiguous |
| DBTC-SPEC-27/L1380 | prohibition | explicit | No post-burn fee increase may silently remove additional backing. | No implementation may silently increase the Bitcoin fee after the DSM burn if the increase changes how much backing leaves the dBTC system. | DSM-HL-064/L3288 | none |
| DBTC-SPEC-27/L1382 | transition | derived | Every economically relevant fee change requires an exactly recomputed accounting transition. | Any economically relevant fee change requires a transition whose accounting recomputes exactly. | DSM-HL-064/L3288 | none |

### DBTC-SPEC-28 — 28 Conservation

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-28/L1393 | invariant | derived | Track burned units awaiting Bitcoin execution separately from live spendable dBTC so retained backing covers both. | - $X_v$: already consumed dBTC with an outstanding Bitcoin execution claim, if the implementation separates burn from observed confirmation; and | DSM-HL-064/L3288 | tension(SOFI-052/L2540) |
| DBTC-SPEC-28/L1411 | invariant | explicit | Outstanding redeemable claims fall by the same amount as backing-paid payouts and fees. | The outstanding redeemable dBTC attributed to that lineage must fall by the same backing reduction: | DSM-HL-064/L3288 | ambiguous |
| DBTC-SPEC-28/L1419 | invariant | explicit | No accepted sequence leaves origin-attributed redeemable dBTC above the origin's retained backing. | No accepted protocol sequence may leave more redeemable dBTC attributed to an origin than the Bitcoin backing retained by that origin under the committed fee and reserve policy. | DSM-HL-064/L3288 | none |

### DBTC-SPEC-29 — 29 Crash Safety and Replay

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-29/L1424 | obligation | explicit | Withdrawal execution must be crash-safe across DSM and Bitcoin. | Withdrawal crosses two systems and must be crash-safe. | DSM-HL-064/L3225 | none |
| DBTC-SPEC-29/L1434 | obligation | derived | Persist burn-completion evidence before deriving and using execution authority. | 4.  durably retain burn completion evidence; | DSM-HL-064/L3225 | none |
| DBTC-SPEC-29/L1442 | obligation | derived | Persist the exact signed transaction before broadcasting. | 8.  durably retain the signed transaction; | DSM-HL-064/L3225 | none |
| DBTC-SPEC-29/L1452 | obligation | explicit | After burn, recovery resumes the identical committed transaction or fails closed. | Once the burn commits an exact Bitcoin transaction body, crash recovery must either: | DSM-HL-064/L3225 | none |
| DBTC-SPEC-29/L1458 | prohibition | explicit | Recovery cannot reuse a burn for another destination, amount or successor. | Recovery must not use the same burn to construct a different destination, amount, or successor. | DSM-HL-064/L3225 | none |
| DBTC-SPEC-29/L1462 | prohibition | explicit | Missing Bitcoin observation cannot remint dBTC while a valid signed release may exist. | Failure to observe a Bitcoin transaction immediately must not automatically recreate spendable dBTC if a Bitcoin-valid signed transaction may still exist. | DSM-HL-064/L3225 | tension(SOFI-052/L2540) |
| DBTC-SPEC-29/L1464 | evidence | explicit | Refund or recovery proves a mutually exclusive condition making the original release impossible. | Any recovery/refund transition must prove a mutually exclusive state under which the original Bitcoin release can no longer validly take effect. | DSM-HL-064/L3225 | none |

### DBTC-SPEC-30 — 30 Concurrent Local Invocation

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-30/L1479 | obligation | explicit | Serialize local execution per vault-generation or use equivalent atomic compare-and-set. | Class K must serialize local execution of one $(v,n)$ generation or use an equivalent atomic compare-and-set guard. | DSM-HL-064/L3225 | ambiguous |
| DBTC-SPEC-30/L1481 | prohibition | explicit | A second local invocation of a committed generation fails closed. | A second local execution request against an already committed generation must fail closed. | DSM-HL-064/L3225 | none |
| DBTC-SPEC-30/L1483 | authority | derived | Local concurrency control does not replace economic validity. | This is implementation concurrency control. It is not a new economic authority and does not replace DSM state validity. | DSM-HL-064/L3225 | none |

### DBTC-SPEC-31 — 31 Security Properties

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-31/L1490 | theorem | explicit | Opening vault authority implies an intent-bound valid DSM consumption. | If a Bitcoin vault authority is opened through the conforming dBTC path, then there exists a valid DSM consumption of the dBTC quantity bound to that withdrawal. | DBTC-SPEC-12/L630 | none |
| DBTC-SPEC-31/L1494 | invariant | explicit | Replicated public vault metadata cannot create positive dBTC. | Public or replicated DLV metadata cannot create a positive dBTC balance. | DBTC-SPEC-07/L373 | none |
| DBTC-SPEC-31/L1498 | invariant | explicit | Consumed state cannot satisfy current ownership for another withdrawal. | A state already consumed by a valid DSM successor cannot independently satisfy the current-state requirement for another withdrawal. | DBTC-SPEC-21/L1194 | none |
| DBTC-SPEC-31/L1508 | safety-assumption | explicit | Changing lock, parameters or completion changes the derived unlock except with negligible hash-collision probability. | changes the DLV unlock derivation except with negligible probability under the hash assumptions. | DSM-HL-064/L3225 | none |
| DBTC-SPEC-31/L1512 | invariant | explicit | A successor cannot retain more Bitcoin than the parent less declared payout and backing-paid fees. | A partial withdrawal cannot validly create a successor whose retained Bitcoin value exceeds: | DSM-HL-064/L3225 | none |
| DBTC-SPEC-31/L1520 | invariant | explicit | A successor below origin-committed Bmin cannot be created or activated. | A partial withdrawal cannot validly create or activate a successor whose retained Bitcoin backing is below the lineage-wide $B_{\min}$ committed by the origin policy, under the declared fee and anchor treatment. | DBTC-SPEC-19/L1032 | none |
| DBTC-SPEC-31/L1524 | invariant | explicit | Spent parent execution authority cannot remain authority over its confirmed successor. | A spent parent generation does not remain the Bitcoin execution authority for the confirmed successor generation. | DBTC-SPEC-19-02/L1091 | none |
| DBTC-SPEC-31/L1528 | invariant | explicit | Storage compromise alone cannot create a valid burn or constrained withdrawal. | Compromise of Class N storage alone does not create a valid dBTC burn or a valid constrained Bitcoin withdrawal. | DBTC-SPEC-24/L1279 | none |
| DBTC-SPEC-31/L1532 | liveness-boundary | explicit | Ordinary circulation and valid withdrawal need no post-admission depositor approval. | After origin admission, ordinary transfer and valid bearer withdrawal do not require the original depositor’s approval. | DBTC-SPEC-25/L1324 | none |

### DBTC-SPEC-32 — 32 What a Device Compromise Means

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-32/L1539 | safety-assumption | derived | Compromise sufficient to produce an accepted DSM burn compromises that dBTC. | If an attacker compromises enough of the claimant’s DSM authority to produce a transition that the applicable DSM verifier accepts as a valid burn, then the attacker has compromised that dBTC. | DSM-HL-064/L3201 | none |
| DBTC-SPEC-32/L1549 | prohibition | explicit | Bitcoin material must not become an independent bearer-ownership system. | > Nor should Bitcoin weaken DSM by becoming an independent bearer-authority system. | DSM-HL-064/L3201 | none |

### DBTC-SPEC-34 — 34 What Is Deliberately Not Claimed

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-34/L1593 | safety-assumption | derived | The protocol does not prevent Bitcoin reorganizations beyond the profile's accepted depth. | 1.  that DSM can prevent a Bitcoin reorganization deeper than the chosen confirmation assumption; | DSM-HL-064/L3201 | none |
| DBTC-SPEC-34/L1605 | safety-assumption | derived | Test-network shortcuts do not establish mainnet settlement security. | 7.  that testnet or Signet confirmation shortcuts imply mainnet security; or | DSM-HL-064/L3201 | none |
| DBTC-SPEC-34/L1607 | obligation | derived | Existing primitive implementations alone do not establish conformance. | 8.  that implementation conformance follows merely because the required primitives exist in the repository. | DSM-HL-064/L3201 | none |

### DBTC-SPEC-38 — 38 Required Conformance Tests

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-38/L1846 | conformance-test | explicit | Provide deterministic conformance tests for every mandatory case in §38. | A conforming implementation must include deterministic tests covering at least the following cases. | DSM-HL-064/L3225 | none |

### DBTC-SPEC-38-01 — 38.1 Origin admission

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-38-01/L1851 | conformance-test | explicit | Test exact issuance for accepted confirmed backing and rejection of amount, script, network and depth mismatches or reused origin proofs. | 1.  Valid confirmed Bitcoin backing admits exactly matching dBTC. | DSM-HL-064/L3225 | none |

### DBTC-SPEC-38-02 — 38.2 DSM ownership

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-38-02/L1866 | conformance-test | explicit | Test valid live-state burn acceptance and rejection of nonexistent, stale, unauthorized, wrong-origin and forged-credit sources. | 1.  Valid live dBTC can enter a withdrawal burn. | DSM-HL-064/L3225 | none |

### DBTC-SPEC-38-03 — 38.3 DLV fulfillment

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-38-03/L1881 | conformance-test | explicit | Test known-answer unlock derivation and sensitivity to each lock, parameter and completion input. | 1.  Correct $L,C,\sigma$ derives the expected $sk_V$. | DSM-HL-064/L3225 | none |
| DBTC-SPEC-38-03/L1889 | conformance-test | explicit | Test rejection of wrong preimages, foreign vault or generation burns and completion unbound to intent. | 5.  Wrong preimage fails the Bitcoin hash lock. | DSM-HL-064/L3225 | none |

### DBTC-SPEC-38-04 — 38.4 Full withdrawal

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-38-04/L1900 | conformance-test | explicit | Test that full burns authorize only their committed transaction with immutable destination, amount and fee treatment. | 1.  Full burn signs only the committed full withdrawal. | DSM-HL-064/L3225 | none |
| DBTC-SPEC-38-04/L1908 | conformance-test | explicit | Test no full-exit successor and terminal parent after confirmed full spend. | 5.  Full withdrawal creates no successor vault. | DSM-HL-064/L3225 | none |

### DBTC-SPEC-38-05 — 38.5 Partial withdrawal

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-38-05/L1915 | conformance-test | explicit | Test a partial burn produces exactly one successor with conserved amount, one generation increment and correct transaction outpoint. | 1.  Partial burn creates exactly one canonical successor output. | DSM-HL-064/L3225 | none |
| DBTC-SPEC-38-05/L1923 | conformance-test | explicit | Test fresh successor authority, retained origin identity and unusable spent-parent authority. | 5.  Successor authority differs from parent authority. | DSM-HL-064/L3225 | none |
| DBTC-SPEC-38-05/L1929 | conformance-test | explicit | Test rejection of post-burn successor key, script or amount changes. | 8.  Mutating successor key or script after burn fails. | DSM-HL-064/L3225 | none |
| DBTC-SPEC-38-05/L1933 | conformance-test | explicit | Test under-floor splits fail before completion and successors cannot modify Bmin. | 10. A partial withdrawal whose successor backing would fall below the origin-committed $B_{\min}$ rejects before completion evidence is produced. | DSM-HL-064/L3225 | none |

### DBTC-SPEC-38-06 — 38.6 Storage

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-38-06/L1940 | conformance-test | explicit | Test that public vault data, copied node records and capsule ciphertext cannot create burns, value or withdrawal authority. | 1.  Public DLV data alone cannot produce a burn. | DSM-HL-064/L3225 | none |
| DBTC-SPEC-38-06/L1946 | conformance-test | explicit | Test storage omission affects availability only and nodes never invoke Bitcoin signers. | 4.  Storage omission causes availability failure, not value creation. | DSM-HL-064/L3225 | none |

### DBTC-SPEC-38-07 — 38.7 Crash and recovery

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-38-07/L1953 | conformance-test | explicit | Test crash recovery before burn cannot unlock and post-burn recovery resumes only the same withdrawal. | 1.  Crash before burn leaves no valid unlock proof. | DSM-HL-064/L3225 | none |
| DBTC-SPEC-38-07/L1957 | conformance-test | explicit | Test exact signed-transaction retention across broadcast crashes without reminting. | 3.  Crash after signing but before broadcast retains the exact signed transaction. | DSM-HL-064/L3225 | none |
| DBTC-SPEC-38-07/L1965 | conformance-test | explicit | Test recovery cannot change destination or successor and replay cannot create a second independent economic effect. | 7.  Replaying a completed burn cannot generate a second independent dBTC debit or credit. | DSM-HL-064/L3225 | none |

### DBTC-SPEC-38-08 — 38.8 Online/offline separation

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-38-08/L1970 | conformance-test | explicit | Test online proof against admitted roots and rejection of unauthenticated wallet caches. | 1.  Online burn verifies against admitted $R_{\mathrm{econ}}$. | DSM-HL-064/L3225 | none |
| DBTC-SPEC-38-08/L1974 | dependency-boundary | explicit | Import tests that offline burns use the existing protected-state verifier without extracting its internals. | 3.  Offline burn verifies through the existing protected-state path. | DSM-HL-064/L3225 | none |
| DBTC-SPEC-38-08/L1976 | conformance-test | explicit | Test offline allocations are not directly spendable in SoFi and online and offline proofs are not interchangeable. | 4.  Offline allocation cannot be used directly as SoFi online liquidity. | DSM-HL-064/L3225 | none |

### DBTC-SPEC-39 — 39 Proof Obligations

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-39/L1983 | proof-obligation | explicit | Discharge the listed dBTC obligations in DSM's existing formal stack where substrate lemmas exist. | The following obligations should be discharged in the existing DSM formal verification stack where their substrate lemmas already exist. | DSM-HL-064/L3225 | none |
| DBTC-SPEC-39/L1987 | proof-obligation | explicit | Prove two accepted burns cannot consume the same canonical source quantity. | For one canonical spendable dBTC source state, two different accepted burns cannot both consume the same economic quantity. | DSM-HL-064/L3225 | none |
| DBTC-SPEC-39/L1991 | proof-obligation | explicit | Prove every accepted vault unlock implies existence of a valid intent-bound burn. | For any accepted dBTC vault unlock: | DSM-HL-064/L3225 | none |
| DBTC-SPEC-39/L2000 | proof-obligation | explicit | Prove that amount, destination, generation or successor mutation invalidates execution. | For any valid burn proof $\sigma$, changing the withdrawal amount, destination, backing generation, or successor commitment causes the associated vault execution check to fail. | DSM-HL-064/L3225 | none |
| DBTC-SPEC-39/L2010 | proof-obligation | explicit | Prove partial-split conservation including payout, fees, successor and retained anchor. | under the declared transaction profile. | DSM-HL-064/L3225 | none |
| DBTC-SPEC-39/L2014 | proof-obligation | explicit | Prove a confirmed successor cannot coexist with its spent parent as live backing. | After a partial withdrawal confirms, the parent backing output is not simultaneously represented as live backing beside its successor. | DSM-HL-064/L3225 | none |
| DBTC-SPEC-39/L2018 | proof-obligation | explicit | Prove every accepted partial successor meets immutable Bmin. | For every accepted partial withdrawal under a lineage with committed $B_{\min}$, the resulting successor backing satisfies: | DSM-HL-064/L3225 | none |
| DBTC-SPEC-39/L2022 | proof-obligation | explicit | Prove no invalid under-floor split yields burn completion evidence. | No valid burn may produce completion evidence for a split that violates this bound. | DSM-HL-064/L3225 | none |
| DBTC-SPEC-39/L2026 | proof-obligation | explicit | Prove transfers, splits, merges and burns conserve origin allocations except canonical issuance and withdrawal burns. | Transfer, split, merge, and burn operations preserve the total origin-attributed dBTC quantity except for explicit valid issuance and explicit withdrawal burn. | DSM-HL-064/L3225 | none |

### DBTC-SPEC-41 — 41 Final Protocol Invariant

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| DBTC-SPEC-41/L2103 | invariant | explicit | The final partial-release invariant requires retained backing under fresh authority with the immutable lineage floor. | where $V_{n+1}$ carries the remaining backing under fresh execution authority and additionally satisfies the lineage-wide floor: | DSM-HL-064/L3225 | none |
| DBTC-SPEC-41/L2131 | authority | explicit | Economic authority comes from valid state and valid transitions rather than detached bookkeeping. | > Authority is established by valid state and a valid transition, not by possession of detached mutable bookkeeping. | DSM-HL-064/L3225 | none |

## DSM_Storage_Node_Specification.md

### STOR-PREAMBLE — Read this first

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-PREAMBLE/L19 | authority | explicit | Storage rules refine the overarching DSM specification without redefining it. | - `DSM_High_Level_Explainer.md` governs. This document refines it and must not silently redefine it. | — | none |
| STOR-PREAMBLE/L20 | obligation | explicit | Specification conflicts require owner resolution before code changes. | - This document does not redefine SoFi or dBTC. Where it appears to conflict with either, the conflict is listed in §23 for the owner to resolve before code changes. | — | none |
| STOR-PREAMBLE/L32 | obligation | explicit | Items marked Open remain undecided and must not be implemented as settled requirements. | \| **Open** \| A decision this document needs and does not make. \| | — | ambiguous |
| STOR-PREAMBLE/L36 | obligation | explicit | Departures from SHOULD requirements need written reasons while MUST requirements cannot be relaxed. | MUST and MUST NOT state requirements an implementation cannot relax. SHOULD states a requirement that may be departed from only with a written reason. MAY states a permission. Statements without these words are explanatory unless labelled Rule, Invariant, Property or Proof Obligation. | — | none |

### STOR-001 — 1 What a storage node is

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-001/L60 | prohibition | explicit | Nodes hold no key and sign nothing. | 1. A node MUST hold no key and MUST sign nothing. | — | none |
| STOR-001/L61 | prohibition | explicit | Nodes cannot validate protocol rules, evaluate guards, calculate balances or leaders, compare values or judge transitions. | 2. A node MUST NOT validate a protocol rule, evaluate a guard, compute a balance, compute a leader, compare one value with another, or decide whether a transition is valid. | — | tension(STOR-016/L414) |
| STOR-001/L62 | prohibition | explicit | Payloads remain opaque apart from content addressing and node storage cannot vary with payload interpretation. | 3. Economic and protocol payloads MUST be opaque to the node apart from content addressing. The node MUST NOT vary what it stores by what a payload would parse as. | — | none |
| STOR-001/L63 | prohibition | explicit | Protocol node paths use logical ticks without clock reads. | 4. No protocol-relevant path in the node MAY read a clock. Ordering inside the node uses logical ticks. | — | none |
| STOR-001/L64 | prohibition | explicit | Gossip only synchronizes state without leader election, Raft, Paxos or votes. | 5. Inter-node gossip is state synchronisation only. There is no leader election, no Raft, no Paxos, and no vote between nodes. | — | none |
| STOR-001/L68 | authority | explicit | Any addition requiring storage to understand protocol meaning belongs in another layer. | Every addition to the node answers one question before it is written: does storage need to know what this means? If yes, the addition is in the wrong layer. | — | none |

### STOR-002 — 2 What a node never does

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-002/L75 | prohibition | explicit | Nodes cannot exercise asset ownership, minting, burn-validation, plaintext vault-key, signing or successor-selection authority. | A node MUST NOT decide who owns an asset, validate a burn as an economic authority, possess a mint key, possess a plaintext reusable Bitcoin vault key, sign a Bitcoin exit, convert an invalid DSM transition into a valid one, or choose a successor on behalf of the protocol. A malicious or unavailable node may degrade availability. It MUST NOT gain authority from the bytes it stores. | — | none |

### STOR-003 — 3 Fault model

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-003/L82 | safety-assumption | explicit | The storage fault model allows crashes and message omissions. | 1. A node may crash and may omit messages. | — | none |
| STOR-003/L83 | safety-assumption | explicit | A member never equivocates, alters, reorders or permanently loses held bytes across restart, restore or migration. | 2. A node never equivocates, never alters content it holds, never reorders what it holds for a key, and never permanently loses stored bytes, including across restart, restoration, and storage migration. | — | conflict(STOR-003/L94) |
| STOR-003/L84 | safety-assumption | explicit | Restoring a snapshot older than a held value violates safety. | 3. Restoring a node from a snapshot that predates a value it held is a safety violation, not an availability event. | — | none |
| STOR-003/L85 | liveness-boundary | explicit | Hash-detectable immutable misresponses affect availability only. | 4. Misresponses about immutable objects are detectable by hash and affect availability only. | — | none |
| STOR-003/L86 | obligation | explicit | Storage outside the stated fault model fails closed. | 5. A store that falls outside this model fails closed. | — | none |
| STOR-003/L90 | liveness-boundary | explicit | Missing leader or replica access stalls finality while loss of durable memory violates safety. | Failure to reach a cell's leader, or two other members, is a liveness failure: the cell waits. Violation of durable memory is a safety failure. | — | none |
| STOR-003/L94 | safety-assumption | explicit | Durable memory belongs to a role across machine handover and an empty replacement cannot impersonate its lost history. | Items 2 and 3 bind a *role* (§11), not a machine. A role's memory survives the machine that serves it through handover (§12.5). The loss of every copy of a role's memory is handled by §12.6, never by treating a new machine's empty memory as the role's history. | — | conflict(STOR-003/L83) |

### STOR-004 — 4 What storage facts are

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-004/L101 | authority | explicit | Core derives only LeaderHeld, Final and Stored from raw reads and none establishes semantic validity. | Core derives exactly three storage facts from raw reads: `LeaderHeld(K, x)`, `Final(K, x)`, and `Stored(o)`. It uses nothing else from storage. Registered is not Validated, and a storage fact implies nothing about semantic validity. | — | none |
| STOR-004/L105 | prohibition | explicit | Failure to establish a storage fact does not establish its negation and rejected presentations record no outcome. | A storage fact is either established from the reads in hand or not established, and a fact that is not established is never read as its negation. A verifier records nothing for a presentation it does not accept. Nothing a node returns is a verdict. | — | none |

### STOR-005 — 5 Immutable objects

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-005/L116 | obligation | explicit | Compute immutable addresses as H(DSM/storage-object ∥ namespace ∥ H(namespace ∥ payload)). | 1. A payload `P` in namespace `N` is stored at `addr = H(DSM/storage-object ∥ N ∥ H(N ∥ P))`, computed by the node from the input. | — | none |
| STOR-005/L117 | obligation | explicit | Check caller addresses against the computed address and never use the supplied address as the storage key. | 2. A caller-supplied address is checked against the computed one and never used as the key. | — | none |
| STOR-005/L118 | prohibition | explicit | Expose no immutable update or overwrite path. | 3. There is no update path and no overwrite path. The path is absent, not a path that refuses. | — | none |
| STOR-005/L119 | transition | explicit | Identical byte replays re-acknowledge and differing bytes at one address report corruption. | 4. Replaying identical bytes re-acknowledges. Different bytes at the same address are reported as corruption. | — | none |
| STOR-005/L120 | evidence | explicit | The node rehashes on serving and the client rehashes independently. | 5. On read, the node recomputes the address before serving. The client re-hashes regardless. | — | none |
| STOR-005/L121 | evidence | explicit | Stored requires the same exact object bytes from three committed members. | 6. `Stored(o)` holds when three members of `S` return the exact bytes of `o`. | — | none |

### STOR-006 — 6 Keyed cells

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-006/L128 | obligation | explicit | Keyed puts append bytes after all previously held values. | 1. Put at a key stores the bytes a writer sends for that key after everything already held there. | — | tension(SOFI-017-4/L1081) |
| STOR-006/L129 | obligation | explicit | Keyed reads return all held bytes in arrival order or state that none are held. | 2. Get returns everything held at the key, in the order it arrived, or that it holds none. | — | none |
| STOR-006/L130 | authority | explicit | Keyed storage has no writer authorization and permits only the declared spend-gate refusal exception. | 3. No member refuses, replaces or compares anything held at a key, except that a node MAY refuse a write addressed to an account that has not met the spend-gate (§16, §17). There is no write authorization: a signed object carries its signer's authority, and a derived object is recomputed by whoever reads it. | — | tension(STOR-009-1/L193) |
| STOR-006/L131 | obligation | explicit | Any carrier may finish copying bytes to unreached members. | 4. Any party MAY carry bytes to members not yet reached. | — | none |

### STOR-007 — 7 Indexes

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-007/L138 | obligation | explicit | Anyone may append an already-held object's address under any locator and paged reads preserve append order without deletion. | Anyone MAY append the content address of an object the member already holds under any locator. Appends are never removed. A read returns addresses in append order, paged. The member interprets nothing. | — | none |

### STOR-008 — 8 Mirror, spool, and identity storage

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-008/L145 | obligation | explicit | Mirror public device heads and encrypted per-relationship leaves under device-and-relationship keys. | 1. **Tip mirror.** A public head and encrypted per-relationship leaves, keyed by device and relationship. | — | none |
| STOR-008/L146 | obligation | explicit | Spools use versioned insertion-ordered envelopes acknowledged by routing key without node inspection. | 2. **Inbox spool.** Unilateral delivery to an offline counterparty. Envelopes are strictly versioned, ordered by insertion, acknowledged per routing key, and never opened by the node. | — | none |
| STOR-008/L147 | dependency-boundary | explicit | Identity and recovery storage import genesis, device-tree and recovery-capsule bytes only. | 3. **Identity and recovery.** Genesis anchoring, device-tree indexing, and recovery capsules, stored as bytes under derived keys. Recovery is out of scope for this round; this document imports it as substrate only. | — | none |
| STOR-008/L151 | obligation | explicit | Routing and token-policy contact boundaries require mutual pre-add from committed state rather than first contact. | Nothing can be sent to a party that has not pre-established the sender as a contact. A relationship is created by mutual pre-add from committed state, never by first contact (DSM §9, §13), and the same rule governs token policies. | — | none |
| STOR-008/L153 | obligation | explicit | Messages address a relationship chain ID derived from the two devices rather than a genesis account. | 1. A message is sent to a relationship, never to a genesis account. The relationship is addressed by its chain id, the hash of the two device ids. | — | none |
| STOR-008/L154 | prohibition | explicit | Senders send only to relationships already pre-added. | 2. **Sender side.** The sender's device sends only over a relationship it has pre-added. With no relationship there is nothing to address, so nothing is sent. | — | none |
| STOR-008/L155 | evidence | explicit | Recipients read only pre-added relationships and accept only the other device's signature. | 3. **Recipient side.** The recipient's device reads only relationships it has pre-added, and accepts a message only if it is signed by the other device of that relationship. | — | none |
| STOR-008/L156 | obligation | explicit | Endpoint devices enforce canonical encoding, authentication, replay protection and recipient-key checks. | 4. The checks listed in DSM §11 (canonical encoding, device authentication, replay-protected message id, recipient key) are performed by the devices at both ends. | — | none |
| STOR-008/L160 | prohibition | explicit | Nodes must not verify writer identity or relationship membership. | The node does not verify who is writing, not even that the writer is one of the relationship's two devices. A node that can check can block, and blocking is an authority the node must not have. Software that skips the sender-side check can still compute a relationship id and write bytes under it; those bytes are never read by the recipient and change nothing. That is accepted. | — | ambiguous |

### STOR-009 — 9 Leader and finality

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-009/L167 | obligation | explicit | Core and writers derive leaders with the specified Fisher–Yates algorithm while nodes remain unaware of leadership. | 1. The writer and Core compute a cell's leader as `L(K) = FisherYates(s, S)[0]`, with the shuffle of SoFi §7.1. A node never computes a leader and does not know which cells it leads. | — | none |
| STOR-009/L168 | prohibition | explicit | Leader seeds use committed state without caller, availability or node-ID inputs. | 2. The seed `s` is derived from committed state only. Availability, the caller's identity, and node ids never enter a seed. | — | none |
| STOR-009/L169 | invariant | explicit | Leader derivation uses the originally committed set including offline members. | 3. `S` is the storage set committed in the state that seeds the cell. A member that is offline is still in `S`. | — | none |
| STOR-009/L170 | prohibition | explicit | Do not read a storage cell for a transition already invalid on locally available evidence. | 4. A verifier reads a cell only after every check it can decide from evidence already in hand has passed. A transition that is Invalid on what the verifier holds never causes a storage read (Imported: DSM Amendment A4). | — | none |
| STOR-009/L174 | invariant | explicit | Finality requires the first recognized leader-held object plus identical copies at two other set members. | `Final(K, x) ⇔ x is the first object naming K at the leader ∧ \|{m ∈ S \ {leader} : m holds x}\| ≥ 2`. | — | none |
| STOR-009/L176 | authority | explicit | Only Core evaluates finality. | 1. Core evaluates finality from raw reads. No node evaluates it. | STOR-004/L101 | none |
| STOR-009/L177 | invariant | explicit | An object absent from the leader can never be final. | 2. A value the leader does not hold is never final. | STOR-009/L174 | none |
| STOR-009/L178 | invariant | explicit | At most one object is final at a cell. | 3. At most one value is final at a cell. | STOR-009/L174 | none |
| STOR-009/L179 | liveness-boundary | explicit | An unreachable leader stalls its cell without substitution. | 4. If the leader is unreachable, the cell waits. No other member stands in. | STOR-003/L90 | none |
| STOR-009/L183 | invariant | explicit | Historical leader roles cannot change with later sets, registry changes or operator bindings. | A cell's leader is a function of the set committed when the cell was seeded. It MUST NOT be re-derived over any later set, registry, or binding. Changing who serves a role (§12) never changes which role leads a cell. | — | none |

### STOR-009-1 — 9.1 Pending challenges counted in the leader's ByteCommits

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-009-1/L190 | obligation | explicit | Any party may challenge a party-dependent pending result at that cell's leader. | 1. When a result is pending on one party, any party MAY write a challenge to the pending cell's leader. | — | none |
| STOR-009-1/L191 | transition | explicit | The challenged party can supply missing evidence and an eligible drop claim competes with its answer. | 2. The challenged party answers by supplying what is missing. The alternative is a drop claim. | — | none |
| STOR-009-1/L192 | transition | explicit | Answer and eligible drop are decided by arrival at the cell's leader. | 3. The answer and the drop claim race to the cell's leader, like every race: the first to reach the leader wins. | — | none |
| STOR-009-1/L193 | evidence | explicit | A drop counts only after X leader ByteCommits following the first leader root including the challenge. | 4. A drop claim counts only if the leader's own ByteCommit chain shows at least X ByteCommits closed after the first of the leader's ByteCommits whose root includes the challenge. A drop claim that arrives before that counts as nothing. | — | tension(DSM-HL-005/L298) |
| STOR-009-1/L194 | transition | explicit | A winning drop permanently ends the pending result for every verifier and later evidence cannot revive it. | 5. Once a drop claim wins, the pending result is dropped for every verifier, and later evidence for it is ignored. In SoFi, a dropped trade is Void: it never executes and moves no balance. | — | none |
| STOR-009-1/L195 | liveness-boundary | explicit | An unreachable leader does not advance its challenge deadline. | 6. If the leader is unreachable, its chain does not advance and the deadline does not arrive. The cell waits, as it always does. | — | tension(STOR-006/L130) |
| STOR-009-1/L196 | prohibition | explicit | Challenge only evidence uniquely obtainable from the challenged party and relay anything others can complete. | 7. A challenge applies only where the missing piece can come from the challenged party alone. Anything a relayer can complete is completed by relaying. | — | none |
| STOR-009-1/L202 | obligation | explicit | Open: X, challenge and drop wire forms, and the SoFi drop-consumption rule remain unspecified. | **Open:** the value of X; the wire form of a challenge and a drop claim; and the SoFi rule that consumes a dropped result (SoFi §24 has no rung for it). | — | ambiguous |

### STOR-010 — 10 Storage sets

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-010/L213 | obligation | explicit | Commit five sorted member IDs in storage_set_id without endpoint identity. | 1. A storage set is five member ids committed in state, identified by `storage_set_id`, which covers member ids only and never endpoints. | — | none |
| STOR-010/L214 | obligation | explicit | Accept vault genesis only with the network-pinned set. | 2. A vault's set is the network's pinned set. Vault genesis is accepted only if `storage_set_id` equals it. | — | none |
| STOR-010/L218 | obligation | explicit | Party-owned objects and cells use that party's set. | 1. Every party has its own storage set for its own objects and cells. Traders' objects and cells go to the trader's set; an owner's objects and cells go to the owner's set. | — | tension(SOFI-017-1/L982) |
| STOR-010/L219 | obligation | explicit | Assign party sets by Fisher–Yates from the active registry rather than party selection. | 2. A party's set is assigned from the active registry by Fisher–Yates. The party never chooses a member. | — | none |
| STOR-010/L220 | obligation | explicit | A party may opt out of a member but replacement is selected by the specified draw. | 3. A party MAY opt out of a member. The replacement is drawn by Fisher–Yates (§12.4). The party may draw another poor performer; that is accepted. | — | none |
| STOR-010/L221 | obligation | explicit | Party storage uses the committed credit mechanism. | 4. A party pays for storage with credits (§17). | — | none |
| STOR-010/L223 | obligation | explicit | Open: the location of the owner-committed device-register set in device state is unspecified. | **Open — device register set.** DSM §9 and §80.12 require the economic-root register's set to be "owner-committed". Where that set is committed in device state is not specified. | — | ambiguous |

### STOR-011 — 11 Member ids are seats

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-011/L230 | invariant | explicit | A committed member ID names a stable seat including its ordered key logs and immutable objects. | 1. A member id in a committed set names a **seat**: a stable logical position together with that seat's ordered memory (every key's arrival log and every immutable object stored under it). This document also calls a seat a *role*. | — | none |
| STOR-011/L231 | invariant | explicit | One operator serves a seat at a time and operator occupancy is not committed in party state. | 2. A seat is served by one operator at a time, `op(r)`. Which operator occupies a seat is not committed in any party's state. | — | none |
| STOR-011/L232 | invariant | explicit | Committed seats and historical leader roles remain fixed across operator replacement. | 3. Once `S` is committed, it never changes. The leader of every cell is a seat, so it is fixed forever (§9), whichever machine later occupies that seat. | — | none |
| STOR-011/L233 | obligation | explicit | Open: endpoint resolution is outside committed party state but its network-configuration versus committed-object authority is undecided. | 4. Operator endpoints are resolved outside committed state. Whether endpoint resolution is network configuration or a committed object is Open. | — | ambiguous |

### STOR-011-1 — 11.1 Two separate Fisher–Yates selections

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-011-1/L249 | obligation | explicit | Seat assignment draws from the registry excluding already-seated operators while cell leadership draws only from the five committed seats. | \| Drawn from \| The active registry, excluding operators already seated in the set \| The five seats of the committed set \| | — | none |
| STOR-011-1/L251 | obligation | explicit | Seat assignment uses seat-bind/v1 or rebind/v1 seeds and seat-fy-prf/v1 draws separately from SoFi leader domains. | \| Seed tags \| `DSM/storage/seat-bind/v1` at creation; `DSM/storage/rebind/v1` on replacement \| SoFi §7.2 (`storage-seed/v4` for vault cells; `DSM/economic/position-seed/v1` for positions) \| | — | none |
| STOR-011-1/L254 | prohibition | explicit | Seat and leader selections must use distinct seed and draw domains. | 1. The two selections MUST use distinct domain tags for their seeds and for their draw functions, so that no input to one can influence the other. | — | none |
| STOR-011-1/L255 | invariant | explicit | Replacing a seat's operator cannot change which cells that seat leads. | 2. Seat assignment never changes a leader: replacing the operator in seat 3 leaves seat 3 as seat 3, and every cell seat 3 led it still leads. | STOR-009/L183 | none |
| STOR-011-1/L256 | prohibition | explicit | Leader selection must not read operator occupancy. | 3. Leader selection never reads which operator occupies a seat. | STOR-009/L167 | none |

### STOR-012-1 — 12.1 Initial binding

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-012-1/L279 | obligation | explicit | Initial binding draws an unseated operator from the active registry using the creation commitment and seat under seat-bind/v1. | When a set is created, each seat is bound to an operator drawn from the active registry by the seat-assignment selection (§11.1), with seed `H(DSM/storage/seat-bind/v1; creating state commitment ∥ seat)`. Operators already seated in the same set are excluded from the draw. | — | none |

### STOR-012-2 — 12.2 Retirement triggers

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-012-2/L288 | transition | explicit | Owner opt-out retires members only for party sets and never for network-pinned vault sets. | 1. **Opt-out.** The party that owns a party set retires one of its members. This applies to party sets only, never to a vault's network-pinned set. | — | none |
| STOR-012-2/L289 | transition | explicit | Network removal retires every role of the underperforming operator without owner action. | 2. **Network cut.** The registry process (§13) removes an operator for under-performance. Every role bound to that operator is retired. | — | none |
| STOR-012-2/L291 | prohibition | explicit | Only owner opt-out and network cut may retire a binding. | No owner action is ever required for a network cut. There is no other trigger. | — | none |

### STOR-012-3 — 12.3 Retirement records

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-012-3/L298 | obligation | explicit | An immutable retirement record names one or two seats and labels each handover or loss. | 1. A retirement is recorded as an immutable object naming **one or two** seats of a set and, for each seat, whether it is a handover (§12.5) or a loss (§12.6). A network cut's record is the registry successor that removes the operator (§13). | — | conflict(STOR-012-6/L344) |
| STOR-012-3/L299 | evidence | explicit | Retirement becomes effective only when every unnamed surviving seat's operator holds its record. | 2. The **survivors** of a record are the seats it does not name. A record is **effective** once every survivor's current operator holds it. This is every survivor, not a count. | — | ambiguous |
| STOR-012-3/L300 | transition | explicit | An unreachable survivor may be added to a replacement two-seat record and any effective naming record supersedes a pending one for that seat. | 3. **Simultaneous or unreachable members.** A record never waits on a seat it names. If a survivor of a pending record is itself unreachable and is to be replaced, a new record naming both seats is issued; its survivors are the remaining three, and it becomes effective without the unreachable seat. Records only add: a seat is retired once any effective record names it, and a pending record that names the same seat is superseded. | — | ambiguous |
| STOR-012-3/L302 | transition | explicit | A verifier finding no retirement record in its read set proceeds as though none is effective. | - A verifier that finds a record at none of the members it read proceeds as though no such record is effective. | — | none |
| STOR-012-3/L303 | prohibition | explicit | A verifier seeing a retirement record must confirm it at every survivor or wait and cannot act on the old binding. | - A verifier that finds a record at any member MUST either confirm it at every survivor, and then treat it as effective, or wait. It MUST NOT proceed as though the record were not effective. | — | none |
| STOR-012-3/L304 | liveness-boundary | explicit | More than two unavailable seats is outside the replacement model and the set waits. | 5. **More than two seats out at once is outside the model.** Finality already needs three live seats, the leader and two others (§9), so a set with three or more seats out cannot advance any cell. It waits. No rule here resolves it, and safety is unaffected. | — | none |
| STOR-012-3/L308 | theorem | explicit | Three-seat finality reads intersect at least one survivor of an effective at-most-two-seat retirement so verifiers cannot use conflicting occupants. | Every finality read touches three seats: the leader and two others. A record names at most two seats, so every finality read touches at least one survivor. If a record is effective, every survivor holds it, so every verifier that can read a cell sees it. A verifier that sees it nowhere among the members it read is therefore right that it is not effective. A verifier that sees it but cannot confirm it waits rather than acting on the old occupant, so no two verifiers act on different occupants of one seat. This is full replication among the survivors, not quorum overlap. | — | none |

### STOR-012-4 — 12.4 Rebinding

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-012-4/L319 | obligation | explicit | Draw replacement operators from the active registry excluding operators already seated in the set. | 1. The replacement operator is drawn by the seat-assignment selection (§11.1) from the active registry, excluding operators already seated in the set. | — | none |
| STOR-012-4/L320 | safety-assumption | explicit | A rebind seed must be unpredictable before retirement effectiveness and bind role, record hash and sorted first-including survivor ByteCommit digests. | 2. The seed MUST NOT be computable by the party before the retirement is effective. Construction: `s_rebind = H(DSM/storage/rebind/v1; role ∥ H(record) ∥ D)`, where `D` is the sorted list of digests of the first ByteCommit (§14) of each surviving operator whose root includes the record. `D` depends on everything those operators hold, so the party cannot predict it or steer it by repeating opt-outs. | — | ambiguous |
| STOR-012-4/L321 | obligation | explicit | Open: whether opt-out should incur a cost is undecided; the stated current per-write model charges none. | 3. Under per-write credits, opting out carries no payment. The unpredictable seed (item 2) is the defence against steering a seat by repeated opt-outs. Whether opting out should carry a cost is Open (§24). | — | ambiguous |

### STOR-012-5 — 12.5 Handover

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-012-5/L328 | obligation | explicit | A live retiring operator transfers every immutable object and complete per-key arrival log in order. | 1. When a retiring operator is live, it MUST transfer the role's memory to the new operator: every key's full arrival log in order, and every immutable object. | — | none |
| STOR-012-5/L329 | evidence | explicit | A replacement's role commitments continue from the retiring operator's last covering ByteCommit. | 2. The new operator's commitments for the role MUST continue from the retiring operator's last ByteCommit that covers the role, so that peers holding the mirrored chain can detect any reordering during handover. | — | none |
| STOR-012-5/L330 | liveness-boundary | explicit | The old operator serves the role until handover completes. | 3. Until handover completes, the role is served by the retiring operator. | — | none |
| STOR-012-5/L331 | prohibition | explicit | Do not release retiring stake before every served role is handed over. | 4. A retiring operator's stake cannot be released until it has handed over every role it served (§15). | STOR-015/L397 | none |
| STOR-012-5/L335 | obligation | explicit | Durably replicate role memory before acknowledging a write. | An operator MUST durably replicate a role's memory before a write to that role is acknowledged. Permanent loss of a role then requires the loss of every replica, not one machine. | — | none |

### STOR-012-6 — 12.6 Loss

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-012-6/L342 | obligation | explicit | Loss without handover is explicitly marked in the retirement record. | 1. If a role's memory is lost with no handover, the retirement record carries a loss marker. | — | conflict(STOR-003/L83) |
| STOR-012-6/L343 | evidence | explicit | Each survivor's ordered loss-marker position distinguishes its pre-loss material. | 2. Each surviving operator records the loss marker at a point in its own ordered memory. For each survivor, material it held before that point is **pre-loss** material. | — | none |
| STOR-012-6/L344 | obligation | explicit | For a lost leader derive C from values naming the cell held pre-loss by at least two survivors. | 3. For a cell `K` whose leader role was lost, the verifier forms `C = {x : x names K and at least two survivors hold x as pre-loss material}` and resolves `K` as follows: | — | conflict(STOR-012-3/L298) |
| STOR-012-6/L348 | transition | explicit | An empty qualifying pre-loss set allows the new operator to lead future writes at that cell. | \| 0 \| No value was realized at `K` before the loss. The role's new operator leads `K` from here. \| | — | conflict(STOR-012-3/L298) |
| STOR-012-6/L349 | transition | explicit | A singleton qualifying pre-loss set supplies the cell winner. | \| 1 \| The single member of `C` is the winner at `K`. \| | — | none |
| STOR-012-6/L350 | transition | explicit | Two or more qualifying pre-loss values freeze the cell without a winner. | \| ≥ 2 \| `Frozen(K)`: no winner. The objects in `C` are evidence of equivocation by whoever signed them. \| | — | none |
| STOR-012-6/L352 | prohibition | explicit | Use no fresh replacement arrival order for a cell with qualifying pre-loss material. | 4. For a cell with any qualifying pre-loss material, the new operator's arrival log MUST NOT be used as the leader's order. Otherwise an equivocator could write a fresh "first" object into an empty replacement and rewrite a decided cell. | — | none |
| STOR-012-6/L356 | theorem | explicit | The survivor rule claims never to select a different pre-loss final value and to freeze only on signer equivocation. | If `Final(K, x)` held before the loss, then `x` was held by the leader and at least two other members. The other members are survivors and lose nothing (§3), so `x ∈ C`. At most one value is final at a cell, so if `\|C\| = 1`, its member is `x`. The rule can resolve to a final result or freeze the cell, but it never selects a different winner. Freezing requires two objects naming one cell, each held by two survivors, which requires the signer to have equivocated. | — | conflict(STOR-003/L83) |
| STOR-012-6/L358 | obligation | explicit | Open: the acceptance, SoFi, dBTC and tripwire consequences of Frozen(K) remain undecided. | **Open — consequences of `Frozen(K)`.** What a frozen cell means for DSM acceptance, SoFi resolution, and dBTC, and whether it triggers the DSM tripwire (§53) against the equivocating signer, is not decided here. | — | ambiguous |

### STOR-013 — 13 The operator registry

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-013/L367 | obligation | explicit | Represent the active registry as an immutable sorted operator-ID list. | 1. The active registry `Reg` is the sorted list of operator ids, stored as an immutable object. | — | none |
| STOR-013/L368 | transition | explicit | Registry succession is a pure function of prior registry and hash-referenced capacity, performance and applicant evidence. | 2. The registry advances by a pure function of the prior registry and input objects referenced by hash: capacity and performance evidence (Up/Down signals, §14), and applicant packs. | — | none |
| STOR-013/L369 | transition | explicit | Anyone may propose a recomputable registry successor at the prior-address cell and the first valid candidate at its leader finalizes by the ordinary rule. | 3. Each registry successor is a keyed cell on the network's pinned set, keyed by the prior registry's address. Any party MAY write a candidate successor. A verifier recomputes a candidate from the inputs it references; an object that does not recompute is not a candidate. The winner is the first candidate at the cell's leader, and it is final under the ordinary rule (§9). This settles which of several valid candidates (built from different discovered inputs) becomes the registry, without a vote. | — | none |
| STOR-013/L370 | prohibition | explicit | Registry pruning uses committed ByteCommit and signal evidence rather than local latency or uptime measurements. | 4. Pruning MUST be computed from committed evidence only (ByteCommit chains and signals that reference them). Measurements a node makes locally, such as latency or uptime, MUST NOT enter the rule, because different nodes observe different values. | — | none |
| STOR-013/L371 | dependency-boundary | explicit | Registry growth imports the cited salted applicant-ranking and genesis commit-reveal boundary without extracting the superseded specification. | 5. Growth selects new operators by the salted applicant ranking of the October 2025 spec §9, which is anchored in the genesis commit-reveal (§5 of that spec), so no party can bias selection. | — | ambiguous |
| STOR-013/L372 | obligation | explicit | New-operator pruning grace counts ByteCommit cycles rather than elapsed time. | 6. A new operator is protected from pruning for a grace period counted in ByteCommit cycles, never in time (October 2025 spec §10). | — | none |
| STOR-013/L373 | obligation | explicit | Admission and removal apply the performance bar including committed cadence regularity. | 7. **Owner decision:** an operator that does not meet the performance bar is never admitted, and one that falls below it is cut. Cadence regularity, meaning the size and spacing of an operator's ByteCommit cycles compared with its own history and its peers, is part of the performance score. | — | tension(STOR-006/L130) |
| STOR-013/L375 | obligation | explicit | Open: the remaining performance criterion expressible in committed evidence is undecided. | **Open — the performance criterion.** The October 2025 spec prunes by lowest utilisation. The owner's intent is to prune under-performers. Which performance measures are expressible over committed evidence is not decided here. | — | ambiguous |

### STOR-014 — 14 ByteCommit

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-014/L382 | obligation | explicit | Each unsigned ByteCommit includes node ID, counter cycle, stored SMT root, bytes used and previous digest. | 1. Each cycle, a node emits an unsigned ByteCommit containing: its node id, a cycle index (a counter, never time), the SMT root over what it holds, the bytes used, and the digest of its previous ByteCommit. | — | tension(STOR-006/L130) |
| STOR-014/L383 | obligation | explicit | Persist and mirror ByteCommits as ordinary objects at deterministic addresses. | 2. A ByteCommit is stored as an ordinary object under a deterministic address and mirrored by peers. | — | none |
| STOR-014/L384 | evidence | explicit | Verify ByteCommit roots and chain links rather than counting mirrors. | 3. A verifier checks the chain link and the root itself. A ByteCommit is **not** accepted by counting how many mirrors hold it; the October 2025 mirror-count rule is not adopted. | — | none |
| STOR-014/L385 | evidence | explicit | Capacity signals reference and are checked against windows of accepted ByteCommits. | 4. Up and Down capacity signals reference windows of accepted ByteCommits and are checked against them (October 2025 spec §8). | — | ambiguous |
| STOR-014/L389 | obligation | explicit | Commit each keyed entry's arrival index so handover and pre-loss partitions are verifiable. | Each keyed-cell entry is committed with its per-key arrival index, so that handover (§12.5) and pre-loss partitioning (§12.6) are checkable against mirrored commitments. | — | none |

### STOR-015 — 15 Stake and exit

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-015/L396 | obligation | explicit | Operator stake is encumbered in a stake DLV. | 1. An operator stakes through a stake DLV. | — | none |
| STOR-015/L397 | evidence | explicit | Stake unlock requires a mirrored DrainProof of two consecutive accepted zero-byte ByteCommits. | 2. The stake unlocks only when a DrainProof is mirrored: two consecutive accepted ByteCommits with bytes used equal to zero. | — | none |
| STOR-015/L401 | theorem | explicit | DrainProof is claimed to prove every role was handed over because payment cannot end retention. | Retention never depends on payment (§19), so an operator's memory empties only when every role it served has been handed over (§12.5). A DrainProof therefore proves completed handover, and an operator that refuses handover never recovers its stake. | — | none |

### STOR-016 — 16 The PaidK spend-gate

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-016/L412 | transition | explicit | A device is receive-only until paying three distinct operators and then remains spend-enabled permanently. | 1. A device is receive-only after genesis until it has paid a flat rate to K = 3 distinct storage operators. On first satisfaction, spending is enabled permanently, with no renewal. | — | none |
| STOR-016/L413 | obligation | explicit | Store payment receipts as ordinary device-signed objects. | 2. Payment receipts are device-signed objects stored like any other object. | — | none |
| STOR-016/L414 | authority | explicit | Nodes store receipts and count distinct operators to enforce the addressed-account spend-gate. | 3. A node enforces the gate itself: it stores the receipts, counts distinct operators, and MAY refuse writes addressed to a device that has not met the gate (§17, enforcement bounds). | — | tension(STOR-001/L61) |
| STOR-016/L415 | dependency-boundary | explicit | PaidK supplies the imported DJTE join event and receipt boundary without extracting emissions internals. | 4. `PaidK` is also the join event that drives DJTE, which verifiers evaluate over the same receipts. Emissions are out of scope for this round; this document imports the gate as substrate only. | — | none |

### STOR-017 — 17 Storage credits

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-017/L422 | obligation | explicit | A party's on-chain storage-credit balance is a committed state leaf. | 1. Storage is paid on-chain with credits. A party's credit balance is a leaf in its own committed state. | — | none |
| STOR-017/L423 | obligation | explicit | A fixed network token price charges actual storage used and operators cannot choose prices. | 2. The credit price is fixed in token units as a committed network parameter and is charged by the storage a write actually uses. Operators do not set prices; they compete on performance (§13). The real-world cost of storage follows the token's exchange value. | — | none |
| STOR-017/L424 | transition | explicit | Sender-authored advancing transitions consume storage credits within the transition and receivers verify the debit without paying to receive. | 3. A sender-authored, state-advancing transition consumes the credits for the storage it uses, inside that transition. The receiver checks the debit as part of acceptance, like any balance debit. Receiving never debits. | — | none |
| STOR-017/L425 | evidence | explicit | Operator payment receipts establish credit refill through the spend-gate path. | 4. Credits are refilled by paying operators. The payment receipts are the evidence for the refill, through the same path as the spend-gate (§16). | — | none |
| STOR-017/L426 | prohibition | explicit | Credits measure storage usage rather than time. | 5. Credits are counted in storage used, never in time, so no clock enters any protocol path. | — | none |
| STOR-017/L427 | liveness-boundary | explicit | Exhausted credits prevent acting but do not make a transition invalid and the client checks balance before acting. | 6. A party whose credits are exhausted cannot act. That is a liveness consequence only, never an invalidity. Before acting, the client checks its own credit balance. | — | none |
| STOR-017/L428 | invariant | explicit | Payment satisfaction and leader-plus-two write finality are separate. | 7. Paying and getting through are separate: a write goes through at a cell once that cell's leader and two other members hold it (§9). | — | none |
| STOR-017/L432 | obligation | explicit | Open: node refusal for exhausted credits versus receiver-only enforcement remains undecided. | 1. A node MAY refuse a write addressed to an account that has not met the spend-gate (§16). Whether nodes also refuse writes from an account whose credits are exhausted, or only receivers enforce credits, is Open (§24). | — | ambiguous |
| STOR-017/L433 | authority | explicit | Refusal is addressed-account-scoped and cannot discriminate by relayer identity. | 2. Any refusal is keyed on the account the write is addressed to, never on who is connected. A relayer carrying a party's bytes is admitted, and the node still never checks the writer (§8). | — | none |
| STOR-017/L434 | prohibition | explicit | Payment refusal never applies to created DLVs or depends on payload meaning or competing values. | 3. Refusal never applies to DLVs (§18), and never depends on a payload's content or on what else is held at a key. | — | none |
| STOR-017/L435 | liveness-boundary | explicit | A payment refusal is protocol unavailability rather than a validity judgment. | 4. To the protocol, a refusal is indistinguishable from unavailability: liveness only, never validity. | STOR-003/L90 | none |
| STOR-017/L436 | liveness-boundary | explicit | A refusing member only stalls cells it leads until opt-out or network cut replaces it. | 5. A node is one of five in a party's set, and the others carry a write it refuses. A refusal can only stall the cells that node leads, and only until the party opts it out (§10) or it is cut (§13). | — | none |

### STOR-018 — 18 DLV exemption

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-018/L443 | transition | explicit | DLV creation debits its creator's credits. | 1. Creating a DLV consumes the creator's credits like any write. | — | none |
| STOR-018/L444 | invariant | explicit | After creation, DLV objects, cells and writes are independent of every party's payment status. | 2. After creation, a DLV's objects and cells, and writes to them, never depend on anyone's credits or payment, the owner's included, because everyone depends on them. | STOR-018/L443 | none |
| STOR-018/L445 | prohibition | explicit | Payment lapse cannot remove or cancel a DLV. | 3. A lapse in payment never removes or cancels a DLV. | STOR-019/L453 | none |
| STOR-018/L446 | authority | explicit | Network processes govern succession of vault sets without owner dependence. | 4. A DLV's storage set is the network-pinned set (§10); its succession is driven by the network (§12.2), never by the owner. | — | none |

### STOR-019 — 19 Retention

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-019/L453 | prohibition | explicit | Payment lapse, owner inactivity or death cannot delete or expire stored bytes. | 1. A node MUST NOT delete, expire, or age out held bytes because of lapsed payment, owner inactivity, or owner death. | — | none |
| STOR-019/L454 | transition | explicit | Only handover may empty an operator's memory for a role. | 2. The only path by which an operator's memory for a role empties is handover (§12.5). | — | none |
| STOR-019/L455 | prohibition | explicit | Verification reads, receipt of value and provenance checks charge no reader credits. | 3. Reads for verification cost no credits. Receiving value, and verifying provenance, MUST NOT cost the reader anything. | — | none |
| STOR-019/L456 | obligation | explicit | Open: the logical-age pruning window and exemptions are undecided; this Open paragraph is not promoted into a settled pruning policy. | 4. **Pruning (Owner direction; Open).** Data past a certain age is to be pruned by a sliding window, with age measured in logical units (positions, generations or ByteCommit cycles), never time. Until the window and its exemptions are specified, nothing is pruned. Whatever rule is adopted MUST NOT make a slot that held a claim read as empty, and MUST NOT prune live DLV or dBTC backing material. | — | ambiguous |

### STOR-020 — 20 Owner independence

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-020/L463 | invariant | explicit | No safety property or other party's liveness depends on continued owner existence. | No safety property, and no party's liveness other than the owner's own, may depend on the owner continuing to exist. In particular: | — | none |
| STOR-020/L467 | authority | explicit | Retirement, loss resolution and eventual Frozen consequences are verifier rules rather than owner actions. | 3. Retirement effectiveness, the survivor rule, and any consequence of `Frozen(K)` are verifier rules, never owner actions. | — | none |

### STOR-021 — 21 Repair

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-021/L478 | obligation | explicit | Any client may repair immutable replicas by content hash after pruning or exit. | 1. After a prune or an exit, any client MAY restore missing replicas of immutable objects. Acceptance is by hash only, so a client's repair is equivalent to an operator's. | — | none |
| STOR-021/L479 | prohibition | explicit | Clients cannot reconstruct authoritative keyed arrival order; use handover or the specified loss rule. | 2. Keyed-cell arrival order is not repairable by clients. It moves only by handover (§12.5). If it is lost, the cell is resolved by §12.6. | — | none |

### STOR-022 — 22 Proof obligations

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-022/L490 | proof-obligation | explicit | Prove handover preserves every LeaderHeld and Final fact. | \| 22.1 \| History invariance: a handover changes no `LeaderHeld` or `Final` fact for any cell. \| | — | none |
| STOR-022/L491 | proof-obligation | explicit | Prove the survivor rule cannot select a winner other than a pre-loss final value and freezes only with qualifying conflicting values. | \| 22.2 \| Survivor-rule soundness: under §3, the rule of §12.6 never selects a value other than the pre-loss final value, and freezes only when two survivor-held objects name one cell. \| | — | conflict(STOR-012-3/L298) |
| STOR-022/L492 | proof-obligation | explicit | Prove retirement of at most two named seats yields convergent operator occupancy. | \| 22.3 \| Retirement convergence: with at most two seats named per record, no two verifiers act on different occupants of one seat. \| | — | none |
| STOR-022/L493 | proof-obligation | explicit | Prove registry determinism from the winning candidate and referenced inputs. | \| 22.4 \| Registry determinism: any two verifiers holding the same winning registry candidate and its referenced inputs compute the same registry. \| | — | none |
| STOR-022/L494 | proof-obligation | explicit | Prove rebind-seed unpredictability until retirement is effective. | \| 22.5 \| Rebind unpredictability: the party cannot compute `s_rebind` before its retirement is effective. \| | — | ambiguous |
| STOR-022/L495 | proof-obligation | explicit | Prove binding, registry and retirement events never change committed cell leadership. | \| 22.6 \| Leader immutability: no binding, registry, or retirement event changes `L(K)` for any committed cell. \| | — | none |

### STOR-023-1 — 23.1 With the pinned corpus

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-023-1/L507 | prohibition | explicit | The retired SoFi node-attribution gate supplies no current requirement. | \| 3 \| SoFi §40.4 (Part VIII, a historical implementation plan) keeps a gate requiring the root register to decode and verify signed single root claims and check attribution. SoFi §12 says a member never checks, decodes, or decides anything, and DSM §11 agrees. \| **Owner ruling (by §8's reasoning):** a node that checks the writer can block, so the root register must not verify caller signatures. SoFi §12 governs and the Part VIII gate is retired. Applied as SoFi Amendment S2. \| | STOR-008/L160 | none |
| STOR-023-1/L508 | obligation | explicit | Use storage Part III succession to refine frozen SoFi membership without changing member IDs. | \| 4 \| SoFi §6 says membership is frozen per vault and replacement is unspecified; SoFi §46 reserves `DSM/sofi/membership-handover/v1`. \| Part III of this document; the reserved tag becomes SoFi's encoding of §12.5. \| | — | none |
| STOR-023-1/L510 | obligation | explicit | Assigned network-pinned vault membership supersedes owner-selected membership. | \| 6 \| DSM §63 calls a vault's storage set owner-chosen, while SoFi §6 and §10 here make it the network-pinned set. \| **Owner ruling:** the set is assigned, never chosen. Applied as DSM Amendment A5. \| | STOR-010/L214 | none |

### STOR-024 — 24 Open items

| ID | Kind | Force | Requirement | Quote | Attaches | Flags |
|---|---|---|---|---|---|---|
| STOR-024/L531 | obligation | explicit | Open: the device register set's committed state location is unspecified. | \| 1 \| Where the device register's committed set lives in device state (§10). \| | — | ambiguous |
| STOR-024/L532 | obligation | explicit | Open: role endpoint resolution authority is unspecified. | \| 2 \| Endpoint resolution for roles: network configuration or a committed object (§11). \| | — | ambiguous |
| STOR-024/L533 | obligation | explicit | Open: Frozen(K) consequences and tripwire integration are unspecified. | \| 3 \| Consequences of `Frozen(K)`, and whether it triggers the tripwire (§12.6). \| | — | ambiguous |
| STOR-024/L534 | obligation | explicit | Open: the performance-pruning criterion beyond cadence regularity is unspecified. | \| 4 \| The performance criterion for pruning, expressible over committed evidence (§13). Cadence regularity (§9.1, §13.7) is one criterion; the rest are undecided. \| | — | ambiguous |
| STOR-024/L535 | obligation | explicit | Open: whether one network-pinned vault set persists through network growth is unspecified. | \| 5 \| Whether vaults keep a single network-pinned set as the network grows (§10). \| | — | ambiguous |
| STOR-024/L536 | obligation | explicit | Open: retirement, loss, handover and registry-successor wire forms and domains are unspecified. | \| 6 \| Wire formats and domain tags for retirement, loss, handover, and registry-successor objects. \| | — | ambiguous |
| STOR-024/L537 | obligation | explicit | Open: challenge deadline X, challenge/drop wire forms and SoFi drop resolution remain incomplete. | \| 7 \| The challenge deadline X, the wire form of challenges and drop claims, and SoFi's rule for a dropped pending result (§9.1). \| | — | ambiguous |
| STOR-024/L538 | obligation | explicit | Open: credit price, payment token and price-change process are unspecified. | \| 8 \| The credit price, its token, and how a price change is made (§17). \| | — | ambiguous |
| STOR-024/L539 | obligation | explicit | Open: payment allocation across the five storing operators is unspecified. | \| 9 \| How a credit payment is split among the five operators that store a write (§17). \| | — | ambiguous |
| STOR-024/L540 | obligation | explicit | Open: node enforcement of exhausted credits is unspecified. | \| 10 \| Whether nodes also refuse writes from accounts whose credits are exhausted, or only receivers enforce credits (§17). \| | — | ambiguous |
| STOR-024/L541 | obligation | explicit | Open: pruning window and exemptions are unspecified. | \| 11 \| The pruning window and its exemptions (§19). \| | — | ambiguous |
| STOR-024/L542 | obligation | explicit | Open: minimum registry size and replacement capacity are unspecified. | \| 12 \| The minimum network size: a set needs five distinct operators, and replacements need more to draw from (§12). \| | — | ambiguous |
| STOR-024/L543 | obligation | explicit | Open: whether member opt-out has an explicit charge is unspecified. | \| 13 \| Whether opting out of a member should carry a cost (§12.4). \| | — | ambiguous |

## Coverage ledger

Every DSM-HL, SOFI, DBTC-SPEC and STOR section anchor appears below in its source-file order, with line numbering restarted per file as required for source IDs. Definition, Requirement, Invariant, Property, Assumption and Proof Obligation labels in dBTC are read and attributed to their containing DBTC-SPEC section, as specified in §4. Exclusion marks extraction scope, not unread text.

### DSM_High_Level_Explainer.md

| Anchor | Line | Title | Status |
|---|---:|---|---|
| DSM-HL-001 | 59 | 1 The Central Question | extracted (1) |
| DSM-HL-001-1 | 88 | 1.1 Candidate Futures Versus Realized Futures | extracted (1) |
| DSM-HL-002 | 117 | 2 The Entire DSM Idea in One Diagram | restated-only: DSM-HL-049/L2213; DSM-HL-046/L2123; DSM-HL-037/L1884 |
| DSM-HL-003 | 154 | 3 Six Answers Before the Mathematics | extracted (1) |
| DSM-HL-004 | 181 | 4 The Two Halves of an Agreement | extracted (2) |
| DSM-HL-005 | 265 | 5 The Six Questions Every Transition Must Answer | extracted (13) |
| DSM-HL-006 | 305 | 6 DSM Does Not Need Global Ordering | extracted (2) |
| DSM-HL-007 | 346 | 7 Concrete Double-Spend Example | excluded: worked examples |
| DSM-HL-008 | 384 | 8 Both Candidates Can Look Valid | extracted (2) |
| DSM-HL-009 | 454 | 9 Same Balance, Two Counterparties | extracted (18) |
| DSM-HL-010 | 663 | 10 A Transition Cannot Cross Relationships | extracted (4) |
| DSM-HL-011 | 736 | 11 Storage Nodes | extracted (37) |
| DSM-HL-012 | 900 | 12 Online DSM | extracted (1) |
| DSM-HL-013 | 961 | 13 DSM Is Not a Payment Channel | extracted (2) |
| DSM-HL-014 | 1020 | 14 Determinism | extracted (2) |
| DSM-HL-014-1 | 1051 | 14.1 Determinism Is Broader Than Arithmetic | extracted (1) |
| DSM-HL-015 | 1097 | 15 Canonical Encoding | extracted (1) |
| DSM-HL-015-1 | 1121 | 15.1 Canonical Equality | extracted (1) |
| DSM-HL-015-2 | 1135 | 15.2 Why This Matters Everywhere | restated-only: DSM-HL-015/L1119; DSM-HL-015-1/L1130 |
| DSM-HL-016 | 1173 | 16 Domain Separation | extracted (1) |
| DSM-HL-017 | 1189 | 17 Cryptographic Hashes | extracted (1) |
| DSM-HL-018 | 1209 | 18 Forward-Only Hash Chaining | extracted (1) |
| DSM-HL-019 | 1232 | 19 Bilateral Relationships | extracted (2) |
| DSM-HL-020 | 1280 | 20 Relationship State as a Vector | excluded: worked examples |
| DSM-HL-021 | 1294 | 21 Relationship Projections | extracted (1) |
| DSM-HL-022 | 1339 | 22 Why Bilateral State Matters | extracted (1) |
| DSM-HL-023 | 1364 | 23 Why a Device Needs a Compact Commitment | extracted (1) |
| DSM-HL-024 | 1379 | 24 Ordinary Merkle Trees | excluded: worked examples |
| DSM-HL-025 | 1419 | 25 Sparse Merkle Trees | extracted (2) |
| DSM-HL-026 | 1463 | 26 Relationship Keys | extracted (2) |
| DSM-HL-027 | 1506 | 27 Updating One SMT Leaf | extracted (1) |
| DSM-HL-028 | 1540 | 28 Merkle Proofs | extracted (1) |
| DSM-HL-029 | 1603 | 29 The DSM State Object | extracted (8) |
| DSM-HL-030 | 1657 | 30 The Layered Root | extracted (3) |
| DSM-HL-031 | 1703 | 31 Canonical State Chaining | extracted (2) |
| DSM-HL-032 | 1736 | 32 Bitcoin Chain Versus DSM State Chain | excluded: Bitcoin Comparison |
| DSM-HL-033 | 1754 | 33 Logical Generations | extracted (2) |
| DSM-HL-034 | 1767 | 34 Precommitment | extracted (1) |
| DSM-HL-035 | 1781 | 35 Candidate Structure | extracted (3) |
| DSM-HL-036 | 1835 | 36 Candidate Forks Are Allowed | extracted (1) |
| DSM-HL-037 | 1857 | 37 Precommitment Chaining | extracted (1) |
| DSM-HL-038 | 1908 | 38 Guards | extracted (2) |
| DSM-HL-039 | 1945 | 39 Guard Families | extracted (1) |
| DSM-HL-040 | 1973 | 40 Guards Alone Are Not the Exclusion Mechanism | extracted (1) |
| DSM-HL-041 | 2002 | 41 Linear Resources | extracted (1) |
| DSM-HL-042 | 2026 | 42 Resource Descriptors | extracted (2) |
| DSM-HL-043 | 2036 | 43 Resource-Consumption Keys | extracted (2) |
| DSM-HL-044 | 2086 | 44 Why Branch-Specific Exclusion Keys Would Be Wrong | extracted (2) |
| DSM-HL-045 | 2104 | 45 Conflict Classes | extracted (1) |
| DSM-HL-046 | 2115 | 46 The Consumed Set | extracted (2) |
| DSM-HL-047 | 2148 | 47 The Consumed Set Can Also Be an SMT | extracted (1) |
| DSM-HL-048 | 2166 | 48 Bitcoin UTXOs Versus DSM Linear Resources | excluded: Bitcoin Comparison |
| DSM-HL-049 | 2206 | 49 The Complete Realization Predicate | extracted (1) |
| DSM-HL-050 | 2221 | 50 Potential and Realized Morphisms | extracted (1) |
| DSM-HL-051 | 2237 | 51 Realized Histories | extracted (2) |
| DSM-HL-052 | 2251 | 52 The Core Uniqueness Theorem | extracted (3) |
| DSM-HL-053 | 2327 | 53 Tripwire | extracted (1) |
| DSM-HL-054 | 2372 | 54 Safety and Liveness | extracted (1) |
| DSM-HL-055 | 2400 | 55 Concurrency Without Global Ordering | extracted (1) |
| DSM-HL-056 | 2435 | 56 Token Conservation | extracted (1) |
| DSM-HL-057 | 2483 | 57 Why Conservation Is Not Enough | extracted (1) |
| DSM-HL-058 | 2507 | 58 Deterministic Limbo Vaults | extracted (1) |
| DSM-HL-059 | 2554 | 59 Smart Commitments | extracted (6) |
| DSM-HL-060 | 2659 | 60 Multi-Party Workflows Through External Commitments | extracted (4) |
| DSM-HL-061 | 2734 | 61 CPTA and Deterministic Policy | extracted (8) |
| DSM-HL-062 | 2847 | 62 Deterministic Emissions (DJTE) | extracted (6) |
| DSM-HL-063 | 2969 | 63 Sovereign Finance (SoFi) | extracted (15) |
| DSM-HL-064 | 3110 | 64 dBTC: Bitcoin as a DSM Asset | extracted (20) |
| DSM-HL-065 | 3329 | 65 Recovery as a Linear Generation | extracted (1) |
| DSM-HL-066 | 3353 | 66 Offline Bearer DSM | extracted (1) |
| DSM-HL-067 | 3367 | 67 Offline Origin | excluded: dedicated offline/hardware subsystem; dependency DSM-HL-066/L3362 |
| DSM-HL-068 | 3406 | 68 The Committed Software Counter | excluded: dedicated offline/hardware subsystem; dependency DSM-HL-066/L3362 |
| DSM-HL-069 | 3418 | 69 Hardware Counter Versus Software Authority | excluded: dedicated offline/hardware subsystem; dependency DSM-HL-066/L3362 |
| DSM-HL-070 | 3442 | 70 The Observer Model, Inverted | excluded: dedicated offline/hardware subsystem; dependency DSM-HL-066/L3362 |
| DSM-HL-071 | 3489 | 71 Three-Factor Offline Identity | excluded: dedicated offline/hardware subsystem; dependency DSM-HL-066/L3362 |
| DSM-HL-072 | 3538 | 72 Two Offline Recipients | excluded: dedicated offline/hardware subsystem; dependency DSM-HL-066/L3362 |
| DSM-HL-073 | 3634 | 73 Conflict-Local Finality as a State Property | extracted (1) |
| DSM-HL-074 | 3662 | 74 Bitcoin Confirmation Versus DSM Finality | excluded: Bitcoin Comparison |
| DSM-HL-075 | 3682 | 75 End-to-End Worked Example | excluded: worked examples; A4 governs the obsolete register-first order |
| DSM-HL-076 | 3808 | 76 Why Every Piece Is Necessary | extracted (3) |
| DSM-HL-077 | 3860 | 77 Architecture Comparison | excluded: Bitcoin Comparison |
| DSM-HL-078 | 3884 | 78 Produced and Discarded, or Never Producible | extracted (1) |
| DSM-HL-079 | 3970 | 79 What Bitcoin Optimizes For | excluded: Bitcoin Comparison |
| DSM-HL-080 | 3984 | 80 Security Assumptions | extracted (10) |
| DSM-HL-081 | 4019 | 81 Formal Verification | extracted (6) |
| DSM-HL-082 | 4102 | 82 One Mathematical Picture of DSM | restated-only: DSM-HL-029/L1607; DSM-HL-030/L1666; DSM-HL-030/L1672; DSM-HL-043/L2040; DSM-HL-049/L2213 |
| DSM-HL-083 | 4165 | 83 Intuitive Analogy | excluded: worked examples (analogy) |
| DSM-HL-084 | 4197 | 84 Final Summary | restated-only: DSM-HL-015/L1119; DSM-HL-043/L2040; DSM-HL-046/L2134; DSM-HL-052/L2258; DSM-HL-006/L309 |
| DSM-HL-085 | 4249 | 85 The Core DSM Statement | restated-only: DSM-HL-049/L2213; DSM-HL-052/L2258; DSM-HL-011/L833; DSM-HL-006/L309 |

### SoFi_Settlement_Specification.md

| Anchor | Line | Title | Status |
|---|---:|---|---|
| SOFI-PREAMBLE | 34 | Read this first: if it exists, it is valid | extracted (9) |
| SOFI-001 | 273 | 1 How to read this document | no-normative-content: container heading |
| SOFI-001-1 | 275 | 1.1 Code references | excluded: code references and commit pins |
| SOFI-001-2 | 293 | 1.2 Normative words | no-normative-content: extraction force convention applied throughout |
| SOFI-001-3 | 298 | 1.3 Boxes | no-normative-content: label convention applied throughout |
| SOFI-001-4 | 309 | 1.4 Notation | extracted (4) |
| SOFI-001-5 | 330 | 1.5 Three valued predicates | extracted (5) |
| SOFI-002 | 353 | 2 The layer rule | extracted (1) |
| SOFI-002-1 | 360 | 2.1 Who owns what | extracted (3) |
| SOFI-002-2 | 384 | 2.2 The storage question | extracted (1) |
| SOFI-002-3 | 389 | 2.3 Distinct facts | extracted (4) |
| SOFI-003 | 415 | 3 How value moves | extracted (2) |
| SOFI-004 | 434 | 4 What SoFi settles | extracted (2) |
| SOFI-005 | 443 | 5 Fault model | no-normative-content: container heading |
| SOFI-005-1 | 445 | 5.1 Storage nodes | extracted (1) |
| SOFI-005-2 | 456 | 5.2 Traders and other callers | extracted (1) |
| SOFI-005-3 | 461 | 5.3 Safety and liveness | extracted (2) |
| SOFI-005-4 | 475 | 5.4 Boundaries that remain | extracted (2) |
| SOFI-005-5 | 484 | 5.5 Checked arithmetic | extracted (1) |
| SOFI-006 | 503 | 6 The committed set | extracted (2) |
| SOFI-007 | 531 | 7 The leader of a cell | extracted (2) |
| SOFI-007-1 | 542 | 7.1 The shuffle | extracted (5) |
| SOFI-007-2 | 555 | 7.2 The two SoFi seeds | extracted (2) |
| SOFI-008 | 578 | 8 Writing a cell | extracted (9) |
| SOFI-009 | 629 | 9 Who may write | extracted (2) |
| SOFI-010 | 639 | 10 Content addressed objects | extracted (2) |
| SOFI-011 | 651 | 11 Indexes | extracted (4) |
| SOFI-012 | 673 | 12 Everything a member does | extracted (2) |
| SOFI-013 | 687 | 13 How Core reads storage | extracted (5) |
| SOFI-014 | 714 | 14 Registries | no-normative-content: container heading |
| SOFI-014-1 | 716 | 14.1 Domain tags | extracted (3) |
| SOFI-014-2 | 775 | 14.2 Object classes | extracted (2) |
| SOFI-014-3 | 819 | 14.3 Signed objects | extracted (3) |
| SOFI-015 | 826 | 15 Derivations | extracted (19) |
| SOFI-016 | 884 | 16 Setup | extracted (7) |
| SOFI-017 | 924 | 17 The operation | extracted (2) |
| SOFI-017-1 | 943 | 17.1 Stage 1: the trader precommit P | extracted (7) |
| SOFI-017-2 | 996 | 17.2 Stage 2: policy fulfillment Gj | extracted (10) |
| SOFI-017-3 | 1046 | 17.3 Stage 3: the trader fulfillment F | extracted (2) |
| SOFI-017-4 | 1077 | 17.4 Fulfillment ingress | extracted (3) |
| SOFI-017-5 | 1097 | 17.5 The exercise | extracted (2) |
| SOFI-018 | 1126 | 18 Settlement preimage and E | no-normative-content: container heading |
| SOFI-018-1 | 1128 | 18.1 The preimage | extracted (5) |
| SOFI-018-2 | 1156 | 18.2 Inputs after E | extracted (1) |
| SOFI-018-3 | 1161 | 18.3 Choosing the form of E | extracted (2) |
| SOFI-018-4 | 1169 | 18.4 Bounds | extracted (7) |
| SOFI-019 | 1184 | 19 The DLV data model | no-normative-content: container heading |
| SOFI-019-1 | 1186 | 19.1 Leaves | extracted (6) |
| SOFI-019-2 | 1205 | 19.2 Cores and the batch fold | extracted (2) |
| SOFI-019-3 | 1215 | 19.3 Closed write sets | extracted (3) |
| SOFI-019-4 | 1228 | 19.4 Route digest and leg rules | extracted (3) |
| SOFI-019-5 | 1241 | 19.5 Static economics | extracted (6) |
| SOFI-019-6 | 1264 | 19.6 Advancing the lineage | extracted (3) |
| SOFI-019-7 | 1272 | 19.7 Close authority | extracted (2) |
| SOFI-019-8 | 1283 | 19.8 Vault genesis | extracted (4) |
| SOFI-020 | 1300 | 20 Validation predicates | restated-only: SOFI-001-5/L338.a; S3 supersedes three-valued wording |
| SOFI-020-1 | 1308 | 20.1 RouteValidation | extracted (3) |
| SOFI-020-2 | 1340 | 20.2 FulfillmentConformance | extracted (8) |
| SOFI-021 | 1367 | 21 Exercise and atomicity | extracted (5) |
| SOFI-021-1 | 1383 | 21.1 Registration and realizability are separate | extracted (4) |
| SOFI-022 | 1403 | 22 The predecessor rule | extracted (4) |
| SOFI-023 | 1429 | 23 Consumption and the walk | no-normative-content: container heading |
| SOFI-023-1 | 1431 | 23.1 Successor resolution | extracted (2) |
| SOFI-023-2 | 1440 | 23.2 Consumed route | extracted (2) |
| SOFI-023-3 | 1460 | 23.3 Trader parent compatibility | extracted (2) |
| SOFI-023-4 | 1470 | 23.4 Routes with more than one leg | extracted (2) |
| SOFI-023-5 | 1479 | 23.5 Impossibility and skips | extracted (8) |
| SOFI-023-6 | 1514 | 23.6 The walk | extracted (4) |
| SOFI-024 | 1527 | 24 Resolution of a trader position | extracted (12) |
| SOFI-025 | 1563 | 25 Crash and recovery | extracted (3) |
| SOFI-026 | 1585 | 26 The stack | extracted (1) |
| SOFI-027 | 1613 | 27 Routes | extracted (2) |
| SOFI-028 | 1631 | 28 Creating a vault | extracted (2) |
| SOFI-029 | 1646 | 29 Setting up with a vault | extracted (1) |
| SOFI-030 | 1655 | 30 Finding the head of a vault | extracted (2) |
| SOFI-031 | 1671 | 31 A trade and a multihop route | extracted (4) |
| SOFI-032 | 1704 | 32 Closing a vault | extracted (1) |
| SOFI-033 | 1710 | 33 Relaying | extracted (1) |
| SOFI-034 | 1715 | 34 Every Core SoFi function, placed | extracted (1) |
| SOFI-035 | 1761 | 35 Rules | extracted (6) |
| SOFI-036 | 1789 | 36 The unlock preimage, traced | restated-only: SOFI-035/L1775; SOFI-035/L1781; SOFI-037/L1891; evidence table maps these checks to code without separate authority |
| SOFI-037 | 1850 | 37 Gates | extracted (5) |
| SOFI-038 | 1911 | 38 What enters the transition | extracted (2) |
| SOFI-039 | 1929 | 39 Requirements | extracted (6) |
| SOFI-040 | 1979 | 40 Step 1: demolition | excluded: historical implementation plans |
| SOFI-040-1 | 1985 | 40.1 Why the node code goes, verified at 817123c | excluded: historical implementation plans and code references |
| SOFI-040-2 | 1995 | 40.2 Storage node | excluded: historical implementation plans and code references |
| SOFI-040-3 | 2038 | 40.3 Core wire material | excluded: historical implementation plans and code references |
| SOFI-040-4 | 2074 | 40.4 Gates | extracted (4) |
| SOFI-041 | 2144 | 41 Step 2: stop and inspect | excluded: historical implementation plans |
| SOFI-041-1 | 2169 | 41.1 Reachability at 817123c | excluded: code references and commit pins |
| SOFI-042 | 2199 | 42 Step 3: the formal floor | excluded: historical implementation plans |
| SOFI-042-1 | 2203 | 42.1 Delete first | restated-only: SOFI-021/L1375; SOFI-023-2/L1447; SOFI-017-5/L1111 |
| SOFI-042-2 | 2212 | 42.2 Then the invariants | extracted (1) |
| SOFI-042-3 | 2236 | 42.3 Two properties the floor must prove | extracted (3) |
| SOFI-042-4 | 2255 | 42.4 Files and counts | extracted (1) |
| SOFI-043 | 2271 | 43 Step 4: the Core seam | excluded: historical implementation plans |
| SOFI-043-1 | 2275 | 43.1 Starting point in the tree | restated-only: SOFI-038/L1925; SOFI-039/L1932; SOFI-039/L1933 |
| SOFI-044 | 2289 | 44 Step 5: rebuild | excluded: historical implementation plans; persistent rules extracted in Parts II–VII |
| SOFI-044-1 | 2340 | 44.1 Device scenarios for R14 | restated-only: SOFI-017-1/L969; SOFI-021/L1379; SOFI-037/L1903; SOFI-017-4/L1093; SOFI-008/L616; scenarios exercise these earlier rules |
| SOFI-045 | 2358 | 45 Step 6: cutover | excluded: historical implementation plans |
| SOFI-046 | 2375 | 46 Not in this work | extracted (3) |
| SOFI-047 | 2398 | 47 What a token policy is | extracted (5) |
| SOFI-048 | 2434 | 48 Two kinds of supply | extracted (5) |
| SOFI-049 | 2468 | 49 What each rule governs | extracted (3) |
| SOFI-050 | 2492 | 50 The mandatory baseline | extracted (2) |
| SOFI-051 | 2502 | 51 Native supply | extracted (3) |
| SOFI-052 | 2533 | 52 Externally backed supply | extracted (3) |
| SOFI-053 | 2557 | 53 Raising supply | extracted (4) |
| SOFI-054 | 2574 | 54 What changes in the tree | extracted (2) |

### dBTC_Native_Specification.md

| Anchor | Line | Title | Status |
|---|---:|---|---|
| DBTC-SPEC-01 | 20 | 1 Scope, Status, and Normative Language | no-normative-content: container heading |
| DBTC-SPEC-01-01 | 23 | 1.1 Scope | extracted (1) |
| DBTC-SPEC-01-02 | 46 | 1.2 Normative language | no-normative-content: force convention applied throughout |
| DBTC-SPEC-01-03 | 53 | 1.3 Specification status | extracted (1) |
| DBTC-SPEC-02 | 66 | 2 Architectural Principle | extracted (4) |
| DBTC-SPEC-03 | 111 | 3 Relationship to DSM and Sovereign Finance | no-normative-content: container heading |
| DBTC-SPEC-03-01 | 114 | 3.1 DSM substrate | extracted (5) |
| DBTC-SPEC-03-02 | 139 | 3.2 Sovereign Finance boundary | extracted (1) |
| DBTC-SPEC-03-03 | 162 | 3.3 DLV compatibility | extracted (1) |
| DBTC-SPEC-04 | 175 | 4 Conformance Classes | extracted (6) |
| DBTC-SPEC-05 | 250 | 5 Clocklessness and External Bitcoin Finality | extracted (3) |
| DBTC-SPEC-06 | 273 | 6 Canonical Encoding and Domain Separation | extracted (5) |
| DBTC-SPEC-06-01 | 308 | 6.1 Required domains | extracted (2) |
| DBTC-SPEC-07 | 341 | 7 The dBTC Asset | extracted (3) |
| DBTC-SPEC-08 | 381 | 8 Bitcoin-Backed Origin DLV | no-normative-content: container heading |
| DBTC-SPEC-08-01 | 384 | 8.1 Origin output | extracted (3) |
| DBTC-SPEC-09 | 443 | 9 Origin Admission and dBTC Issuance | extracted (8) |
| DBTC-SPEC-10 | 484 | 10 What Moves During an Ordinary dBTC Transfer | extracted (4) |
| DBTC-SPEC-11 | 551 | 11 Withdrawal Is a DSM Consumption First | restated-only: DBTC-SPEC-12/L630; DBTC-SPEC-13/L696; DBTC-SPEC-15-02/L846; DBTC-SPEC-17/L958 |
| DBTC-SPEC-11-01 | 572 | 11.1 Withdrawal intent | extracted (3) |
| DBTC-SPEC-12 | 625 | 12 The dBTC Burn | extracted (4) |
| DBTC-SPEC-13 | 687 | 13 DLV Completion Evidence | extracted (4) |
| DBTC-SPEC-14 | 759 | 14 Knowledge Is Not Possession | extracted (2) |
| DBTC-SPEC-15 | 812 | 15 Encrypted Bitcoin Execution Authority | no-normative-content: container heading |
| DBTC-SPEC-15-01 | 815 | 15.1 Purpose | extracted (4) |
| DBTC-SPEC-15-02 | 843 | 15.2 Fulfillment-gated opening | extracted (3) |
| DBTC-SPEC-16 | 892 | 16 Current Bitcoin Fulfillment Script Profile | extracted (3) |
| DBTC-SPEC-16-01 | 919 | 16.1 Refund branch | extracted (4) |
| DBTC-SPEC-17 | 932 | 17 Constructing the Bitcoin Withdrawal | extracted (3) |
| DBTC-SPEC-18 | 960 | 18 Full Withdrawal | extracted (2) |
| DBTC-SPEC-19 | 991 | 19 Partial Withdrawal and Successor Vault | extracted (4) |
| DBTC-SPEC-19-01 | 1048 | 19.1 Successor identity | extracted (1) |
| DBTC-SPEC-19-02 | 1068 | 19.2 Fresh successor authority | extracted (6) |
| DBTC-SPEC-19-03 | 1115 | 19.3 Successor activation | extracted (2) |
| DBTC-SPEC-20 | 1136 | 20 Why the Parent Cannot Remain the Authority | extracted (1) |
| DBTC-SPEC-21 | 1163 | 21 No Separate dBTC Double-Spend System | extracted (2) |
| DBTC-SPEC-22 | 1204 | 22 Online dBTC | extracted (3) |
| DBTC-SPEC-23 | 1231 | 23 Offline dBTC | extracted (2) |
| DBTC-SPEC-24 | 1260 | 24 Storage Nodes | extracted (3) |
| DBTC-SPEC-25 | 1299 | 25 Original Depositor Independence | extracted (1) |
| DBTC-SPEC-26 | 1326 | 26 Multi-Origin Balances | extracted (4) |
| DBTC-SPEC-27 | 1363 | 27 Fee Accounting | extracted (4) |
| DBTC-SPEC-28 | 1384 | 28 Conservation | extracted (3) |
| DBTC-SPEC-29 | 1421 | 29 Crash Safety and Replay | extracted (7) |
| DBTC-SPEC-30 | 1466 | 30 Concurrent Local Invocation | extracted (3) |
| DBTC-SPEC-31 | 1485 | 31 Security Properties | extracted (9) |
| DBTC-SPEC-32 | 1534 | 32 What a Device Compromise Means | extracted (2) |
| DBTC-SPEC-33 | 1559 | 33 What Is Deliberately Not Introduced | restated-only: DBTC-SPEC-04/L246; DBTC-SPEC-05/L257; DBTC-SPEC-10/L527; DBTC-SPEC-24/L1279; DBTC-SPEC-25/L1324; DSM substrate excludes a separate custody or double-spend authority |
| DBTC-SPEC-34 | 1588 | 34 What Is Deliberately Not Claimed | extracted (3) |
| DBTC-SPEC-35 | 1609 | 35 End-to-End Protocol | no-normative-content: container heading |
| DBTC-SPEC-35-01 | 1612 | 35.1 Deposit: BTC to dBTC | restated-only: DBTC-SPEC-08-01/L399; DBTC-SPEC-09/L448; DBTC-SPEC-09/L456; DBTC-SPEC-09/L468; DBTC-SPEC-09/L476 |
| DBTC-SPEC-35-02 | 1633 | 35.2 Transfer: dBTC to dBTC | restated-only: DBTC-SPEC-10/L499; DBTC-SPEC-10/L527; DBTC-SPEC-10/L547 |
| DBTC-SPEC-35-03 | 1650 | 35.3 Full withdrawal: dBTC to BTC | restated-only: DBTC-SPEC-11-01/L621; DBTC-SPEC-12/L650; DBTC-SPEC-13/L696; DBTC-SPEC-17/L958; DBTC-SPEC-18/L989 |
| DBTC-SPEC-35-04 | 1677 | 35.4 Partial withdrawal: dBTC to BTC plus successor vault | restated-only: DBTC-SPEC-19/L1030; DBTC-SPEC-19/L1046; DBTC-SPEC-19-02/L1071; DBTC-SPEC-19-03/L1120; DBTC-SPEC-20/L1159 |
| DBTC-SPEC-36 | 1718 | 36 Complete Causal Architecture | restated-only: DBTC-SPEC-09/L476; DBTC-SPEC-12/L630; DBTC-SPEC-13/L698; DBTC-SPEC-15-02/L872; DBTC-SPEC-19-03/L1120 |
| DBTC-SPEC-37 | 1748 | 37 Implementation Mapping | excluded: informative implementation mapping |
| DBTC-SPEC-37-01 | 1753 | 37.1 Existing DLV fulfillment machinery | excluded: informative implementation mapping |
| DBTC-SPEC-37-02 | 1778 | 37.2 Existing Bitcoin HTLC machinery | excluded: informative implementation mapping |
| DBTC-SPEC-37-03 | 1795 | 37.3 Existing DLV state model | excluded: informative implementation mapping |
| DBTC-SPEC-37-04 | 1804 | 37.4 Existing proof carrier | excluded: informative implementation mapping |
| DBTC-SPEC-37-05 | 1811 | 37.5 Existing successor machinery | excluded: informative implementation mapping |
| DBTC-SPEC-37-06 | 1818 | 37.6 Narrow implementation change | excluded: informative implementation mapping |
| DBTC-SPEC-38 | 1843 | 38 Required Conformance Tests | extracted (1) |
| DBTC-SPEC-38-01 | 1848 | 38.1 Origin admission | extracted (1) |
| DBTC-SPEC-38-02 | 1863 | 38.2 DSM ownership | extracted (1) |
| DBTC-SPEC-38-03 | 1878 | 38.3 DLV fulfillment | extracted (2) |
| DBTC-SPEC-38-04 | 1897 | 38.4 Full withdrawal | extracted (2) |
| DBTC-SPEC-38-05 | 1912 | 38.5 Partial withdrawal | extracted (4) |
| DBTC-SPEC-38-06 | 1937 | 38.6 Storage | extracted (2) |
| DBTC-SPEC-38-07 | 1950 | 38.7 Crash and recovery | extracted (3) |
| DBTC-SPEC-38-08 | 1967 | 38.8 Online/offline separation | extracted (3) |
| DBTC-SPEC-39 | 1980 | 39 Proof Obligations | extracted (9) |
| DBTC-SPEC-40 | 2028 | 40 Comparison of Authority Models | restated-only: DBTC-SPEC-02/L79; DBTC-SPEC-02/L83; DBTC-SPEC-12/L630; DBTC-SPEC-15-02/L872; DBTC-SPEC-19-02/L1091 |
| DBTC-SPEC-41 | 2045 | 41 Final Protocol Invariant | extracted (2) |
| DBTC-SPEC-42 | 2133 | 42 Conclusion | restated-only: DBTC-SPEC-12/L630; DBTC-SPEC-13/L696; DBTC-SPEC-17/L958; DBTC-SPEC-18/L989; DBTC-SPEC-19-02/L1091; DBTC-SPEC-24/L1279 |

### DSM_Storage_Node_Specification.md

| Anchor | Line | Title | Status |
|---|---:|---|---|
| STOR-PREAMBLE | 10 | Read this first | extracted (4) |
| STOR-001 | 55 | 1 What a storage node is | extracted (6) |
| STOR-002 | 70 | 2 What a node never does | extracted (1) |
| STOR-003 | 77 | 3 Fault model | extracted (7) |
| STOR-004 | 96 | 4 What storage facts are | extracted (2) |
| STOR-005 | 111 | 5 Immutable objects | extracted (6) |
| STOR-006 | 123 | 6 Keyed cells | extracted (4) |
| STOR-007 | 133 | 7 Indexes | extracted (1) |
| STOR-008 | 140 | 8 Mirror, spool, and identity storage | extracted (9) |
| STOR-009 | 162 | 9 Leader and finality | extracted (10) |
| STOR-009-1 | 185 | 9.1 Pending challenges counted in the leader's ByteCommits | extracted (8) |
| STOR-010 | 208 | 10 Storage sets | extracted (7) |
| STOR-011 | 225 | 11 Member ids are seats | extracted (4) |
| STOR-011-1 | 239 | 11.1 Two separate Fisher–Yates selections | extracted (5) |
| STOR-012 | 271 | 12 Binding and succession | no-normative-content: container heading |
| STOR-012-1 | 274 | 12.1 Initial binding | extracted (1) |
| STOR-012-2 | 281 | 12.2 Retirement triggers | extracted (3) |
| STOR-012-3 | 293 | 12.3 Retirement records | extracted (7) |
| STOR-012-4 | 314 | 12.4 Rebinding | extracted (3) |
| STOR-012-5 | 323 | 12.5 Handover | extracted (5) |
| STOR-012-6 | 337 | 12.6 Loss | extracted (9) |
| STOR-013 | 362 | 13 The operator registry | extracted (8) |
| STOR-014 | 377 | 14 ByteCommit | extracted (5) |
| STOR-015 | 391 | 15 Stake and exit | extracted (3) |
| STOR-016 | 407 | 16 The PaidK spend-gate | extracted (4) |
| STOR-017 | 417 | 17 Storage credits | extracted (12) |
| STOR-018 | 438 | 18 DLV exemption | extracted (4) |
| STOR-019 | 448 | 19 Retention | extracted (4) |
| STOR-020 | 458 | 20 Owner independence | extracted (2) |
| STOR-021 | 473 | 21 Repair | extracted (2) |
| STOR-022 | 485 | 22 Proof obligations | extracted (6) |
| STOR-023 | 497 | 23 Conflicts for the owner | no-normative-content: container heading |
| STOR-023-1 | 500 | 23.1 With the pinned corpus | extracted (3) |
| STOR-023-2 | 512 | 23.2 From the October 2025 specification, not adopted | excluded: historical mechanisms explicitly not adopted |
| STOR-024 | 526 | 24 Open items | extracted (13) |

## Findings

These are specification findings for owner reconciliation, not implementation findings or proposed specification fixes.

| # | Type | IDs | Finding |
|---:|---|---|---|
| 1 | tension | DSM-HL-005/L298; SOFI-024/L1560.a; SOFI-017-4/L1093; STOR-009-1/L193 | A1 says a nonexecuting transition leaves nothing in storage, whereas signed attempts, challenge/drop objects and permanent losing cell entries persist. S1 forbids stored result verdicts. Clarify that the prohibition concerns negative verdict records rather than all evidence of unsuccessful attempts; otherwise these requirements cannot all hold. |
| 2 | tension | DSM-HL-005/L297.c; SOFI-001-5/L342; SOFI-024/L1560.b; STOR-009-1/L202 | Challenge termination is Invalid in A1's protocol account but Void for a SoFi position under S1/S3. The distinction may be between predicate failure and resolution, but §24 formerly requires both predicates Valid before Void. The new rung and precedence remain Open, including interaction with Invalid and later supplied evidence. |
| 3 | conflict | STOR-003/L83; STOR-003/L94; STOR-012-6/L342; STOR-012-6/L356 | Role memory is assumed never permanently lost, including after migration, yet §12.6 specifies total role loss as an owner-decided path. Clarify whether this is an explicit exception to the overarching durable-memory assumption or behavior outside the supported safety model before implementing it. |
| 4 | conflict | STOR-012-3/L298; STOR-012-6/L344; STOR-012-6/L348; STOR-012-6/L356; STOR-022/L491 | The no-contradiction proof assumes both nonleader copies of a pre-loss final value survive. A permitted two-seat loss can remove the leader and one of its two copies, leaving only one surviving copy: the value is absent from C, which may be empty and reopen the cell. The stated two-loss model does not establish the claimed survivor soundness. |
| 5 | ambiguity | STOR-012-3/L299; STOR-012-3/L300; STOR-012-4/L320 | Overlapping effective retirement records can name the same seat with different record hashes and survivor ByteCommit lists, yielding different replacement seeds. No canonical record-selection rule or repeat-retirement binding generation is given; convergence of a retired seat does not by itself establish convergence of its replacement operator. |
| 6 | ambiguity | STOR-012-4/L320; STOR-022/L494 | Unpredictability until effectiveness is asserted from first-including ByteCommit digests, while effectiveness requires only record possession. The relationship between holding, cycle closure and observing all digests is not proved, particularly for operator collusion or influence over other writes; retain this as a proof obligation rather than proven anti-grinding. |
| 7 | tension | STOR-006/L130; STOR-009-1/L193; STOR-009-1/L195; STOR-013/L373; STOR-014/L382 | Nodes retain raw arrivals but early drop claims count as nothing until eligible; specify whether eligibility is fixed at arrival or can mature later, and how the earliest eligible answer/drop is recognized without node semantics. The document also assumes an unreachable leader's chain stops, although unreachability to a verifier need not stop writes from other clients. |
| 8 | ambiguity | STOR-019/L456; STOR-024/L541 | The pruning paragraph is explicitly Open even though it contains MUST NOT sentences and an interim no-pruning direction. It is retained as Open without inventing a settled pruning policy; clarify which interim constraints, if any, should be separated as independently settled rules. |
| 9 | tension | STOR-001/L61; STOR-016/L414; STOR-017/L432; DSM-HL-011/L758.a | Payment receipt counting is an express owner-authorized exception to otherwise content-blind storage. Receipt authenticity, addressed-account binding and credit-exhaustion enforcement are not fully specified; do not expand the exception into generic writer or economic validation. |
| 10 | ambiguity | STOR-013/L371; STOR-014/L385; STOR-024/L536 | Registry growth and capacity-signal algorithms import details from the superseded October specification, which is outside the pinned corpus and forbidden to read for this task. The boundary is recorded but exact applicant ranking, genesis salt and signal computations cannot be fully derived from these four files. |
| 11 | tension | SOFI-PREAMBLE/L48; SOFI-008/L599; SOFI-014-3/L823; DSM-HL-081/L4060 | SoFi asserts one valid signed envelope per body from deterministic signing, while DSM §81 expressly does not claim recognized signatures are byte-for-byte constructor outputs because verifier-side randomizer recomputation is unavailable. Deterministic honest signing alone is not proof of unique accepted envelopes; resolve whether finality compares bodies, envelopes or a constrained signature language. |
| 12 | ambiguity | SOFI-017-5/L1111; SOFI-023-5/L1483; SOFI-023-5/L1504; SOFI-020-2/L1358 | Recognition must distinguish meaningless bytes from an authentic but semantically invalid or incompletely evidenced exercise. §17.5 says exercises prove themselves and can always be classified, while later rules admit registered invalid artifacts and pending evidence. Define the minimum recognition predicate without dropping the invalid-exercise skip cases or letting junk occupy a cell. |
| 13 | tension | SOFI-017-4/L1081; SOFI-042-2/L2217; STOR-006/L128 | The fulfillment/root pair must be atomically installed, but generic append-only keyed puts are also available to arbitrary callers. Clarify whether PositionPairAtomic describes conforming multi-key installation operations or all reachable raw storage states; arbitrary single-key puts can otherwise create a half-pair. |
| 14 | tension | SOFI-017-1/L982; SOFI-006/L506; STOR-010/L218 | SoFi uses one committed set S in P and its registration facts, while storage distinguishes trader-owned cells from network-pinned vault cells. The exact set used for trader position finality, setups and shared closure objects needs reconciliation rather than silently treating every cell as belonging to the vault's set. |
| 15 | ambiguity | DBTC-SPEC-13/L698; DBTC-SPEC-13/L731; DBTC-SPEC-15-01/L828; DBTC-SPEC-15-02/L846 | The origin fixes a fulfillment hash before a future holder chooses intent-bound burn evidence, yet the unlock hash includes that future evidence. The corpus does not supply a constructive way to satisfy the precommitted hash for arbitrary valid later withdrawals or a concrete sealed-capsule construction implementing that relation. |
| 16 | ambiguity | DBTC-SPEC-17/L952; DBTC-SPEC-19-02/L1099 | Successor-key derivation binds the exact transaction commitment, while that transaction contains the successor key or key-derived script. A staged commitment or acyclic derivation is needed but is not specified; do not fill this dependency cycle with an invented mechanism. |
| 17 | ambiguity | DBTC-SPEC-15-02/L870; DBTC-SPEC-15-02/L872; DSM-HL-064/L3232 | Intent-constrained execution is a requirement, but an abstract opening API alone does not establish enforcement against modified caller software holding opened material. The threat boundary and construction that prevent a valid partial burn from exposing unrestricted Bitcoin authority remain to be specified and proved. |
| 18 | tension | SOFI-052/L2540; DBTC-SPEC-12/L630; DBTC-SPEC-28/L1393; DBTC-SPEC-29/L1462 | SoFi says burn and matching external release occur in the same transition and neither occurs alone, whereas dBTC explicitly burns before Bitcoin signing/confirmation and retains outstanding execution claims. Clarify that atomicity binds the authorized release claim rather than simultaneous cross-system settlement. |
| 19 | ambiguity | DBTC-SPEC-19/L1032; DBTC-SPEC-27/L1374; DBTC-SPEC-28/L1411 | The successor floor includes anchor treatment, while the simple burn and backing equations mostly use payout plus fee. State explicitly whether retained anchors remain eligible backing and which origin allocation funds them so no unaccounted collateral reduction occurs. |
| 20 | ambiguity | DBTC-SPEC-26/L1347; DBTC-SPEC-30/L1479; DSM-HL-064/L3288 | A holder may burn only part of one shared origin while other holders redeem that origin concurrently. Local generation serialization is explicit, but the exact cross-device backing-generation claim/consumption and loser recovery binding is not described at the same precision; ordinary source-state linearity alone does not specify it. |
| 21 | scope | DSM-HL-062/L2855; DSM-HL-065/L3334; DSM-HL-066/L3362; DBTC-SPEC-23/L1238; STOR-016/L415 | Emissions, recovery and dedicated offline/hardware internals were read where present but excluded beyond the imported boundaries; no files outside the four-spec corpus supplied protocol requirements. |
| 22 | scope | SOFI-001-5/L338.a; SOFI-024/L1560.a; SOFI-040-4/L2128.a; DSM-HL-009/L558; DSM-HL-063/L3107 | Owner amendments A1–A5 and S1–S3 govern superseded predicate, read-order, writer-gate and storage-set language. Historical sequencing, comparisons, worked examples and informative dBTC §37 are not promoted into requirements. |
| 23 | ambiguity | SOFI-019-8/L1294; SOFI-040-4/L2128.a; STOR-008/L160 | Genesis says locator writes are attributed to the owner while S2 and storage forbid writer attribution at the node. This extraction treats attribution as authenticated Core evidence; confirm that raw locator appends remain unauthenticated. |
| 24 | scope | DSM-HL-017/L1202; DSM-HL-080/L3986.a; DBTC-SPEC-01-03/L58 | This is a specification extraction, not a code-conformance audit or a claim that the security assumptions are proved. Cross-document tensions are left for owner reconciliation before implementation changes. |
