# Bilateral finality barrier — one unresolved semantic predecessor per originator

Status: implemented on `feat/bilateral-finality-barrier` (2026-08-16).
Companion to ADR 0003 (§"Finality barrier" addendum). Rust paths relative to
`dsm_client/deterministic_state_machine/dsm_sdk/src/`.

## Rule

On an ordinary bilateral relationship, a side may not originate while its own
finality barrier is unresolved:

- **as sender** — until the `RelationshipFinalizedV1` for its previous send has
  reached storage quorum (the pending online gate stays armed until then);
- **as recipient** — until it has verified the sender's `RelationshipFinalizedV1`
  for the transfer it applied (`acceptance_fold_journal.peer_finalized = 1`);
- **as either** — while an inbound transfer from the peer is staged but not yet
  applied (crossing mitigation).

A next-generation transfer may be transported before the peer processes the
predecessor's certificate, but it may not be canonically applied: the recipient
holds it at `ready_to_verify` (route retained, re-served each poll) until the
certificate lands. Relationship-local, never wallet-global. DLV untouched.

## State machine

```text
SENDER (per relationship, one send in flight)
  wallet.send ── authority Ready ──▶ [advance + proposal + gate + pending EK + frozen artifacts]  (one tx)
        │                                                    │
        │  storage.sync ◀── delta (sig_b over commitment ‖ b_pair) ── recipient
        ▼
  finalize_on_acceptance_atomically (one tx):
        tip sync · promote pending EK · CAS Counterparty EK · CAS counterparty_canonical_heads(b_parent→b_child)
        · proposal finalized · freeze RelationshipFinalizedV1 (own route) · outbox → finalization_checkpoint_pending
        │
        │  checkpoint sweep: replay frozen certificate under its id/route until quorum K
        ▼
  release_gate_on_finalization_checkpoint_atomically (one tx): gate deleted (exact match) · outbox → gc_pending
        │
        ▼  authority Ready again

RECIPIENT (per relationship)
  poll: certificates drained FIRST → complete_ready_split_transfers
        │
        ├─ relationship_awaits_peer_finalization ? ── HOLD (ready_to_verify, no ack/apply/reject)
        │
        ▼
  apply_incoming_transfer_staged (one tx):
        pin (counterparty_canonical_heads) · advance · nonce · CanonicalApplyRecord(+B pair)
        · CAS counterparty_canonical_heads(a_parent→a_child) · journal(+B pair, peer_finalized=0)
        │
        ▼ converge · reply delta (b_pair authenticated by sig_b, quorum K)
        │
        │  certificate arrives → verify vs journal (fields + signature_a under journal.new_counterparty_a_head)
        ▼
  peer_finalized = 1  →  authority Ready toward the peer
```

## Where things live

| Concern | Code |
|---|---|
| Authenticated B pair | `sdk/receipts.rs::compute_receipt_b_canonical_target`, `*_target` sign/verify; `handlers/recipient_receipt.rs::generate_b_artifacts_from_inbound`; `handlers/online_finalize.rs::verify_acceptance_receipt` |
| Staged recipient apply, in-tx journal | `sdk/core_sdk.rs::apply_incoming_transfer_staged`; `storage/client_db/recipient_receipt_fold.rs::insert_prepared_acceptance_journal_with_conn` |
| Peer head authority | `storage/client_db/counterparty_canonical_heads.rs`; `canonical_apply.rs::pinned_counterparty_a_head` |
| Certificate | proto `RelationshipFinalizedV1`; `dsm/src/types/receipt_types.rs` codec + target; `handlers/relationship_finalized.rs` (recipient); `handlers/storage_routes.rs::build_relationship_finalized_artifact` / `deliver_pending_finalization_checkpoints` (sender) |
| Sender release | `storage/client_db/sender_outbox.rs::finalize_on_acceptance_atomically` / `release_gate_on_finalization_checkpoint_atomically` |
| Authority | `handlers/relationship_status.rs::finality_barrier_block` — consulted by `derive_local_send_status_*`, `wallet.send`, BLE `prepare_bilateral_transaction`; in-tx guard in `commit_send_prerequisites_with_conn` |
| Reordering hold | `handlers/storage_routes.rs::complete_ready_split_transfers` |
| Tests | `handlers/bilateral_finality_tests.rs` (R1–R4, R7–R9, R11, R12 over the two-device harness `test_support::two_device` + `test_support::fake_node`), R5 in `storage_routes` tests, R6 in `core_sdk` tests |

Schema: `CLIENT_DB_SCHEMA_VERSION` 2 → 3 (beta: reset, no migration).

## Known limitations (pinned, not solved here)

- Crossing sends after mutual finality: both sides' finalize hits
  `CanonicalMovedToDifferentTip` on the projection tip the inbound converge
  advanced; both proposals park. Mitigation: a staged inbound blocks
  originating (`counterparty_has_unconverged_inbound`). A deterministic turn
  rule is a protocol decision beyond this branch. R12 pins the state.
- Mixed BLE + online on one relationship: BLE settlement does not CAS
  `counterparty_canonical_heads`; the next online step conflicts. Follow-up.
- Lost delta / lost certificate: on-demand repost from `bilateral.reconcile`.
  Follow-up (delivery is now quorum K on both).
