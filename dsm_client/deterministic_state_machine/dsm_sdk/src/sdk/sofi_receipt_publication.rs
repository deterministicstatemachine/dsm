// SPDX-License-Identifier: Apache-2.0

//! The Def 14.2 receipt's publication obligation (amendment 2c-F, R5 and R6).
//!
//! AN OBLIGATION, NEVER A GATE. Once the walk certifies a market settlement,
//! its completion freezes the receipt closure for the vault's authenticated
//! committed storage set `S_v`, re-derived from the composed `V_n`:
//!
//! ```text
//! SofiReceipt   the projection of (B, TA_B)          DSM/sofi-receipt/v1
//! CCB(B)        the bound bundle, byte for byte       DSM/settlement-bundle
//! CCB(TA_B)     the acceptance §7 certified           DSM/trader-settlement-acceptance/v2
//! ```
//!
//! The ONE generic sweep then replays those exact bytes until a quorum of `S_v`
//! holds each. Nothing waits for that. The fence releases on C2's condition
//! alone, and a closure below quorum is a pending obligation — never a reason
//! to re-fence, re-bind, re-admit or re-certify (the ruling on R6).
//!
//! NEVER LOST (the owner's merge condition on #859). A projection or freeze
//! that fails in the completion pass does not hold the fence. If the fence then
//! releases and the process dies, the obligation is rediscovered from durable
//! facts alone, by [`recover_owed_receipts`]:
//!
//! ```text
//! a released trader fence    Released is reachable only through
//!                            SuccessorAccepted, recorded only by the
//!                            certified completion: the durable record that
//!                            certification happened. Carries addr(B) and S_v.
//! CCB(B)                     at quorum since pre-bind; fetched by b, re-hashed,
//!                            and required to sit at the fence's addr(B)
//! this device's TA_B         frozen locally by its own admission, reached
//!                            through its own locator for b, and required to
//!                            accept exactly b
//! ```
//!
//! Recovery rebuilds the byte-identical closure and freezes it. It never
//! composes, walks, binds, advances, admits or touches the fence: it rebuilds
//! the record of what certification already decided, and re-decides nothing.
//!
//! NOTHING READS THIS AS AUTHORITY (R7). [`publication`] reports whether the
//! obligation is met, and nothing more. No composition, admission,
//! realization, fence, certification or reserve-provenance path may consult it.
//!
//! ONE SET PER ROW. A frozen row binds one storage set per `(key, digest)`. If
//! `TA_B` was already frozen by its admission for a DIFFERENT set, freezing it
//! again for `S_v` is a no-op, and [`publication`] reports
//! [`ClosurePublication::BoundToAnotherSet`] rather than counting the other
//! set's quorum as `S_v`'s. Every beta consumer resolves the one catalog set,
//! so beta never reaches that arm.

use anyhow::{anyhow, Result};
use dsm::common::domain_tags::{
    TAG_DSM_SETTLEMENT_BUNDLE, TAG_DSM_SOFI_RECEIPT_V1, TAG_DSM_TRADER_SETTLEMENT_ACCEPTANCE,
};
use dsm::dlv::sofi_receipt::SofiReceipt;
use dsm::dlv::trader_fence::FenceState;
use dsm::economic::trader_acceptance::TraderAcceptance;

use crate::sdk::economic_registers::{immutable_object_key, immutable_object_key_for_inner};
use crate::sdk::trader_acceptance_locator::{decode_locator, locator_key, LocatorFetch};
use crate::storage::client_db::frozen_publication_artifact as fpa;
use crate::storage::client_db::trader_parent_fence::{list_released_fences, TraderFence};

/// The frozen-artifact purpose of the receipt row itself.
pub(crate) const RECEIPT_PURPOSE: &str = "sofi-receipt";
const BUNDLE_PURPOSE: &str = "sofi-receipt-bundle";
const ACCEPTANCE_PURPOSE: &str = "sofi-receipt-acceptance";

/// Test-only: make the next closure freeze fail, the way a local storage fault
/// would. Consumed by the freeze it fails.
#[cfg(test)]
pub(crate) static FAIL_NEXT_CLOSURE_FREEZE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// One member of the publication set: the exact bytes and the immutable key
/// they travel under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClosureObject {
    pub key: String,
    pub bytes: Vec<u8>,
    pub purpose: &'static str,
}

/// `P(ρ_B)` for one settlement, bound to the set its quorum is counted on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReceiptClosure {
    pub receipt: SofiReceipt,
    pub storage_set_id: [u8; 32],
    /// The receipt, the bundle and the acceptance, in that order.
    pub objects: [ClosureObject; 3],
}

/// The closure of the settlement whose canonical bundle is `bundle_canon` and
/// whose certified acceptance is `acceptance`, for storage set
/// `storage_set_id`.
///
/// A pure projection: the same inputs produce the same keys and bytes on
/// every call, which is what makes re-freezing and re-publishing idempotent.
pub(crate) fn closure(
    bundle_canon: &[u8],
    acceptance: &TraderAcceptance,
    storage_set_id: [u8; 32],
) -> std::result::Result<ReceiptClosure, String> {
    let decoded = dsm::dlv::settlement_bundle::decode_canonical(bundle_canon)
        .map_err(|e| format!("the bundle is not canonical: {e}"))?;
    let acceptance_bytes = acceptance
        .encode()
        .map_err(|e| format!("the acceptance does not encode: {e}"))?;
    let a_b = acceptance
        .ta_b()
        .map_err(|e| format!("the acceptance has no identity: {e}"))?;
    let receipt = SofiReceipt::project(&decoded.bundle, a_b).map_err(|e| e.to_string())?;
    let object = |namespace, bytes: Vec<u8>, purpose| ClosureObject {
        key: immutable_object_key(namespace, &bytes),
        bytes,
        purpose,
    };
    Ok(ReceiptClosure {
        objects: [
            object(TAG_DSM_SOFI_RECEIPT_V1, receipt.encode(), RECEIPT_PURPOSE),
            object(
                TAG_DSM_SETTLEMENT_BUNDLE,
                bundle_canon.to_vec(),
                BUNDLE_PURPOSE,
            ),
            object(
                TAG_DSM_TRADER_SETTLEMENT_ACCEPTANCE,
                acceptance_bytes,
                ACCEPTANCE_PURPOSE,
            ),
        ],
        receipt,
        storage_set_id,
    })
}

/// Freeze every member of `closure` for its set — all three rows, or none.
///
/// All-or-none is what makes the receipt row a sound marker: recovery treats
/// "a receipt row is frozen for `b`" as "the obligation is recorded", so a
/// receipt row must never exist without its bundle and acceptance rows.
/// Re-freezing identical bytes is a no-op, so this is safe on every pass.
pub(crate) fn freeze_closure_with_conn(
    conn: &rusqlite::Connection,
    closure: &ReceiptClosure,
) -> Result<()> {
    #[cfg(test)]
    {
        if FAIL_NEXT_CLOSURE_FREEZE.swap(false, std::sync::atomic::Ordering::SeqCst) {
            return Err(anyhow!("injected closure freeze failure"));
        }
    }
    let b = closure.receipt.bundle();
    conn.execute_batch("SAVEPOINT sofi_receipt_closure")?;
    let frozen = closure.objects.iter().try_for_each(|o| {
        fpa::freeze_artifact_with_conn(
            conn,
            &closure.storage_set_id,
            &o.key,
            &o.bytes,
            &b,
            o.purpose,
        )
        .map(|_| ())
    });
    match frozen {
        Ok(()) => {
            conn.execute_batch("RELEASE sofi_receipt_closure")?;
            Ok(())
        }
        Err(e) => {
            conn.execute_batch("ROLLBACK TO sofi_receipt_closure; RELEASE sofi_receipt_closure")
                .map_err(|r| anyhow!("{e}; and rolling the partial closure back failed: {r}"))?;
            Err(e)
        }
    }
}

/// Where the obligation stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClosurePublication {
    /// Every member is frozen for `S_v` and a quorum of `S_v` holds it.
    Published,
    /// Some member is not frozen yet, or not yet at quorum. The sweep owes it.
    Pending(String),
    /// A member's only frozen row is bound to another storage set, whose
    /// quorum is not `S_v`'s.
    BoundToAnotherSet { purpose: &'static str },
}

/// Whether `closure` is published over its own set (Req 14.6, as 2c-F states
/// it). A report, never an input to any validity or release decision.
pub(crate) fn publication(closure: &ReceiptClosure) -> Result<ClosurePublication> {
    for o in &closure.objects {
        let digest = fpa::content_digest(&o.key, &o.bytes);
        match fpa::get_artifact(&o.key, &digest)? {
            None => {
                return Ok(ClosurePublication::Pending(format!(
                    "{} is not frozen",
                    o.purpose
                )))
            }
            Some(row) if row.storage_set_id != closure.storage_set_id => {
                return Ok(ClosurePublication::BoundToAnotherSet { purpose: o.purpose })
            }
            Some(row) if row.state != fpa::ArtifactState::Published => {
                return Ok(ClosurePublication::Pending(format!(
                    "{} is {}",
                    o.purpose,
                    row.state.as_str()
                )))
            }
            Some(_) => {}
        }
    }
    Ok(ClosurePublication::Published)
}

/// What recovering one released settlement's receipt established. Nothing
/// here moves anything but frozen rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReceiptRecovery {
    /// The receipt row for this bundle is already frozen: the sweep owns it.
    AlreadyRecorded,
    /// The exact closure was rebuilt from durable facts and frozen now.
    Frozen,
    /// A durable fact is not reachable now (the bundle, or a local read).
    /// Retried on the next pass.
    Pending(String),
    /// The durable facts do not reconstruct THIS settlement's closure — a
    /// substituted bundle, set or acceptance. Nothing is frozen.
    Refused(String),
}

/// **Rediscover and rebuild one released settlement's receipt obligation.**
///
/// `fence` is a `Released` row on this device's own market chain. Every input
/// is a durable fact that existed before the release, and each is checked
/// against the others before anything is frozen:
///
/// ```text
/// B      fetched by b = fence.tx_id, re-hashed, at the fence's addr(B)
/// S_v    the fence's set, and the set B's successor commits
/// TA_B   this device's own locator for b, its own frozen bytes at the
///        locator's ta_B, re-hashed, accepting exactly b
/// ```
pub(crate) async fn recover_owed_receipt(fence: &TraderFence) -> ReceiptRecovery {
    use ReceiptRecovery::{AlreadyRecorded, Frozen, Pending, Refused};

    if fence.state != FenceState::Released {
        return Refused("the fence is not released; its completion owns it".into());
    }
    let b = fence.tx_id;
    match fpa::find_artifact_by_purpose_and_bound_root(RECEIPT_PURPOSE, &b) {
        Ok(Some(_)) => return AlreadyRecorded,
        Ok(None) => {}
        Err(e) => return Pending(format!("the frozen rows could not be read: {e}")),
    }

    // B — by its identity, at the address the fence bound.
    let bundle = match crate::sdk::storage_io::fetch_immutable_payload(
        TAG_DSM_SETTLEMENT_BUNDLE,
        &b,
    )
    .await
    {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Pending("the bound bundle is not retrievable yet".into()),
        Err(e) => return Pending(format!("the bound bundle could not be read: {e}")),
    };
    if dsm::dlv::settlement_bundle::bundle_digest(&bundle) != b
        || dsm::dlv::settlement_bundle::bundle_addr(&bundle) != fence.value_addr
    {
        return Refused("the bundle is not the one this fence bound".into());
    }
    let decoded = match dsm::dlv::settlement_bundle::decode_canonical(&bundle) {
        Ok(decoded) => decoded,
        Err(e) => return Refused(format!("the bound bundle does not decode: {e}")),
    };

    // S_v — the set the fence was bound under, and the set the bundle's own
    // successor commits (equal to the parent's by bundle validity).
    let [transition] = decoded.bundle.transitions() else {
        return Refused("the bound bundle is not a beta bundle".into());
    };
    match dsm::ccb::storage_set_id(&transition.successor.storage_set) {
        Ok(id) if id == fence.storage_set_id => {}
        _ => return Refused("the fence's storage set is not the one the bundle commits".into()),
    }

    // TA_B — this device's own admission artifacts for exactly b.
    let ta_b = match fpa::get_current_artifact_payload(&locator_key(&b)) {
        Ok(Some(bytes)) => match decode_locator(&bytes) {
            LocatorFetch::Found { ta_b, .. } => ta_b,
            _ => return Refused("this device's locator for the bundle is malformed".into()),
        },
        Ok(None) => {
            return Refused("this device holds no acceptance locator for the bundle".into())
        }
        Err(e) => return Pending(format!("the locator row could not be read: {e}")),
    };
    let ta_bytes = match fpa::get_current_artifact_payload(&immutable_object_key_for_inner(
        TAG_DSM_TRADER_SETTLEMENT_ACCEPTANCE,
        &ta_b,
    )) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Refused("this device holds no acceptance bytes at its locator".into()),
        Err(e) => return Pending(format!("the acceptance row could not be read: {e}")),
    };
    if dsm::storage_object::immutable_inner(TAG_DSM_TRADER_SETTLEMENT_ACCEPTANCE, &ta_bytes) != ta_b
    {
        return Refused("the held acceptance bytes are not the ones the locator names".into());
    }
    let acceptance = match dsm::economic::trader_acceptance::decode_trader_acceptance(&ta_bytes) {
        Ok(acceptance) => acceptance,
        Err(e) => return Refused(format!("the held acceptance does not decode: {e}")),
    };
    if acceptance.acceptance_leaf().bundle != b {
        return Refused("the held acceptance accepts another bundle".into());
    }

    let closure = match closure(&bundle, &acceptance, fence.storage_set_id) {
        Ok(closure) => closure,
        Err(e) => return Refused(format!("no receipt for this settlement: {e}")),
    };
    let binding = match crate::storage::client_db::get_connection() {
        Ok(binding) => binding,
        Err(e) => return Pending(format!("database: {e}")),
    };
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    match freeze_closure_with_conn(&conn, &closure) {
        Ok(()) => Frozen,
        Err(e) => Pending(format!("the receipt closure could not be frozen: {e}")),
    }
}

/// **The recovery pass**: every released settlement on `own_chain` whose
/// receipt obligation was never recorded, rebuilt and frozen. Returns how many
/// were frozen. Runs from `storage.sync`, beside D-f.
pub(crate) async fn recover_owed_receipts(
    own_chain: &[u8; 32],
) -> std::result::Result<u32, String> {
    let fences = list_released_fences(own_chain).map_err(|e| format!("released fences: {e}"))?;
    let mut frozen = 0u32;
    for fence in &fences {
        match recover_owed_receipt(fence).await {
            ReceiptRecovery::Frozen => frozen += 1,
            ReceiptRecovery::AlreadyRecorded => {}
            ReceiptRecovery::Pending(why) => {
                log::info!("[receipt recovery] pending, retried next pass: {why}")
            }
            ReceiptRecovery::Refused(why) => log::warn!("[receipt recovery] refused: {why}"),
        }
    }
    if frozen > 0 {
        if let Err(e) = crate::handlers::artifact_republish::republish_unpublished_artifacts().await
        {
            log::warn!("[receipt recovery] publication pass failed (retried by the sweep): {e}");
        }
    }
    Ok(frozen)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::client_db::{get_connection, init_database, reset_database_for_tests};
    use dsm::ccb::settlement::fixtures;
    use dsm::economic::state::EconomicBundleAcceptanceState;
    use serial_test::serial;

    const PARENT: [u8; 32] = [0xC0; 32];
    const SET: [u8; 32] = [0xB2; 32];
    const OTHER_SET: [u8; 32] = [0xA1; 32];

    fn bundle_canon() -> Vec<u8> {
        let bundle = fixtures::market_bundle(
            PARENT,
            fixtures::successor(PARENT, 1_010_000, 495_065),
            [0x58; 32],
        );
        dsm::dlv::settlement_bundle::canon(&bundle).expect("canon")
    }

    fn acceptance(b: [u8; 32]) -> TraderAcceptance {
        TraderAcceptance::new(
            [0x11; 32],
            3,
            EconomicBundleAcceptanceState {
                bundle: b,
                economic_operation_id: [0x50; 32],
            },
            vec![[0x00; 32]; dsm::economic::tree::ECONOMIC_SMT_HEIGHT],
        )
        .expect("well formed")
    }

    fn fixture_closure(set: [u8; 32]) -> ReceiptClosure {
        let canon = bundle_canon();
        let b = dsm::dlv::settlement_bundle::bundle_digest(&canon);
        closure(&canon, &acceptance(b), set).expect("closure")
    }

    fn freeze(closure: &ReceiptClosure) -> Result<()> {
        let binding = get_connection().expect("db");
        let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
        freeze_closure_with_conn(&conn, closure)
    }

    fn receipt_row(closure: &ReceiptClosure) -> Option<fpa::FrozenArtifact> {
        fpa::find_artifact_by_purpose_and_bound_root(RECEIPT_PURPOSE, &closure.receipt.bundle())
            .expect("row read")
    }

    #[test]
    fn a_closure_is_a_pure_projection_of_its_inputs() {
        let one = fixture_closure(SET);
        assert_eq!(
            one,
            fixture_closure(SET),
            "same inputs, same keys and bytes"
        );
        assert_eq!(
            one.objects[1].bytes,
            bundle_canon(),
            "the bundle travels byte for byte"
        );
        assert_eq!(
            one.receipt.bundle(),
            dsm::dlv::settlement_bundle::bundle_digest(&bundle_canon())
        );
        assert_eq!(
            one.receipt.trader_acceptance(),
            acceptance(one.receipt.bundle()).ta_b().expect("ta_b"),
            "a_B is the acceptance's inner identity"
        );
        for (o, ns) in one.objects.iter().zip([
            TAG_DSM_SOFI_RECEIPT_V1,
            TAG_DSM_SETTLEMENT_BUNDLE,
            TAG_DSM_TRADER_SETTLEMENT_ACCEPTANCE,
        ]) {
            assert_eq!(o.key, immutable_object_key(ns, &o.bytes));
        }
        // The key from the inner identity is the same key.
        let a = &one.objects[2];
        assert_eq!(
            a.key,
            immutable_object_key_for_inner(
                TAG_DSM_TRADER_SETTLEMENT_ACCEPTANCE,
                &one.receipt.trader_acceptance()
            )
        );
    }

    #[test]
    #[serial]
    fn an_obligation_is_pending_until_every_member_is_frozen_and_at_quorum() {
        reset_database_for_tests();
        init_database().expect("init");
        let c = fixture_closure(SET);
        assert!(matches!(
            publication(&c).unwrap(),
            ClosurePublication::Pending(_)
        ));
        freeze(&c).expect("freeze");
        assert!(
            matches!(publication(&c).unwrap(), ClosurePublication::Pending(_)),
            "frozen is owed, not published"
        );
        freeze(&c).expect("idempotent");
        for o in &c.objects {
            fpa::upsert_artifact_publication_state(
                &o.key,
                &fpa::content_digest(&o.key, &o.bytes),
                fpa::ArtifactState::Published,
                "",
            )
            .expect("mark published");
        }
        assert_eq!(publication(&c).unwrap(), ClosurePublication::Published);
    }

    /// All three rows or none: a closure whose LAST member cannot be frozen
    /// leaves no receipt row behind to be mistaken for a recorded obligation.
    #[test]
    #[serial]
    fn a_closure_that_fails_part_way_freezes_nothing() {
        reset_database_for_tests();
        init_database().expect("init");
        let mut c = fixture_closure(SET);
        c.objects[2].bytes.clear(); // an empty payload is refused by the freeze
        assert!(freeze(&c).is_err());
        assert!(
            receipt_row(&c).is_none(),
            "the receipt row was rolled back with the failed member"
        );
        let whole = fixture_closure(SET);
        assert!(
            matches!(publication(&whole).unwrap(), ClosurePublication::Pending(ref w) if w.contains("not frozen")),
            "and nothing of the closure was left frozen"
        );
    }

    #[test]
    #[serial]
    fn an_injected_freeze_failure_freezes_nothing_and_is_consumed() {
        reset_database_for_tests();
        init_database().expect("init");
        let c = fixture_closure(SET);
        FAIL_NEXT_CLOSURE_FREEZE.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(freeze(&c).is_err());
        assert!(receipt_row(&c).is_none());
        freeze(&c).expect("the next freeze is not failed");
        assert!(receipt_row(&c).is_some());
    }

    /// The honesty arm: a member frozen for ANOTHER set is reported, never
    /// counted as published on `S_v` — even when that other row is published.
    #[test]
    #[serial]
    fn a_member_frozen_for_another_set_is_reported_not_counted() {
        reset_database_for_tests();
        init_database().expect("init");
        let c = fixture_closure(SET);
        let acceptance = &c.objects[2];
        {
            let binding = get_connection().expect("db");
            let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
            fpa::freeze_artifact_with_conn(
                &conn,
                &OTHER_SET,
                &acceptance.key,
                &acceptance.bytes,
                &[0u8; 32],
                "trader-settlement-acceptance",
            )
            .expect("admission freeze");
        }
        freeze(&c).expect("freeze");
        for o in &c.objects {
            fpa::upsert_artifact_publication_state(
                &o.key,
                &fpa::content_digest(&o.key, &o.bytes),
                fpa::ArtifactState::Published,
                "",
            )
            .expect("mark published");
        }
        assert_eq!(
            publication(&c).unwrap(),
            ClosurePublication::BoundToAnotherSet {
                purpose: "sofi-receipt-acceptance"
            }
        );
    }
}
