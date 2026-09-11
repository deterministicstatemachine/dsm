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

use anyhow::Result;
use dsm::common::domain_tags::{
    TAG_DSM_SETTLEMENT_BUNDLE, TAG_DSM_SOFI_RECEIPT_V1, TAG_DSM_TRADER_SETTLEMENT_ACCEPTANCE,
};
use dsm::dlv::sofi_receipt::SofiReceipt;
use dsm::economic::trader_acceptance::TraderAcceptance;

use crate::sdk::economic_registers::immutable_object_key;
use crate::storage::client_db::frozen_publication_artifact as fpa;

/// The frozen-artifact purpose of the receipt row itself.
pub(crate) const RECEIPT_PURPOSE: &str = "sofi-receipt";
const BUNDLE_PURPOSE: &str = "sofi-receipt-bundle";
const ACCEPTANCE_PURPOSE: &str = "sofi-receipt-acceptance";

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

/// Freeze every member of `closure` for its set. Re-freezing identical bytes
/// is a no-op, so this is safe on every completion pass.
pub(crate) fn freeze_closure_with_conn(
    conn: &rusqlite::Connection,
    closure: &ReceiptClosure,
) -> Result<()> {
    let b = closure.receipt.bundle();
    for o in &closure.objects {
        fpa::freeze_artifact_with_conn(
            conn,
            &closure.storage_set_id,
            &o.key,
            &o.bytes,
            &b,
            o.purpose,
        )?;
    }
    Ok(())
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

    fn freeze(closure: &ReceiptClosure) {
        let binding = get_connection().expect("db");
        let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
        freeze_closure_with_conn(&conn, closure).expect("freeze");
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
        freeze(&c);
        assert!(
            matches!(publication(&c).unwrap(), ClosurePublication::Pending(_)),
            "frozen is owed, not published"
        );
        freeze(&c); // idempotent
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
        freeze(&c);
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
