// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical AMM vault record — what a restart cannot re-derive.
//!
//! The reserve LEAVES already survive a restart: every reserve write stamps the
//! vault's sequence into the leaf value, and the device-head codec persists
//! `VaultReserve { amount, sequence }`. So the amounts and the sequence are not
//! lost, and this record does not repeat them. Persisting them here would create
//! a second copy of an authenticated fact, and the two copies would eventually
//! disagree — with nothing to say which was right.
//!
//! What a restart genuinely loses is the vault's IDENTITY AND POLICY:
//! `current_sequence` was documented as "Domain-only: not persisted", so a
//! reloaded wallet had a vault at sequence 0. A sequence reset to 0 makes
//! every anchor binding mismatch, and — since gate 1 — makes the reserve proof
//! at the baseline sequence unfindable. The vault was silently un-tradable and
//! looked fine.
//!
//! NOTHING IS REPAIRED BY DEFAULT. A record that is absent, malformed, or
//! inconsistent with the leaves makes that vault UNAVAILABLE. Defaulting
//! `current_sequence` to 0 would turn missing reconstruction data into a vault
//! that trades under rules nobody chose — the failure mode this exists to
//! prevent, arriving as a repair.
//!
//! `anchor_enforcement` is no longer part of that story. It is deprecation
//! residue: anchor binding is unconditional in the code that enforces it, so
//! the column could only ever have described a weaker posture than the one in
//! force. Nothing reads it for a decision; see the field's doc below.

use anyhow::Result;
use rusqlite::{params, OptionalExtension};

use super::get_connection;

/// The authoritative reconstruction inputs for one AMM vault.
///
/// Deliberately does NOT carry reserves or sequence: those live in the reserve
/// leaves, which are authenticated by the device root. This record carries only
/// what the leaves cannot express.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmmVaultRecord {
    pub vault_id: [u8; 32],
    /// Owner identity — the key-derivation inputs for this vault's reserve
    /// leaves. Without them the leaves cannot be located at all.
    pub owner_genesis: [u8; 32],
    pub owner_devid: [u8; 32],
    /// The pair, in canonical order: `policy_commit_a` is lex-lower.
    pub policy_commit_a: [u8; 32],
    pub policy_commit_b: [u8; 32],
    pub fee_bps: u32,
    /// DEPRECATION RESIDUE — SEMANTICALLY DEAD, scheduled for removal with the
    /// column. Written with the canonical `Required` and read by no decision:
    /// `rehydrate_amm_vault` derives the posture instead, because anchor
    /// binding is unconditional in `enforce_parent_binding` and always was.
    /// Do not add a reader.
    pub anchor_enforcement: i32,
    /// The CPTA policy anchor governing this vault.
    pub policy_digest: [u8; 32],
    /// The canonical storage set the vault was born under — a LOCAL COPY of the
    /// value bound inside the vault's signed birth anchor. Consumers resolve
    /// the anchor's set; a caller that has both must require equality and fail
    /// closed on mismatch (the anchor chooses the set; this only caches it).
    pub storage_set_id: [u8; 32],
    /// `CCB(V_n)` — the owner's CURRENT published baseline (birth at
    /// creation, terminal after close), exactly as published immutably.
    /// `c_n` recomputes from these bytes; owner-side composition decodes them.
    pub baseline_state_ccb: Vec<u8>,
    /// The `AnchorPresentationV3` proto bytes anchoring that baseline,
    /// exactly as published — reused for every owner-side composition so the
    /// authority chain is not re-signed per quote.
    pub baseline_presentation: Vec<u8>,
    /// The vault's frozen `VaultPostProto` bytes, produced once at
    /// `dlv.create` after the vault is finalized and stamped. The routing
    /// advertisement's full proto mirror replays these exact bytes, so
    /// publishing survives a restart without consulting the in-memory
    /// DLVManager. Empty means the producer never ran; consumers fail closed.
    pub vault_post_proto: Vec<u8>,
    /// WHERE THIS VAULT'S RESERVE PROOF LIVES — the content address of the
    /// `EconomicProofArtifactV1` the admitted create published, and the
    /// economic position whose registered root it names.
    ///
    /// A LOCATOR, on the way in and on the way out. A reader resolves the
    /// position's root from the publisher's own register cell and re-derives
    /// every inclusion path, so a wrong address or position here can only make
    /// a lookup fail; it can never make one succeed against a root the owner
    /// did not register. `None` when the create published no artifact.
    pub economic_proof: Option<EconomicProofLocator>,
}

/// The two halves of a reserve-proof locator; only ever present together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EconomicProofLocator {
    pub addr: [u8; 32],
    pub position: u64,
}

/// TEST-ONLY full-row writer.
///
/// `INSERT OR REPLACE` over every column is a whole-record overwrite: it can
/// replace a live vault's owner, pair, fee, policy digest and both baseline
/// blobs in one statement, with no pre-check and no transaction around it.
/// Production does not need that shape and must not have it — `dlv.create`
/// inserts inside the advance transaction (with its own concurrent-creation
/// pre-check) and every later change goes through a NARROW writer
/// (`update_baseline_with_conn`, `update_vault_post_proto`). Compiling this
/// out of shipping builds is what makes "no production path can rewrite a
/// whole vault row" a property of the binary rather than of review.
#[cfg(any(test, feature = "test-utils"))]
pub fn put_amm_vault_record(rec: &AmmVaultRecord) -> Result<()> {
    let now = crate::util::deterministic_time::tick();
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in put_amm_vault_record, recovering");
        poisoned.into_inner()
    });
    conn.execute(
        "INSERT OR REPLACE INTO amm_vault_records(
            vault_id, owner_genesis, owner_devid, policy_commit_a, policy_commit_b,
            fee_bps, anchor_enforcement, policy_digest, storage_set_id,
            baseline_state_ccb, baseline_presentation, vault_post_proto, created_at)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            rec.vault_id.as_slice(),
            rec.owner_genesis.as_slice(),
            rec.owner_devid.as_slice(),
            rec.policy_commit_a.as_slice(),
            rec.policy_commit_b.as_slice(),
            rec.fee_bps,
            rec.anchor_enforcement,
            rec.policy_digest.as_slice(),
            rec.storage_set_id.as_slice(),
            rec.baseline_state_ccb.as_slice(),
            rec.baseline_presentation.as_slice(),
            rec.vault_post_proto.as_slice(),
            now as i64,
        ],
    )?;
    Ok(())
}

/// Advance the record's published baseline inside an open transaction — the
/// close writes its terminal `CCB(V_n)` + presentation here so the record and
/// the frozen publication commit together or not at all.
pub fn update_baseline_with_conn(
    tx: &rusqlite::Transaction<'_>,
    vault_id: &[u8; 32],
    state_ccb: &[u8],
    presentation: &[u8],
) -> Result<()> {
    let changed = tx.execute(
        "UPDATE amm_vault_records
            SET baseline_state_ccb = ?2, baseline_presentation = ?3
          WHERE vault_id = ?1",
        params![vault_id.as_slice(), state_ccb, presentation],
    )?;
    if changed != 1 {
        anyhow::bail!("baseline update touched {changed} rows for one vault id");
    }
    Ok(())
}

/// Stamp this vault's reserve-proof locator onto its record. Runs once, at
/// `dlv.create`, after the admitted create published the artifact — the
/// earliest point at which both halves exist. Refuses a zero address so an
/// absent locator can never be written as a present one.
pub fn update_economic_proof_locator(
    vault_id: &[u8; 32],
    locator: &EconomicProofLocator,
) -> Result<()> {
    if locator.addr == [0u8; 32] {
        anyhow::bail!("refusing to stamp a zero economic-proof address");
    }
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in update_economic_proof_locator, recovering");
        poisoned.into_inner()
    });
    let changed = conn.execute(
        "UPDATE amm_vault_records
            SET economic_proof_addr = ?2, economic_proof_position = ?3
          WHERE vault_id = ?1",
        params![
            vault_id.as_slice(),
            locator.addr.as_slice(),
            locator.position as i64
        ],
    )?;
    if changed != 1 {
        anyhow::bail!("economic-proof locator stamp touched {changed} rows for one vault id");
    }
    Ok(())
}

/// Stamp the vault's frozen `VaultPostProto` bytes onto its record. Runs once,
/// at `dlv.create`, after the vault is finalized and its enforcement/policy
/// digest are stamped — the earliest point at which the bytes are final.
pub fn update_vault_post_proto(vault_id: &[u8; 32], post_proto: &[u8]) -> Result<()> {
    if post_proto.is_empty() {
        anyhow::bail!("refusing to stamp empty vault-post bytes");
    }
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in update_vault_post_proto, recovering");
        poisoned.into_inner()
    });
    let changed = conn.execute(
        "UPDATE amm_vault_records SET vault_post_proto = ?2 WHERE vault_id = ?1",
        params![vault_id.as_slice(), post_proto],
    )?;
    if changed != 1 {
        anyhow::bail!("vault-post stamp touched {changed} rows for one vault id");
    }
    Ok(())
}

fn fixed32(v: Vec<u8>) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(v.as_slice()).ok()
}

/// Read one record. A row whose stored bytes are the wrong width yields `None`
/// rather than a struct wearing zeros — a zero-filled vault id would name a
/// different vault, and a zero owner would locate no leaves.
pub fn get_amm_vault_record(vault_id: &[u8; 32]) -> Result<Option<AmmVaultRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in get_amm_vault_record, recovering");
        poisoned.into_inner()
    });
    let row = conn
        .query_row(
            "SELECT vault_id, owner_genesis, owner_devid, policy_commit_a, policy_commit_b,
                    fee_bps, anchor_enforcement, policy_digest, storage_set_id,
                    baseline_state_ccb, baseline_presentation, vault_post_proto,
                    economic_proof_addr, economic_proof_position
             FROM amm_vault_records WHERE vault_id = ?1",
            params![vault_id.as_slice()],
            |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                    r.get::<_, Vec<u8>>(4)?,
                    r.get::<_, u32>(5)?,
                    r.get::<_, i32>(6)?,
                    r.get::<_, Vec<u8>>(7)?,
                    r.get::<_, Vec<u8>>(8)?,
                    r.get::<_, Vec<u8>>(9)?,
                    r.get::<_, Vec<u8>>(10)?,
                    r.get::<_, Vec<u8>>(11)?,
                    r.get::<_, Vec<u8>>(12)?,
                    r.get::<_, i64>(13)?,
                ))
            },
        )
        .optional()?;
    let Some((
        vid,
        g,
        d,
        a,
        b,
        fee_bps,
        anchor_enforcement,
        pd,
        ss,
        baseline_state_ccb,
        baseline_presentation,
        vault_post_proto,
        proof_addr,
        proof_position,
    )) = row
    else {
        return Ok(None);
    };
    let (Some(vault_id), Some(owner_genesis), Some(owner_devid)) =
        (fixed32(vid), fixed32(g), fixed32(d))
    else {
        return Ok(None);
    };
    let (Some(policy_commit_a), Some(policy_commit_b), Some(policy_digest), Some(storage_set_id)) =
        (fixed32(a), fixed32(b), fixed32(pd), fixed32(ss))
    else {
        return Ok(None);
    };
    // Both halves or neither: a present address with an unreadable width is a
    // corrupt row, not a vault without a locator, so the whole record is
    // dropped exactly as a bad policy commit drops it.
    let economic_proof = if proof_addr.is_empty() {
        None
    } else {
        let Some(addr) = fixed32(proof_addr) else {
            return Ok(None);
        };
        Some(EconomicProofLocator {
            addr,
            position: proof_position as u64,
        })
    };
    Ok(Some(AmmVaultRecord {
        vault_id,
        owner_genesis,
        owner_devid,
        policy_commit_a,
        policy_commit_b,
        fee_bps,
        anchor_enforcement,
        policy_digest,
        storage_set_id,
        baseline_state_ccb,
        baseline_presentation,
        vault_post_proto,
        economic_proof,
    }))
}

/// Every persisted AMM vault record. Rows that cannot be read back as a whole
/// record are dropped rather than partially reconstructed.
pub fn list_amm_vault_records() -> Result<Vec<AmmVaultRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in list_amm_vault_records, recovering");
        poisoned.into_inner()
    });
    let mut stmt =
        conn.prepare("SELECT vault_id FROM amm_vault_records ORDER BY created_at ASC")?;
    let ids: Vec<Vec<u8>> = stmt
        .query_map([], |r| r.get::<_, Vec<u8>>(0))?
        .filter_map(|r| r.ok())
        .collect();
    drop(stmt);
    drop(conn);
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let Some(vid) = fixed32(id) else { continue };
        if let Ok(Some(rec)) = get_amm_vault_record(&vid) {
            out.push(rec);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    /// The DLV-policy digest a record for this fee carries — a derived view of
    /// the beta release family and the fee, exactly what `dlv.create` persists.
    fn derived_policy_digest(fee_bps: u32) -> [u8; 32] {
        dsm::ccb::dlv_policy_digest(
            &dsm::ccb::ReleasePolicy::beta_owner_local_full_close(),
            &dsm::ccb::FeePolicy::new(fee_bps).expect("fee below the denominator"),
        )
    }

    use super::*;
    use serial_test::serial;

    fn init_test_db() {
        unsafe { std::env::set_var("DSM_SDK_TEST_MODE", "1") };
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
    }

    fn rec(b: u8) -> AmmVaultRecord {
        AmmVaultRecord {
            vault_id: [b; 32],
            owner_genesis: [0xA0; 32],
            owner_devid: [0xB0; 32],
            policy_commit_a: [0x11; 32],
            policy_commit_b: [0x22; 32],
            fee_bps: 30,
            anchor_enforcement: 2,
            policy_digest: derived_policy_digest(30),
            storage_set_id: [0x6B; 32],
            baseline_state_ccb: Vec::new(),
            baseline_presentation: Vec::new(),
            vault_post_proto: vec![0xC3; 48],
            economic_proof: None,
        }
    }

    #[test]
    #[serial]
    fn a_record_round_trips_every_field() {
        init_test_db();
        let r = rec(0x77);
        put_amm_vault_record(&r).expect("put");
        assert_eq!(
            get_amm_vault_record(&r.vault_id).expect("get"),
            Some(r.clone()),
            "every reconstruction input must survive"
        );
    }

    #[test]
    #[serial]
    fn an_absent_record_is_none_not_a_default_vault() {
        init_test_db();
        assert_eq!(
            get_amm_vault_record(&[0xEE; 32]).expect("get"),
            None,
            "a vault with no record must not materialise from defaults"
        );
    }

    #[test]
    #[serial]
    fn a_row_with_a_wrong_width_field_reads_as_absent() {
        init_test_db();
        let r = rec(0x78);
        put_amm_vault_record(&r).expect("put");
        // Corrupt the owner devid to 31 bytes, as a truncated write would.
        {
            let binding = get_connection().expect("conn");
            let conn = binding.lock().expect("lock");
            conn.execute(
                "UPDATE amm_vault_records SET owner_devid = ?1 WHERE vault_id = ?2",
                params![vec![0u8; 31], r.vault_id.as_slice()],
            )
            .expect("corrupt");
        }
        assert_eq!(
            get_amm_vault_record(&r.vault_id).expect("get"),
            None,
            "a malformed row must read as absent, never as a zero-filled owner"
        );
    }

    #[test]
    #[serial]
    fn listing_skips_unreadable_rows_rather_than_reconstructing_them() {
        init_test_db();
        let good = rec(0x79);
        let bad = rec(0x7A);
        put_amm_vault_record(&good).expect("put");
        put_amm_vault_record(&bad).expect("put");
        {
            let binding = get_connection().expect("conn");
            let conn = binding.lock().expect("lock");
            conn.execute(
                "UPDATE amm_vault_records SET policy_commit_a = ?1 WHERE vault_id = ?2",
                params![vec![0u8; 7], bad.vault_id.as_slice()],
            )
            .expect("corrupt");
        }
        let listed = list_amm_vault_records().expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].vault_id, good.vault_id);
    }
}
