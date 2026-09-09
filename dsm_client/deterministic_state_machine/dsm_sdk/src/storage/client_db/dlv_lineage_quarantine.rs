// SPDX-License-Identifier: MIT OR Apache-2.0

//! DURABLE LINEAGE QUARANTINE (amendment 2c-C3.1), AND THE FINALITY RECORD
//! ITS TRIGGER NEEDS.
//!
//! Two write-once tables, beside the Req 6.23 fence whose discipline they copy:
//!
//! - `dlv_binding_finality_observed` — every qualifying binding finality this
//!   verifier established at a key, with the read (or the commit) that
//!   established it. The duplicate-finality trigger is TEMPORAL: one read at
//!   the canonical quorum cannot show two chosen values
//!   (`one_read_cannot_show_two_chosen_values`, `DSMLineageQuarantine.lean`),
//!   so the contradiction Req 6.3 names is a finality that contradicts one
//!   recorded EARLIER at the same key. Nothing recorded the earlier read
//!   before this table existed.
//! - `dlv_lineage_quarantine` — the roots. One row per `(vault, root c_n)`,
//!   holding BOTH evidence objects. **No `UPDATE` statement exists in this
//!   module and no `DELETE` statement exists in this module**: ruling E
//!   defines no clearing path, so none is implemented, and a test below reads
//!   this source to keep it that way.
//!
//! Values are compared on `(tx_id, value_digest, value_addr)` and NEVER on the
//! round: a value re-accepted at a higher round is the same binding, and the
//! proposer's own recovery carries a foreign chosen value forward rather than
//! overwriting it.
//!
//! Descendants are refused by the GENERATION BOUND (ruling B): same vault,
//! generation at or beyond a root's. The walk's baseline moves at close
//! (`amm_vault_records::update_baseline_with_conn`), so "walk from the
//! baseline and stop at the root" would miss a root the baseline was advanced
//! past. Below the first contradiction a vault's chain is linear, so every
//! state at or beyond the root's generation is the root or descends from it.
//!
//! No clock columns; ordering is the insertion ordinal.

use anyhow::{anyhow, Result};
use dsm::dlv::binding_observation::{tally_key, CanonicalQuorum, ChosenBinding, KeyRead};
use dsm::storage::binding_record::{BindingRecord, Round};
use rusqlite::{params, OptionalExtension};

use super::get_connection;
use crate::storage::codecs::{read_len_u32, read_u64, read_u8, read_vec, take};

/// The value a finality names — what two finalities are compared on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalityValue {
    pub tx_id: [u8; 32],
    pub value_digest: [u8; 32],
    pub value_addr: [u8; 32],
}

impl FinalityValue {
    pub fn of(c: &ChosenBinding) -> Self {
        Self {
            tx_id: c.tx_id,
            value_digest: c.value_digest,
            value_addr: c.value_addr,
        }
    }
}

/// One committed member, as the read attributed it (Req 15.8: both axes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberIdentity {
    pub member_id: Vec<u8>,
    pub register_incarnation: [u8; 32],
}

/// Ruling H, for an OBSERVED finality: the committed members in set order,
/// the read at the key exactly as counted, the quorum it was counted at, and
/// the chosen value. Lossless — [`ObservedEvidence::recompute`] re-tallies it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedEvidence {
    pub quorum: u32,
    pub members: Vec<MemberIdentity>,
    pub read: KeyRead,
    pub chosen: ChosenBinding,
}

/// Ruling H, for this device's OWN committed bind (ruling A, source (b)): the
/// exact value the driver committed, its final ballot, and the permitted
/// successor the fence fixed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnCommitEvidence {
    pub quorum: u32,
    pub value: FinalityValue,
    pub ballot: u64,
    pub storage_set_id: [u8; 32],
    pub trader_successor: [u8; 32],
}

/// An evidence object. The row's byte layout is client-local and defined
/// here; it is not wire and the registry allocates nothing for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Evidence {
    Observed(ObservedEvidence),
    OwnCommit(OwnCommitEvidence),
}

const TAG_OBSERVED: u8 = 1;
const TAG_OWN_COMMIT: u8 = 2;
const MEMBER_UNATTRIBUTED: u8 = 0;
const MEMBER_ABSENT: u8 = 1;
const MEMBER_RECORD: u8 = 2;

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn put_vec(out: &mut Vec<u8>, v: &[u8]) {
    put_u32(out, v.len() as u32);
    out.extend_from_slice(v);
}
fn read_u32(r: &mut &[u8]) -> std::io::Result<u32> {
    Ok(u32::from_le_bytes(take::<4>(r)?))
}

fn put_chosen(out: &mut Vec<u8>, c: &ChosenBinding) {
    out.extend_from_slice(&c.tx_id);
    out.extend_from_slice(&c.value_digest);
    out.extend_from_slice(&c.value_addr);
    put_u64(out, c.round.counter);
    out.extend_from_slice(&c.round.proposer_id);
    put_u32(out, c.holders);
}

fn read_chosen(r: &mut &[u8]) -> std::io::Result<ChosenBinding> {
    Ok(ChosenBinding {
        tx_id: take::<32>(r)?,
        value_digest: take::<32>(r)?,
        value_addr: take::<32>(r)?,
        round: Round {
            counter: read_u64(r)?,
            proposer_id: take::<32>(r)?,
        },
        holders: read_u32(r)?,
    })
}

impl Evidence {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Evidence::Observed(o) => {
                out.push(TAG_OBSERVED);
                put_u32(&mut out, o.quorum);
                put_u32(&mut out, o.members.len() as u32);
                for m in &o.members {
                    put_vec(&mut out, &m.member_id);
                    out.extend_from_slice(&m.register_incarnation);
                }
                put_u32(&mut out, o.read.per_member.len() as u32);
                for m in &o.read.per_member {
                    match m {
                        None => out.push(MEMBER_UNATTRIBUTED),
                        Some(None) => out.push(MEMBER_ABSENT),
                        Some(Some(rec)) => {
                            out.push(MEMBER_RECORD);
                            put_vec(&mut out, &rec.encode());
                        }
                    }
                }
                put_chosen(&mut out, &o.chosen);
            }
            Evidence::OwnCommit(c) => {
                out.push(TAG_OWN_COMMIT);
                put_u32(&mut out, c.quorum);
                out.extend_from_slice(&c.value.tx_id);
                out.extend_from_slice(&c.value.value_digest);
                out.extend_from_slice(&c.value.value_addr);
                put_u64(&mut out, c.ballot);
                out.extend_from_slice(&c.storage_set_id);
                out.extend_from_slice(&c.trader_successor);
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = bytes;
        let out = match read_u8(&mut r)? {
            TAG_OBSERVED => {
                let quorum = read_u32(&mut r)?;
                let n = read_len_u32(&mut r)?;
                let mut members = Vec::with_capacity(n);
                for _ in 0..n {
                    members.push(MemberIdentity {
                        member_id: read_vec(&mut r)?,
                        register_incarnation: take::<32>(&mut r)?,
                    });
                }
                let n = read_len_u32(&mut r)?;
                let mut per_member = Vec::with_capacity(n);
                for _ in 0..n {
                    per_member.push(match read_u8(&mut r)? {
                        MEMBER_UNATTRIBUTED => None,
                        MEMBER_ABSENT => Some(None),
                        MEMBER_RECORD => {
                            let raw = read_vec(&mut r)?;
                            let rec = BindingRecord::decode_canonical(&raw)
                                .map_err(|e| anyhow!("evidence record: {e:?}"))?;
                            Some(Some(rec))
                        }
                        other => return Err(anyhow!("evidence member tag {other}")),
                    });
                }
                let chosen = read_chosen(&mut r)?;
                Evidence::Observed(ObservedEvidence {
                    quorum,
                    members,
                    read: KeyRead { per_member },
                    chosen,
                })
            }
            TAG_OWN_COMMIT => Evidence::OwnCommit(OwnCommitEvidence {
                quorum: read_u32(&mut r)?,
                value: FinalityValue {
                    tx_id: take::<32>(&mut r)?,
                    value_digest: take::<32>(&mut r)?,
                    value_addr: take::<32>(&mut r)?,
                },
                ballot: read_u64(&mut r)?,
                storage_set_id: take::<32>(&mut r)?,
                trader_successor: take::<32>(&mut r)?,
            }),
            other => return Err(anyhow!("evidence tag {other}")),
        };
        if !r.is_empty() {
            return Err(anyhow!("evidence has {} trailing bytes", r.len()));
        }
        Ok(out)
    }

    /// The value this evidence establishes.
    pub fn value(&self) -> FinalityValue {
        match self {
            Evidence::Observed(o) => FinalityValue::of(&o.chosen),
            Evidence::OwnCommit(c) => c.value,
        }
    }
}

impl ObservedEvidence {
    /// LOSSLESS, checked: re-tally the preserved read at the preserved quorum
    /// and require that it yields exactly the preserved chosen value. An
    /// evidence object that does not reproduce its finality is not evidence.
    pub fn recompute(&self) -> Result<(), String> {
        if self.read.per_member.len() != self.members.len() {
            return Err(format!(
                "the read has {} answers for {} members",
                self.read.per_member.len(),
                self.members.len()
            ));
        }
        let q = CanonicalQuorum::of_committed(self.members.len(), self.quorum)
            .map_err(|e| e.to_string())?;
        let tally = tally_key(&self.read.as_attributed_records(), 0, q.get());
        if tally.chosen == vec![self.chosen.clone()] {
            Ok(())
        } else {
            Err(format!(
                "re-tallying the read yields {} chosen value(s), not the preserved one",
                tally.chosen.len()
            ))
        }
    }
}

/// One qualifying binding finality this verifier established at a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedFinality {
    pub vault_id: [u8; 32],
    pub c_n: [u8; 32],
    pub generation: u64,
    pub value: FinalityValue,
    /// Carried for the record; never compared.
    pub round: Round,
    pub holders: u32,
    pub storage_set_id: [u8; 32],
    pub quorum: u32,
    /// [`Evidence::encode`] bytes.
    pub evidence: Vec<u8>,
}

/// What recording a finality established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordOutcome {
    /// First finality at this key; it is now the record.
    Recorded,
    /// The same VALUE was already recorded here — at any round. Not a
    /// contradiction, and nothing is written.
    AlreadyRecordedSameValue,
    /// A DIFFERENT value was recorded here: duplicate contradictory qualifying
    /// binding finality at one parent. The record is left as it was — it is
    /// evidence, not an error to correct.
    Contradiction { recorded: Box<ObservedFinality> },
}

const OBSERVED_COLS: &str = "vault_id, c_n, generation, tx_id, value_digest, value_addr, \
     round_counter, round_proposer, holders, storage_set_id, quorum, evidence";

fn fixed32(v: Vec<u8>) -> Result<[u8; 32]> {
    <[u8; 32]>::try_from(v.as_slice()).map_err(|_| anyhow!("column is not 32 bytes"))
}

fn row_to_observed(r: &rusqlite::Row<'_>) -> rusqlite::Result<ObservedFinality> {
    let conv = |e: anyhow::Error| rusqlite::Error::ToSqlConversionFailure(e.into());
    Ok(ObservedFinality {
        vault_id: fixed32(r.get(0)?).map_err(conv)?,
        c_n: fixed32(r.get(1)?).map_err(conv)?,
        generation: r.get::<_, i64>(2)? as u64,
        value: FinalityValue {
            tx_id: fixed32(r.get(3)?).map_err(conv)?,
            value_digest: fixed32(r.get(4)?).map_err(conv)?,
            value_addr: fixed32(r.get(5)?).map_err(conv)?,
        },
        round: Round {
            counter: r.get::<_, i64>(6)? as u64,
            proposer_id: fixed32(r.get(7)?).map_err(conv)?,
        },
        holders: r.get::<_, i64>(8)? as u32,
        storage_set_id: fixed32(r.get(9)?).map_err(conv)?,
        quorum: r.get::<_, i64>(10)? as u32,
        evidence: r.get(11)?,
    })
}

/// The finality this verifier recorded at `(vault, c_n)`, if any.
pub fn observed_finality(vault_id: &[u8; 32], c_n: &[u8; 32]) -> Result<Option<ObservedFinality>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    observed_with_conn(&conn, vault_id, c_n)
}

fn observed_with_conn(
    conn: &rusqlite::Connection,
    vault_id: &[u8; 32],
    c_n: &[u8; 32],
) -> Result<Option<ObservedFinality>> {
    Ok(conn
        .query_row(
            &format!(
                "SELECT {OBSERVED_COLS} FROM dlv_binding_finality_observed
                  WHERE vault_id = ?1 AND c_n = ?2"
            ),
            params![vault_id.as_slice(), c_n.as_slice()],
            row_to_observed,
        )
        .optional()?)
}

/// Record a qualifying finality the moment it is established (ruling A),
/// compared on VALUE against what was recorded earlier at the same key.
///
/// Write-once: the first finality at a key is the record. A second finality
/// naming the same value writes nothing; a second finality naming a different
/// value writes nothing either and reports the contradiction, so the caller
/// can write the root with both evidence objects.
pub fn record_finality(f: &ObservedFinality) -> Result<RecordOutcome> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(recorded) = observed_with_conn(&conn, &f.vault_id, &f.c_n)? {
        return Ok(if recorded.value == f.value {
            RecordOutcome::AlreadyRecordedSameValue
        } else {
            RecordOutcome::Contradiction {
                recorded: Box::new(recorded),
            }
        });
    }
    conn.execute(
        &format!(
            "INSERT OR IGNORE INTO dlv_binding_finality_observed ({OBSERVED_COLS})
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"
        ),
        params![
            f.vault_id.as_slice(),
            f.c_n.as_slice(),
            f.generation as i64,
            f.value.tx_id.as_slice(),
            f.value.value_digest.as_slice(),
            f.value.value_addr.as_slice(),
            f.round.counter as i64,
            f.round.proposer_id.as_slice(),
            f.holders as i64,
            f.storage_set_id.as_slice(),
            f.quorum as i64,
            f.evidence,
        ],
    )?;
    Ok(RecordOutcome::Recorded)
}

/// A quarantine root: the exact parent, and BOTH evidence objects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineRoot {
    pub vault_id: [u8; 32],
    pub root_c_n: [u8; 32],
    pub root_generation: u64,
    pub storage_set_id: [u8; 32],
    pub quorum: u32,
    /// The finality recorded FIRST at the key.
    pub first_evidence: Vec<u8>,
    /// The finality that contradicted it.
    pub second_evidence: Vec<u8>,
    pub insertion_ordinal: i64,
}

const ROOT_COLS: &str = "vault_id, root_c_n, root_generation, storage_set_id, quorum, \
     first_evidence, second_evidence, insertion_ordinal";

fn row_to_root(r: &rusqlite::Row<'_>) -> rusqlite::Result<QuarantineRoot> {
    let conv = |e: anyhow::Error| rusqlite::Error::ToSqlConversionFailure(e.into());
    Ok(QuarantineRoot {
        vault_id: fixed32(r.get(0)?).map_err(conv)?,
        root_c_n: fixed32(r.get(1)?).map_err(conv)?,
        root_generation: r.get::<_, i64>(2)? as u64,
        storage_set_id: fixed32(r.get(3)?).map_err(conv)?,
        quorum: r.get::<_, i64>(4)? as u32,
        first_evidence: r.get(5)?,
        second_evidence: r.get(6)?,
        insertion_ordinal: r.get(7)?,
    })
}

/// Write a root. `INSERT OR IGNORE`: the first evidence written IS the
/// evidence, and a second call for the same root changes nothing.
pub fn quarantine_root(root: &QuarantineRoot) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "INSERT OR IGNORE INTO dlv_lineage_quarantine
            (vault_id, root_c_n, root_generation, storage_set_id, quorum,
             first_evidence, second_evidence)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            root.vault_id.as_slice(),
            root.root_c_n.as_slice(),
            root.root_generation as i64,
            root.storage_set_id.as_slice(),
            root.quorum as i64,
            root.first_evidence,
            root.second_evidence,
        ],
    )?;
    Ok(())
}

/// The root that refuses a cursor or an execution at `(vault, generation,
/// c_n)`, if any: the exact root, or any root of the vault whose generation
/// is at or below this one (ruling B's generation bound). The lowest such
/// root is named, because it is the one every later state descends from.
pub fn refusing_root(
    vault_id: &[u8; 32],
    generation: u64,
    c_n: &[u8; 32],
) -> Result<Option<QuarantineRoot>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    Ok(conn
        .query_row(
            &format!(
                "SELECT {ROOT_COLS} FROM dlv_lineage_quarantine
                  WHERE vault_id = ?1 AND (root_c_n = ?2 OR root_generation <= ?3)
                  ORDER BY root_generation ASC, insertion_ordinal ASC LIMIT 1"
            ),
            params![vault_id.as_slice(), c_n.as_slice(), generation as i64],
            row_to_root,
        )
        .optional()?)
}

/// Every root of one vault, oldest first.
pub fn roots_for_vault(vault_id: &[u8; 32]) -> Result<Vec<QuarantineRoot>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let mut stmt = conn.prepare(&format!(
        "SELECT {ROOT_COLS} FROM dlv_lineage_quarantine
          WHERE vault_id = ?1 ORDER BY insertion_ordinal ASC"
    ))?;
    let rows = stmt.query_map(params![vault_id.as_slice()], row_to_root)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// The one sentence every refusal carries: which root, and why this cursor
/// is under it.
pub fn describe_refusal(root: &QuarantineRoot, generation: u64) -> String {
    let b32 = crate::util::text_id::encode_base32_crockford;
    format!(
        "generation {generation} is at or beyond the quarantined root {} (generation {}) of \
         this vault; duplicate binding finality was established there and no later read, \
         retry or restart clears it",
        b32(&root.root_c_n),
        root.root_generation
    )
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use dsm::dlv::quorum_bind::BINDING_STATUS_ACCEPTED;
    use serial_test::serial;

    fn init() {
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init");
    }

    fn rec(value: u8, counter: u64) -> BindingRecord {
        BindingRecord {
            schema: dsm::storage::binding_record::BINDING_RECORD_SCHEMA_V1,
            round: Round {
                counter,
                proposer_id: [7; 32],
            },
            tx_id: [value; 32],
            keyset_digest: [0x5E; 32],
            value_digest: [value; 32],
            value_addr: [value ^ 0xFF; 32],
            status: BINDING_STATUS_ACCEPTED,
        }
    }

    fn chosen(value: u8, counter: u64, holders: u32) -> ChosenBinding {
        ChosenBinding {
            tx_id: [value; 32],
            value_digest: [value; 32],
            value_addr: [value ^ 0xFF; 32],
            round: Round {
                counter,
                proposer_id: [7; 32],
            },
            holders,
        }
    }

    fn members() -> Vec<MemberIdentity> {
        (1..=3u8)
            .map(|i| MemberIdentity {
                member_id: format!("dsm-node-{i}").into_bytes(),
                register_incarnation: [i; 32],
            })
            .collect()
    }

    /// Two members hold `value`, one is an explicit absence: bound-final at q=2.
    fn observed(value: u8, counter: u64) -> ObservedEvidence {
        ObservedEvidence {
            quorum: 2,
            members: members(),
            read: KeyRead {
                per_member: vec![
                    Some(Some(rec(value, counter))),
                    Some(None),
                    Some(Some(rec(value, counter))),
                ],
            },
            chosen: chosen(value, counter, 2),
        }
    }

    fn finality(vault: u8, cn: u8, generation: u64, value: u8, counter: u64) -> ObservedFinality {
        let ev = observed(value, counter);
        ObservedFinality {
            vault_id: [vault; 32],
            c_n: [cn; 32],
            generation,
            value: FinalityValue::of(&ev.chosen),
            round: ev.chosen.round,
            holders: 2,
            storage_set_id: [0x55; 32],
            quorum: 2,
            evidence: Evidence::Observed(ev).encode(),
        }
    }

    // ── ruling H: the evidence object ────────────────────────────────────

    #[test]
    fn observed_evidence_round_trips_and_recomputes_its_finality() {
        let ev = observed(0xAA, 3);
        let bytes = Evidence::Observed(ev.clone()).encode();
        let back = Evidence::decode(&bytes).expect("decodes");
        assert_eq!(back, Evidence::Observed(ev.clone()));
        assert_eq!(back.value(), FinalityValue::of(&ev.chosen));
        ev.recompute()
            .expect("the preserved read reproduces the chosen value");
    }

    #[test]
    fn own_commit_evidence_round_trips() {
        let ev = OwnCommitEvidence {
            quorum: 2,
            value: FinalityValue {
                tx_id: [1; 32],
                value_digest: [1; 32],
                value_addr: [2; 32],
            },
            ballot: 9,
            storage_set_id: [3; 32],
            trader_successor: [4; 32],
        };
        let back = Evidence::decode(&Evidence::OwnCommit(ev.clone()).encode()).expect("decodes");
        assert_eq!(back, Evidence::OwnCommit(ev));
    }

    /// An evidence object whose read does NOT yield its chosen value is not
    /// evidence, and `recompute` says so rather than trusting the label.
    #[test]
    fn evidence_that_does_not_reproduce_its_finality_is_refused_by_recompute() {
        let mut ev = observed(0xAA, 3);
        ev.chosen = chosen(0xBB, 3, 2);
        assert!(ev.recompute().is_err());
        let mut short = observed(0xAA, 3);
        short.read.per_member[2] = Some(None);
        assert!(
            short.recompute().is_err(),
            "one holder is not finality at q=2"
        );
    }

    #[test]
    fn trailing_bytes_and_unknown_tags_do_not_decode() {
        let mut bytes = Evidence::Observed(observed(0xAA, 1)).encode();
        bytes.push(0);
        assert!(Evidence::decode(&bytes).is_err());
        assert!(Evidence::decode(&[9u8]).is_err());
    }

    // ── ruling A: the temporal trigger ───────────────────────────────────

    #[test]
    #[serial]
    fn the_first_finality_at_a_key_is_recorded_and_the_same_value_is_not_a_contradiction() {
        init();
        let first = finality(1, 10, 5, 0xAA, 3);
        assert_eq!(record_finality(&first).unwrap(), RecordOutcome::Recorded);
        assert_eq!(
            observed_finality(&[1; 32], &[10; 32]).unwrap().as_ref(),
            Some(&first)
        );
        // The same VALUE at a higher round, by different holders: the same
        // binding, and nothing is rewritten.
        let again = finality(1, 10, 5, 0xAA, 9);
        assert_eq!(
            record_finality(&again).unwrap(),
            RecordOutcome::AlreadyRecordedSameValue
        );
        assert_eq!(
            observed_finality(&[1; 32], &[10; 32]).unwrap().as_ref(),
            Some(&first),
            "the record is write-once"
        );
    }

    #[test]
    #[serial]
    fn a_different_value_at_the_same_key_is_a_contradiction_and_corrects_nothing() {
        init();
        let first = finality(1, 10, 5, 0xAA, 3);
        assert_eq!(record_finality(&first).unwrap(), RecordOutcome::Recorded);
        let second = finality(1, 10, 5, 0xBB, 4);
        assert_eq!(
            record_finality(&second).unwrap(),
            RecordOutcome::Contradiction {
                recorded: Box::new(first.clone())
            }
        );
        assert_eq!(
            observed_finality(&[1; 32], &[10; 32]).unwrap().as_ref(),
            Some(&first),
            "the earlier observation is evidence, not an error to correct"
        );
        // Another key of the same vault, and the same key of another vault,
        // are untouched by it.
        assert_eq!(
            record_finality(&finality(1, 11, 6, 0xBB, 1)).unwrap(),
            RecordOutcome::Recorded
        );
        assert_eq!(
            record_finality(&finality(2, 10, 5, 0xBB, 1)).unwrap(),
            RecordOutcome::Recorded
        );
    }

    // ── rulings B, C, E: the roots ───────────────────────────────────────

    fn root(vault: u8, cn: u8, generation: u64) -> QuarantineRoot {
        QuarantineRoot {
            vault_id: [vault; 32],
            root_c_n: [cn; 32],
            root_generation: generation,
            storage_set_id: [0x55; 32],
            quorum: 2,
            first_evidence: Evidence::Observed(observed(0xAA, 3)).encode(),
            second_evidence: Evidence::Observed(observed(0xBB, 4)).encode(),
            insertion_ordinal: 0,
        }
    }

    #[test]
    #[serial]
    fn a_root_refuses_its_parent_both_continuations_and_everything_beyond_never_below() {
        init();
        quarantine_root(&root(1, 100, 5)).unwrap();
        let refused = |gen: u64, cn: u8| refusing_root(&[1; 32], gen, &[cn; 32]).unwrap();
        assert!(refused(5, 100).is_some(), "the root itself");
        assert!(refused(6, 201).is_some(), "the first continuation");
        assert!(refused(6, 202).is_some(), "the second continuation");
        assert!(
            refused(9, 250).is_some(),
            "everything beyond, by generation"
        );
        assert!(
            refused(4, 40).is_none(),
            "below the root is not quarantined"
        );
        assert!(
            refusing_root(&[2; 32], 9, &[100; 32]).unwrap().is_none(),
            "another vault is untouched, even at the same c_n"
        );
        let named = refused(9, 250).unwrap();
        assert_eq!(named.root_c_n, [100; 32]);
        assert!(describe_refusal(&named, 9).contains("generation 9 is at or beyond"));
    }

    /// Write-once: a second root for the same parent changes nothing, and the
    /// FIRST evidence written stays the evidence.
    #[test]
    #[serial]
    fn a_root_is_written_once_and_its_evidence_is_immutable() {
        init();
        quarantine_root(&root(1, 100, 5)).unwrap();
        let mut again = root(1, 100, 5);
        again.first_evidence = vec![0xDE, 0xAD];
        quarantine_root(&again).unwrap();
        let roots = roots_for_vault(&[1; 32]).unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].first_evidence, root(1, 100, 5).first_evidence);
        let ev = Evidence::decode(&roots[0].first_evidence).unwrap();
        let Evidence::Observed(o) = ev else {
            panic!("observed evidence")
        };
        o.recompute().expect("preserved evidence recomputes");
    }

    /// Ruling E as a structural fact about this module: no statement here can
    /// update or delete a root or a recorded finality. Removing this
    /// discipline means writing such a statement, which this test reads.
    #[test]
    fn the_module_has_no_update_and_no_delete_statement() {
        const SRC: &str = include_str!("dlv_lineage_quarantine.rs");
        for forbidden in [
            "DELETE FROM dlv_lineage_quarantine",
            "UPDATE dlv_lineage_quarantine",
            "DELETE FROM dlv_binding_finality_observed",
            "UPDATE dlv_binding_finality_observed",
        ] {
            assert_eq!(
                SRC.matches(forbidden).count(),
                1,
                "{forbidden}: the only occurrence must be this test's own list"
            );
        }
    }
}
