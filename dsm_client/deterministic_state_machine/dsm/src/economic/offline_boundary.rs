// SPDX-License-Identifier: Apache-2.0

//! Offline boundaries — CCB classes `0x002A` (load) and `0x002B` (unload).
//!
//! A load moves value from the online balance into the device's offline
//! account; an unload moves it back. Each is an economic transition admitted
//! like any other, and its substrate is the boundary body: what the device
//! root and the offline account were before it, and the paths that let a
//! verifier fold both trees across it.
//!
//! ```text
//! R_A  ─ device path ─ offline_account_leaf_key(B) → R_off
//! R_off ─ account paths ─ allocation(asset), funding chain
//! ```
//!
//! Nothing a verifier needs about the boundary's effect is carried as a
//! claim. The account after it is folded from the account before it and the
//! step the body names; the device root after it is folded from the device
//! path; the boundary's identity is hashed from the roots it starts from
//! (`OfflineBoundaryId`), and becomes the account's funding chain. An unload's
//! online credit is funded by exactly the account debit that fold proves
//! (`CreditSourceOfflineBoundaryDebit`, `0x0075`), and the source it consumes
//! is derived from that identity, so one offline debit funds one online
//! credit, once.
//!
//! Schema 2: a boundary also carries the account's ancestry since the boundary
//! before it. It names the anchor the account belongs to — the keys and birth
//! its bundle `B` commits, so a verifier recomputes `B` with the owner's online
//! key and device id — and where the account stood when the last boundary left
//! it (or, at the account's first boundary, the frontier it opened at, empty),
//! and every spend the anchor released since, in order. The spends are verified
//! hop by hop from that account to the one the boundary starts from
//! ([`crate::types::offline_chain::verify_spend_chain`]): value only leaves an
//! account between its boundaries, and the boundary exposes each payment
//! online. A walker that recorded the previous boundary holds the account it
//! left, and takes this boundary only from there.
//!
//! Schema 3 (owner, 2026-11-07: an offline payment needs a board on both sides,
//! and the money received lands in the receiver's own offline balance): the
//! ancestry's steps are typed (`OfflineAccountHop`). Besides spends, an account
//! moves between its boundaries by its own board's receive commits, into what it
//! holds received, and by the unload of a received payment, out of it
//! ([`crate::types::offline_chain::verify_account_hops`]). A receive brings no
//! money a contact takes on its word: the money leaves only by its unload, which
//! is checked against the payer's own history. An account's first boundary may
//! come after receives, and still after no spend.

use crate::ccb::decode::{Cursor, DecodeError};
use crate::ccb::{
    class, push_absent, push_bytes, push_digest32, push_envelope, push_present, push_u32, push_u64,
    CcbError, CcbObject,
};
use crate::common::domain_tags::{
    TAG_DSM_ECONOMIC_OFFLINE_BOUNDARY_EVIDENCE, TAG_DSM_ECONOMIC_OPERATION_DIGEST_OFFLINE_BOUNDARY,
    TAG_DSM_ECONOMIC_OPERATION_ID_OFFLINE_SETTLEMENT, TAG_DSM_ECON_SOURCE_OFFLINE_BOUNDARY_DEBIT,
};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::merkle::batch_fold::{fold_path, FOLD_HEIGHT};
use crate::merkle::smt_path::{self, EncodedPath, HEIGHT_SET_BYTES};
use crate::merkle::sparse_merkle_tree::DeviceSmtHashes;
use crate::types::device_state::{OfflineBoundaryId, OfflineBoundaryKind, OfflineBoundaryOutcome};
use crate::types::error::DsmError;
use crate::types::offline_account::{
    offline_account_leaf_key, verify_step, OfflineAccountStep, StepBefore,
};

/// Envelope of a load body.
struct LoadBody;
impl CcbObject for LoadBody {
    const CLASS: u16 = class::OFFLINE_LOAD_BOUNDARY_BODY;
    const SCHEMA: u16 = 5;
}

/// Envelope of an unload body.
struct UnloadBody;
impl CcbObject for UnloadBody {
    const CLASS: u16 = class::OFFLINE_UNLOAD_BOUNDARY_BODY;
    const SCHEMA: u16 = 5;
}

/// The anchor an offline account belongs to, as its bundle `B` commits it:
/// the keys its spends are signed under, its enrolled counter and its birth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryAnchor {
    pub anchor_id: [u8; 32],
    /// `pk_chip`, which verifies `σ^chip`.
    pub pk_chip: Vec<u8>,
    /// `pk_host`, which verifies `σ^host`.
    pub pk_host: Vec<u8>,
    /// `H₀`.
    pub enrolled_counter: u64,
    /// `S_birth`.
    pub birth_commitment: [u8; 32],
}

/// Where an offline account stood since its last boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundarySince {
    /// The account's first boundary: it was opened empty, at this frontier
    /// and counter. An account opens at its board's origin (counter zero),
    /// or, for a wallet upgraded in place from 0.1.0-beta.4, empty at the
    /// counter its board already stood at (owner, 2026-11-15: "Change Core
    /// tonight"); nothing before that counter is spendable from it.
    Opened { frontier: [u8; 32], counter: u64 },
    /// The account the previous boundary left.
    Previous { account_root: [u8; 32] },
}

/// What a boundary exposes of its account: its anchor, where it stood since
/// its last boundary, and the spends since (each an `OfflineSpendHop`'s
/// canonical bytes), in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryAncestry {
    pub anchor: BoundaryAnchor,
    pub since: BoundarySince,
    pub chain: Vec<Vec<u8>>,
}

/// The body of one offline boundary, its class saying which way it moves value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineBoundaryBody {
    pub kind: OfflineBoundaryKind,
    /// The enrolled anchor bundle whose offline account the boundary moves.
    pub bundle: [u8; 32],
    pub asset: [u8; 32],
    pub amount: u64,
    /// The device root the boundary starts from.
    pub pre_device_root: [u8; 32],
    /// The offline account's root before the boundary.
    pub pre_account_root: [u8; 32],
    /// The account's allocation of `asset` before, if it held one.
    pub pre_allocation: Option<u64>,
    /// The account's funding chain before, if a boundary had funded it.
    pub pre_funding_chain: Option<[u8; 32]>,
    /// The account's counter and frontier before: where its board stood.
    pub pre_counter: u64,
    pub pre_frontier: [u8; 32],
    /// The frontier the board advanced to when it signed the boundary.
    pub next_frontier: [u8; 32],
    /// The board's release of the boundary (a `dsm.anchor.OfflineRelease`, its
    /// offline-state proofs attached): the load or unload signed at the board's
    /// next counter, as a spend is (DSM Amendment A39 draft, option B).
    pub release: Vec<u8>,
    /// The account paths of the leaves the boundary writes, in key order.
    pub account_paths: Vec<EncodedPath>,
    /// The device path of the account's leaf against `pre_device_root`.
    pub device_path: EncodedPath,
    /// The account's ancestry since its last boundary.
    pub ancestry: BoundaryAncestry,
}

/// What a verifier established of one offline boundary. Built only by
/// [`OfflineBoundaryBody::verify`]: every root in it was folded, and the
/// identity and digest were hashed, by the verifier itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedOfflineBoundary {
    kind: OfflineBoundaryKind,
    bundle: [u8; 32],
    asset: [u8; 32],
    amount: u64,
    operation_id: [u8; 32],
    operation_digest: [u8; 32],
    moved: Moved,
}

/// What a verified boundary moved: an offline account (a load or an unload),
/// or, for a settlement, nothing of the device's own besides its balance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Moved {
    Account {
        pre_device_root: [u8; 32],
        post_device_root: [u8; 32],
        pre_account_root: [u8; 32],
        post_account_root: [u8; 32],
        since: BoundarySince,
        /// `M`, the root-advance message the board signed for the boundary: what
        /// holds the boundary's origin cell.
        departure: [u8; 32],
    },
    Settlement,
}

impl VerifiedOfflineBoundary {
    pub fn kind(&self) -> OfflineBoundaryKind {
        self.kind
    }
    /// `M`, the root-advance message the account's board signed for the
    /// boundary: the step that holds the origin cell of the root it starts
    /// from. `None` for a settlement, which moves no offline account.
    pub fn departure(&self) -> Option<[u8; 32]> {
        match self.moved {
            Moved::Account { departure, .. } => Some(departure),
            Moved::Settlement => None,
        }
    }
    pub fn bundle(&self) -> [u8; 32] {
        self.bundle
    }
    pub fn asset(&self) -> [u8; 32] {
        self.asset
    }
    pub fn amount(&self) -> u64 {
        self.amount
    }
    /// The boundary's economic operation id, the account's funding chain after it.
    pub fn operation_id(&self) -> [u8; 32] {
        self.operation_id
    }
    /// The digest of the exact body bytes.
    pub fn operation_digest(&self) -> [u8; 32] {
        self.operation_digest
    }
    /// The device root the boundary starts from; `None` for a settlement.
    pub fn pre_device_root(&self) -> Option<[u8; 32]> {
        match self.moved {
            Moved::Account {
                pre_device_root, ..
            } => Some(pre_device_root),
            Moved::Settlement => None,
        }
    }
    /// The device root the boundary leaves; `None` for a settlement.
    pub fn post_device_root(&self) -> Option<[u8; 32]> {
        match self.moved {
            Moved::Account {
                post_device_root, ..
            } => Some(post_device_root),
            Moved::Settlement => None,
        }
    }
    /// The offline account the boundary starts from; `None` for a settlement.
    pub fn pre_account_root(&self) -> Option<[u8; 32]> {
        match self.moved {
            Moved::Account {
                pre_account_root, ..
            } => Some(pre_account_root),
            Moved::Settlement => None,
        }
    }
    /// The offline account the boundary leaves; `None` for a settlement.
    pub fn post_account_root(&self) -> Option<[u8; 32]> {
        match self.moved {
            Moved::Account {
                post_account_root, ..
            } => Some(post_account_root),
            Moved::Settlement => None,
        }
    }
    /// Where the account stood since its last boundary, verified to lead, by
    /// the boundary's chain of spends, to the account it starts from; `None`
    /// for a settlement.
    pub fn since(&self) -> Option<BoundarySince> {
        match self.moved {
            Moved::Account { since, .. } => Some(since),
            Moved::Settlement => None,
        }
    }
}

/// The immutable-store address of exact boundary body bytes — what the
/// manifest's offline-boundary substrate slot names.
pub fn offline_boundary_evidence_addr(body_bytes: &[u8]) -> [u8; 32] {
    crate::storage_object::immutable_inner(TAG_DSM_ECONOMIC_OFFLINE_BOUNDARY_EVIDENCE, body_bytes)
}

/// `operation_digest = H(DSM/economic-operation-digest/offline-boundary/v1 ‖
/// exact body bytes)`: what the witness and the accepted substrate both bind.
pub fn offline_boundary_operation_digest(body_bytes: &[u8]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_ECONOMIC_OPERATION_DIGEST_OFFLINE_BOUNDARY);
    h.update(body_bytes);
    *h.finalize().as_bytes()
}

/// The source an unload's online credit consumes:
/// `H(DSM/econ-source/offline-boundary-debit/v1 ‖ G ‖ DevID ‖ boundary id)`.
/// Derived from the boundary's own identity, which no other boundary has, so
/// the offline debit it names is consumed once.
pub fn offline_boundary_debit_source_id(
    genesis: &[u8; 32],
    device_id: &[u8; 32],
    boundary_id: &[u8; 32],
) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_ECON_SOURCE_OFFLINE_BOUNDARY_DEBIT);
    h.update(genesis);
    h.update(device_id);
    h.update(boundary_id);
    *h.finalize().as_bytes()
}

fn push_path(out: &mut Vec<u8>, path: &EncodedPath) -> Result<(), CcbError> {
    push_digest32(out, &path.explicit_heights);
    push_bytes(out, &path.siblings)
}

fn read_path(c: &mut Cursor<'_>) -> Result<EncodedPath, DecodeError> {
    let explicit_heights: [u8; HEIGHT_SET_BYTES] = c.digest32()?;
    let len = c.u32()? as usize;
    let siblings = c.take(len)?.to_vec();
    Ok(EncodedPath {
        explicit_heights,
        siblings,
    })
}

fn decode_path(path: &EncodedPath) -> Result<Box<[[u8; 32]; FOLD_HEIGHT]>, DsmError> {
    smt_path::decode::<DeviceSmtHashes>(&path.explicit_heights, &path.siblings)
        .map_err(|e| DsmError::invalid_operation(format!("an offline boundary's path: {e}")))
}

impl OfflineBoundaryBody {
    /// The body of a boundary Core took: everything a verifier needs to fold
    /// it again, read off the outcome.
    pub fn of(
        outcome: &OfflineBoundaryOutcome,
        kind: OfflineBoundaryKind,
        bundle: [u8; 32],
        asset: [u8; 32],
        amount: u64,
        ancestry: BoundaryAncestry,
        release: Vec<u8>,
    ) -> Result<Self, DsmError> {
        let StepBefore::Boundary {
            allocation,
            funding_chain,
            counter,
            frontier,
        } = outcome.account_move.before
        else {
            return Err(DsmError::invalid_operation(
                "a boundary body is taken of a boundary step",
            ));
        };
        let device_write = match outcome.device_writes.as_slice() {
            [write] => write,
            writes => {
                return Err(DsmError::invalid_operation(format!(
                    "a boundary writes the one account leaf of the device, not {}",
                    writes.len()
                )))
            }
        };
        Ok(Self {
            kind,
            bundle,
            asset,
            amount,
            pre_device_root: outcome.pre_device_root,
            pre_account_root: outcome.pre_account_root,
            pre_allocation: allocation,
            pre_funding_chain: funding_chain,
            pre_counter: counter,
            pre_frontier: frontier,
            next_frontier: outcome.account_move.account.frontier(),
            release,
            account_paths: outcome
                .account_move
                .entries
                .iter()
                .map(|e| smt_path::encode::<DeviceSmtHashes>(&e.path))
                .collect(),
            device_path: smt_path::encode::<DeviceSmtHashes>(&device_write.path),
            ancestry,
        })
    }

    /// The body's canonical bytes, fields in registry order.
    pub fn encode(&self) -> Result<Vec<u8>, CcbError> {
        let mut out = Vec::new();
        match self.kind {
            OfflineBoundaryKind::Load => push_envelope::<LoadBody>(&mut out),
            OfflineBoundaryKind::Unload => push_envelope::<UnloadBody>(&mut out),
            OfflineBoundaryKind::Settle => return Err(CcbError::NotAnOfflineAccountBoundary),
        }
        push_digest32(&mut out, &self.bundle); // 1
        push_digest32(&mut out, &self.asset); // 2
        push_u64(&mut out, self.amount); // 3
        push_digest32(&mut out, &self.pre_device_root); // 4
        push_digest32(&mut out, &self.pre_account_root); // 5
        match self.pre_allocation {
            // 6
            Some(amount) => {
                push_present(&mut out);
                push_u64(&mut out, amount);
            }
            None => push_absent(&mut out),
        }
        match &self.pre_funding_chain {
            // 7
            Some(chain) => {
                push_present(&mut out);
                push_digest32(&mut out, chain);
            }
            None => push_absent(&mut out),
        }
        push_u64(&mut out, self.pre_counter); // 8
        push_digest32(&mut out, &self.pre_frontier); // 9
        push_digest32(&mut out, &self.next_frontier); // 10
        push_bytes(&mut out, &self.release)?; // 11
                                              // 12: a boundary writes exactly four account leaves — its allocation,
                                              // the funding chain, the counter and the frontier — so four paths, in
                                              // key order.
        if self.account_paths.len() != BOUNDARY_WRITES {
            return Err(CcbError::FixedLength {
                field: "account_paths",
                expected: BOUNDARY_WRITES,
                got: self.account_paths.len(),
            });
        }
        for path in &self.account_paths {
            push_path(&mut out, path)?;
        }
        push_path(&mut out, &self.device_path)?; // 13
        let anchor = &self.ancestry.anchor;
        push_digest32(&mut out, &anchor.anchor_id); // 14
        push_bytes(&mut out, &anchor.pk_chip)?; // 15
        push_bytes(&mut out, &anchor.pk_host)?; // 16
        push_u64(&mut out, anchor.enrolled_counter); // 17
        push_digest32(&mut out, &anchor.birth_commitment); // 18
        match &self.ancestry.since {
            // 19
            BoundarySince::Opened { frontier, counter } => {
                out.push(SINCE_OPENED);
                push_digest32(&mut out, frontier);
                push_u64(&mut out, *counter);
            }
            BoundarySince::Previous { account_root } => {
                out.push(SINCE_PREVIOUS);
                push_digest32(&mut out, account_root);
            }
        }
        // 20: the steps since, each its canonical `OfflineAccountHop` bytes.
        if self.ancestry.chain.len() > crate::types::offline_chain::MAX_CHAIN_HOPS {
            return Err(CcbError::FixedLength {
                field: "chain",
                expected: crate::types::offline_chain::MAX_CHAIN_HOPS,
                got: self.ancestry.chain.len(),
            });
        }
        push_u32(&mut out, self.ancestry.chain.len() as u32);
        for hop in &self.ancestry.chain {
            push_bytes(&mut out, hop)?;
        }
        Ok(out)
    }

    /// Decode a body, strictly: its class, its live schema, every field, nothing after.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        let kind = match c.peek_class()? {
            class::OFFLINE_LOAD_BOUNDARY_BODY => {
                c.envelope(LoadBody::CLASS, LoadBody::SCHEMA)?;
                OfflineBoundaryKind::Load
            }
            class::OFFLINE_UNLOAD_BOUNDARY_BODY => {
                c.envelope(UnloadBody::CLASS, UnloadBody::SCHEMA)?;
                OfflineBoundaryKind::Unload
            }
            got => return Err(DecodeError::WrongClass { got }),
        };
        let bundle = c.digest32()?;
        let asset = c.digest32()?;
        let amount = c.u64()?;
        let pre_device_root = c.digest32()?;
        let pre_account_root = c.digest32()?;
        let pre_allocation = match c.u8()? {
            0x00 => None,
            0x01 => Some(c.u64()?),
            got => return Err(DecodeError::Invalid(format!("presence marker {got}"))),
        };
        let pre_funding_chain = match c.u8()? {
            0x00 => None,
            0x01 => Some(c.digest32()?),
            got => return Err(DecodeError::Invalid(format!("presence marker {got}"))),
        };
        let pre_counter = c.u64()?;
        let pre_frontier = c.digest32()?;
        let next_frontier = c.digest32()?;
        let release = read_bytes(&mut c)?;
        // A boundary writes four account leaves: its allocation, the chain, the
        // counter and the frontier.
        let account_paths = (0..BOUNDARY_WRITES)
            .map(|_| read_path(&mut c))
            .collect::<Result<Vec<_>, _>>()?;
        let device_path = read_path(&mut c)?;
        let anchor_id = c.digest32()?;
        let pk_chip = read_bytes(&mut c)?;
        let pk_host = read_bytes(&mut c)?;
        let enrolled_counter = c.u64()?;
        let birth_commitment = c.digest32()?;
        let since = match c.u8()? {
            SINCE_OPENED => BoundarySince::Opened {
                frontier: c.digest32()?,
                counter: c.u64()?,
            },
            SINCE_PREVIOUS => BoundarySince::Previous {
                account_root: c.digest32()?,
            },
            got => return Err(DecodeError::Invalid(format!("an ancestry marker {got}"))),
        };
        let count = c.u32()? as usize;
        if count > crate::types::offline_chain::MAX_CHAIN_HOPS {
            return Err(DecodeError::Invalid(format!(
                "a chain of {count} spends; at most {} are carried",
                crate::types::offline_chain::MAX_CHAIN_HOPS
            )));
        }
        let chain = (0..count)
            .map(|_| read_bytes(&mut c))
            .collect::<Result<Vec<_>, _>>()?;
        if c.i != bytes.len() {
            return Err(DecodeError::TrailingBytes {
                extra: bytes.len() - c.i,
            });
        }
        Ok(Self {
            kind,
            bundle,
            asset,
            amount,
            pre_device_root,
            pre_account_root,
            pre_allocation,
            pre_funding_chain,
            pre_counter,
            pre_frontier,
            next_frontier,
            release,
            account_paths,
            device_path,
            ancestry: BoundaryAncestry {
                anchor: BoundaryAnchor {
                    anchor_id,
                    pk_chip,
                    pk_host,
                    enrolled_counter,
                    birth_commitment,
                },
                since,
                chain,
            },
        })
    }

    /// Verify the body at `body_bytes` as a boundary of the device
    /// `(genesis, device_id)` — the authenticated identity whose lineage it is
    /// admitted on, never taken from the body.
    ///
    /// The account step is folded from the account root the body states with
    /// the step's own pre-values and paths; the account's leaf is folded into
    /// the device root the body states and, with the account's new root, into
    /// the device root after. A misstated value folds to another root and is
    /// refused.
    ///
    /// Its ancestry is verified too: `B` recomputes from the anchor the body
    /// names, the owner's online key `owner_key`, its device id and the
    /// offline-bearer policy; and the spends since the last boundary lead, hop
    /// by hop, from where the account stood to the account the boundary starts
    /// from — at the account's first boundary, from the account opened empty,
    /// with no spends. Answers the payments the chain exposes beside the
    /// verified boundary.
    pub fn verify(
        body_bytes: &[u8],
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        owner_key: &[u8],
    ) -> Result<
        (
            VerifiedOfflineBoundary,
            Vec<crate::types::offline_chain::ChainPayment>,
        ),
        DsmError,
    > {
        let body = Self::decode(body_bytes)
            .map_err(|e| DsmError::invalid_operation(format!("an offline boundary body: {e}")))?;
        let payments = verify_ancestry(&body, device_id, owner_key)?;
        let verified = verify_boundary_step(&body, body_bytes, genesis, device_id)?;
        Ok((verified, payments))
    }

    /// Verify the body at `body_bytes` as the departure of a boundary of the
    /// device `(genesis, device_id)` from the root it starts from (DSM Amendment
    /// A39 draft): the boundary with no steps carried, as its origin cell holds
    /// it. `B` recomputes from the anchor it names and the owner's online key
    /// `owner_key`; the account step folds; the board signed it. The steps
    /// since the last boundary are each at their own cell.
    pub fn verify_departure(
        body_bytes: &[u8],
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        owner_key: &[u8],
    ) -> Result<VerifiedOfflineBoundary, DsmError> {
        let body = Self::decode(body_bytes)
            .map_err(|e| DsmError::invalid_operation(format!("an offline boundary body: {e}")))?;
        if !body.ancestry.chain.is_empty() {
            return Err(DsmError::invalid_operation(
                "a boundary's departure carries no steps: each is at its own cell",
            ));
        }
        require_anchor_of(&body, device_id, owner_key)?;
        verify_boundary_step(&body, body_bytes, genesis, device_id)
    }

    /// The boundary as its departure: the same boundary with no steps carried.
    pub fn departure(&self) -> Self {
        Self {
            ancestry: BoundaryAncestry {
                chain: Vec::new(),
                ..self.ancestry.clone()
            },
            ..self.clone()
        }
    }
}

/// The account step of a boundary folded, its device leaf folded, and the
/// board's release of it checked: what a boundary is, whether or not the steps
/// since the last boundary are carried with it.
fn verify_boundary_step(
    body: &OfflineBoundaryBody,
    body_bytes: &[u8],
    genesis: &[u8; 32],
    device_id: &[u8; 32],
) -> Result<VerifiedOfflineBoundary, DsmError> {
    let operation_id = OfflineBoundaryId {
        genesis: *genesis,
        device_id: *device_id,
        kind: body.kind,
        bundle: body.bundle,
        asset: body.asset,
        amount: body.amount,
        pre_device_root: body.pre_device_root,
        pre_account_root: body.pre_account_root,
    }
    .operation_id();
    let step = match body.kind {
        OfflineBoundaryKind::Load => OfflineAccountStep::Load {
            asset: body.asset,
            amount: body.amount,
            boundary_id: operation_id,
            next_frontier: body.next_frontier,
        },
        OfflineBoundaryKind::Unload => OfflineAccountStep::Unload {
            asset: body.asset,
            amount: body.amount,
            boundary_id: operation_id,
            next_frontier: body.next_frontier,
        },
        OfflineBoundaryKind::Settle => {
            return Err(DsmError::invalid_operation(
                "an offline boundary body is a load or an unload of the device's own account",
            ))
        }
    };
    let paths = body
        .account_paths
        .iter()
        .map(decode_path)
        .collect::<Result<Vec<_>, _>>()?;
    let post_account_root = verify_step(
        &body.pre_account_root,
        &step,
        &StepBefore::Boundary {
            allocation: body.pre_allocation,
            funding_chain: body.pre_funding_chain,
            counter: body.pre_counter,
            frontier: body.pre_frontier,
        },
        &paths,
    )?;
    let device_path = decode_path(&body.device_path)?;
    let key = offline_account_leaf_key(&body.bundle);
    if fold_path::<DeviceSmtHashes>(&key, Some(&body.pre_account_root), &device_path)
        != body.pre_device_root
    {
        return Err(DsmError::invalid_operation(
            "the boundary's device root does not commit the offline account it states",
        ));
    }
    let post_device_root =
        fold_path::<DeviceSmtHashes>(&key, Some(&post_account_root), &device_path);
    // The board signed this very boundary, at its next counter, from where the
    // account stood, after every step since the last boundary (DSM Amendment A39
    // draft, option B).
    {
        let departure = verify_boundary_release(
            body,
            device_id,
            &operation_id,
            &post_device_root,
            &post_account_root,
        )?;
        let verified = VerifiedOfflineBoundary {
            kind: body.kind,
            bundle: body.bundle,
            asset: body.asset,
            amount: body.amount,
            operation_id,
            operation_digest: offline_boundary_operation_digest(body_bytes),
            moved: Moved::Account {
                pre_device_root: body.pre_device_root,
                post_device_root,
                pre_account_root: body.pre_account_root,
                post_account_root,
                since: body.ancestry.since,
                departure,
            },
        };
        Ok(verified)
    }
}

/// Envelope of a settlement body.
struct SettlementBody;
impl CcbObject for SettlementBody {
    const CLASS: u16 = class::OFFLINE_SETTLEMENT_BODY;
    const SCHEMA: u16 = 3;
}

/// The body of an offline settlement (SA-91; DSM Amendment A39 draft): a
/// receiver's admission of value it received offline. It names the payer's
/// spend by the root-advance message `M` the payer's anchor signed for it, the
/// economic position of the payer's boundary whose account the receiver
/// recorded before it took the payment, and the account root the payment's own
/// step starts from. The payment is proved from the payer's origin cells, from
/// that account to the payment, each final: the payer is never needed. Its
/// credit is funded by that spend and consumed once: the settlement's identity
/// is `H(G ‖ DevID ‖ G_payer ‖ DevID_payer ‖ M)`, one per receiver and spend,
/// and the source it consumes is derived from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineSettlementBody {
    pub payer_genesis: [u8; 32],
    pub payer_device: [u8; 32],
    /// The economic position of the payer's boundary whose account the
    /// payment's history starts from.
    pub boundary_position: u64,
    /// The account root the payment's own step starts from: the last cell of
    /// the path.
    pub payment_root: [u8; 32],
    /// `M`, the root-advance message the payer's anchor signed for the spend.
    pub release_message: [u8; 32],
    /// The payer's anchor bundle.
    pub bundle: [u8; 32],
    pub asset: [u8; 32],
    pub amount: u64,
    /// The bearer transfer the payment was, as the receiver accepted it: its
    /// canonical bytes, which re-hash to the `payload_hash` the payer's anchor
    /// signed. They name the recipient's lineage (SA-133).
    pub payment_operation: Vec<u8>,
}

impl OfflineSettlementBody {
    /// The body's canonical bytes, fields in registry order.
    pub fn encode(&self) -> Result<Vec<u8>, CcbError> {
        let mut out = Vec::new();
        push_envelope::<SettlementBody>(&mut out);
        push_digest32(&mut out, &self.payer_genesis); // 1
        push_digest32(&mut out, &self.payer_device); // 2
        push_u64(&mut out, self.boundary_position); // 3
        push_digest32(&mut out, &self.payment_root); // 4
        push_digest32(&mut out, &self.release_message); // 5
        push_digest32(&mut out, &self.bundle); // 6
        push_digest32(&mut out, &self.asset); // 7
        push_u64(&mut out, self.amount); // 8
        push_bytes(&mut out, &self.payment_operation)?; // 9
        Ok(out)
    }

    /// Decode a body, strictly: its class, schema 3, every field, nothing after.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        c.envelope(SettlementBody::CLASS, SettlementBody::SCHEMA)?;
        let body = Self {
            payer_genesis: c.digest32()?,
            payer_device: c.digest32()?,
            boundary_position: c.u64()?,
            payment_root: c.digest32()?,
            release_message: c.digest32()?,
            bundle: c.digest32()?,
            asset: c.digest32()?,
            amount: c.u64()?,
            payment_operation: read_bytes(&mut c)?,
        };
        if c.i != bytes.len() {
            return Err(DecodeError::TrailingBytes {
                extra: bytes.len() - c.i,
            });
        }
        Ok(body)
    }

    /// The settlement's identity: the receiver's one settlement of this spend.
    pub fn operation_id(&self, genesis: &[u8; 32], device_id: &[u8; 32]) -> [u8; 32] {
        settlement_id(
            genesis,
            device_id,
            &self.payer_genesis,
            &self.payer_device,
            &self.release_message,
        )
    }

    /// Verify the body at `body_bytes` as a settlement of the device
    /// `(genesis, device_id)`. `start` is the account the payer's boundary at
    /// `boundary_position` left, as a check of the payer this verifier ran or
    /// recorded found it, and `reads` the payer's origin cells from it through
    /// the cell of `payment_root`. The cells must hold, each final, the one
    /// history from `start` to the payment `M`; the payment must be to this
    /// device, of the body's asset and amount, and the bearer transfer the
    /// payer's anchor signed.
    pub fn verify(
        body_bytes: &[u8],
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        start: &[u8; 32],
        reads: &[crate::offline_origin::OriginRead],
    ) -> Result<VerifiedOfflineBoundary, DsmError> {
        let body = Self::decode(body_bytes)
            .map_err(|e| DsmError::invalid_operation(format!("an offline settlement body: {e}")))?;
        match reads.last() {
            Some(last)
                if *last.key()
                    == crate::offline_origin::origin_key(&body.bundle, &body.payment_root) => {}
            Some(..) | None => {
                return Err(DsmError::invalid_operation(
                    "the settlement's path does not end at the cell its payment starts from",
                ))
            }
        }
        let payment = crate::offline_origin::payment_at_cells(
            &body.bundle,
            start,
            reads,
            &body.release_message,
        )?;
        if payment.recipient != *device_id {
            return Err(DsmError::invalid_operation(
                "the payment the payer's cells hold is not to the device that settles it",
            ));
        }
        if payment.asset != body.asset || payment.amount != body.amount {
            return Err(DsmError::invalid_operation(
                "the settlement does not name the payment the payer's cells hold",
            ));
        }
        // The payment was the bearer transfer the anchor signed, to this
        // lineage: its bytes re-hash to the spend's payload hash, and it names
        // this device and this genesis, the asset and the amount. A device id
        // alone names no one lineage (SA-133).
        if crate::types::operations::bearer_payload_hash(&body.payment_operation)
            != payment.payload_hash
        {
            return Err(DsmError::invalid_operation(
                "the settlement's payment is not the transfer the payer's anchor signed",
            ));
        }
        match crate::types::operations::Operation::from_bytes(&body.payment_operation) {
            Ok(crate::types::operations::Operation::Transfer {
                to_device_id,
                to_genesis,
                amount,
                policy_commit,
                authority_policy: Some(..),
                ..
            }) if to_device_id.as_slice() == device_id.as_slice()
                && to_genesis == *genesis
                && amount.value() == body.amount
                && policy_commit == body.asset => {}
            Ok(..) => {
                return Err(DsmError::invalid_operation(
                    "the payment the anchor signed is not a bearer transfer to this lineage of \
                     this asset and amount",
                ))
            }
            Err(e) => {
                return Err(DsmError::invalid_operation(format!(
                    "the settlement's payment does not decode: {e}"
                )))
            }
        }
        Ok(VerifiedOfflineBoundary {
            kind: OfflineBoundaryKind::Settle,
            bundle: body.bundle,
            asset: body.asset,
            amount: body.amount,
            operation_id: body.operation_id(genesis, device_id),
            operation_digest: offline_boundary_operation_digest(body_bytes),
            moved: Moved::Settlement,
        })
    }
}

/// The identity of the receiver `(genesis, device_id)`'s one settlement — the unload of the payment it
/// received offline — of the spend the payer's anchor signed as `release_message`:
/// `H(G ‖ DevID ‖ G_payer ‖ DevID_payer ‖ M)`.
pub fn settlement_id(
    genesis: &[u8; 32],
    device_id: &[u8; 32],
    payer_genesis: &[u8; 32],
    payer_device: &[u8; 32],
    release_message: &[u8; 32],
) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_ECONOMIC_OPERATION_ID_OFFLINE_SETTLEMENT);
    h.update(genesis);
    h.update(device_id);
    h.update(payer_genesis);
    h.update(payer_device);
    h.update(release_message);
    *h.finalize().as_bytes()
}

/// Which body an offline substrate's bytes hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineBodyKind {
    /// A load or an unload of the device's own offline account.
    Boundary,
    /// A settlement of value the device received offline.
    Settlement,
}

/// The kind of offline body `bytes` hold, by their CCB class.
pub fn offline_body_kind(bytes: &[u8]) -> Result<OfflineBodyKind, DsmError> {
    let c = Cursor { b: bytes, i: 0 };
    match c
        .peek_class()
        .map_err(|e| DsmError::invalid_operation(format!("an offline body: {e}")))?
    {
        class::OFFLINE_LOAD_BOUNDARY_BODY | class::OFFLINE_UNLOAD_BOUNDARY_BODY => {
            Ok(OfflineBodyKind::Boundary)
        }
        class::OFFLINE_SETTLEMENT_BODY => Ok(OfflineBodyKind::Settlement),
        got => Err(DsmError::invalid_operation(format!(
            "an offline body of class {got:#06x}, which is none"
        ))),
    }
}

/// The ancestry marker of an account's first boundary.
const SINCE_OPENED: u8 = 0x01;
/// That the board of the account signed this boundary: its release is the
/// board's signed advance of exactly the transition [`boundary_transition`]
/// builds for it — this kind, from the account's frontier and counter, to its own
/// device, its payload the boundary's operation id — under the keys the anchor
/// the body names commits, and its device roots before and after commit the
/// account before and after the boundary, at the counter's step and the advanced
/// frontier. Answers `M`, which names the boundary at its origin cell.
///
/// [`boundary_transition`]: crate::types::offline_chain::boundary_transition
fn verify_boundary_release(
    body: &OfflineBoundaryBody,
    device_id: &[u8; 32],
    operation_id: &[u8; 32],
    post_device_root: &[u8; 32],
    post_account_root: &[u8; 32],
) -> Result<[u8; 32], DsmError> {
    use crate::types::offline_account::verify_offline_state_at;
    use crate::types::offline_chain::{boundary_transition, Ed25519Chip, SphincsHost};
    use anchor_core::accept::verify_cert_frontier_and_sigs;
    use anchor_core::root_advance::transition_digest;
    use prost::Message;
    let refused =
        |why: &str| DsmError::invalid_operation(format!("the boundary's board release: {why}"));
    let release = anchor_core::proto::pb::OfflineRelease::decode(body.release.as_slice())
        .map_err(|e| refused(&e.to_string()))?
        .to_release()
        .map_err(|e| refused(&format!("{e:?}")))?;
    let (expected, challenge) = boundary_transition(
        body.kind,
        device_id,
        operation_id,
        &body.pre_frontier,
        body.pre_counter,
    )?;
    let cert = &release.cert;
    if anchor_core::root_advance::enc_transition(&release.transition.as_transition())
        != anchor_core::root_advance::enc_transition(&expected.as_transition())
    {
        return Err(refused("it is not the transition of this boundary"));
    }
    if cert.anchor_bundle != body.bundle || cert.anchor_id != body.ancestry.anchor.anchor_id {
        return Err(refused("it is not the account's own board's"));
    }
    if cert.receiver_challenge != challenge
        || cert.recipient != *device_id
        || cert.prev_frontier != body.pre_frontier
        || cert.next_frontier != expected.next_root
        || cert.next_frontier != body.next_frontier
        || cert.anchor_counter != body.pre_counter
        || cert.next_anchor_counter != expected.next_anchor_counter
        || transition_digest(&expected.as_transition(), &challenge) != cert.transition_digest
    {
        return Err(refused(
            "its certificate does not sign this boundary's advance",
        ));
    }
    verify_cert_frontier_and_sigs::<Ed25519Chip, SphincsHost>(
        cert,
        &body.ancestry.anchor.pk_chip,
        &body.ancestry.anchor.pk_host,
    )
    .map_err(|e| refused(&format!("the board did not sign it: {e:?}")))?;
    if cert.sender_device_root_before != body.pre_device_root
        || cert.sender_device_root_after != *post_device_root
    {
        return Err(refused("its device roots are not the boundary's"));
    }
    let before = verify_offline_state_at(
        &cert.sender_device_root_before,
        &body.bundle,
        &cert.prev_frontier,
        cert.anchor_counter,
        &release.offline_state_proof_before,
    )
    .map_err(|e| refused(&format!("its device root before: {e}")))?;
    let after = verify_offline_state_at(
        &cert.sender_device_root_after,
        &body.bundle,
        &cert.next_frontier,
        cert.next_anchor_counter,
        &release.offline_state_proof_after,
    )
    .map_err(|e| refused(&format!("its device root after: {e}")))?;
    if before != body.pre_account_root || after != *post_account_root {
        return Err(refused(
            "its device roots do not commit the account before and after the boundary",
        ));
    }
    Ok(cert.root_advance_message)
}

/// The account leaves a load or an unload writes: its allocation, the funding
/// chain, the counter and the frontier.
const BOUNDARY_WRITES: usize = 4;

/// The ancestry marker of a boundary after the first.
const SINCE_PREVIOUS: u8 = 0x02;

fn read_bytes(c: &mut Cursor<'_>) -> Result<Vec<u8>, DecodeError> {
    let len = c.u32()? as usize;
    Ok(c.take(len)?.to_vec())
}

/// That `B` recomputes from the anchor `body` names, the owner's online key
/// `owner_key`, its device id and the offline-bearer policy.
fn require_anchor_of(
    body: &OfflineBoundaryBody,
    device_id: &[u8; 32],
    owner_key: &[u8],
) -> Result<(), DsmError> {
    let anchor = &body.ancestry.anchor;
    crate::crypto::anchor_enrollment::require_bundle_of(
        crate::crypto::anchor_enrollment::PinKeys {
            bundle: &body.bundle,
            anchor_id: &anchor.anchor_id,
            pk_chip: &anchor.pk_chip,
            partition_pk: &anchor.pk_host,
            enrolled_counter: anchor.enrolled_counter,
        },
        crate::crypto::anchor_enrollment::BundleOwner {
            online_key: owner_key,
            device_id,
            policy: &crate::types::operations::canonical_offline_bearer_policy().policy_id,
            birth_commitment: &anchor.birth_commitment,
        },
    )
}

/// The account's ancestry since its last boundary, verified against `body`.
fn verify_ancestry(
    body: &OfflineBoundaryBody,
    device_id: &[u8; 32],
    owner_key: &[u8],
) -> Result<Vec<crate::types::offline_chain::ChainPayment>, DsmError> {
    use crate::types::offline_chain::{verify_account_hops, ChainAnchor};
    let anchor = &body.ancestry.anchor;
    require_anchor_of(body, device_id, owner_key)?;
    let hops = body
        .ancestry
        .chain
        .iter()
        .map(|hop| crate::types::offline_chain::AccountHop::from_bytes(hop))
        .collect::<Result<Vec<_>, DsmError>>()?;
    // An account's first boundary starts from the account opened empty, at the frontier and counter
    // it opened at. Nothing can be spent before a load funds it, but its board may have received
    // offline since it opened (owner, 2026-11-07).
    let start = match (&body.ancestry.since, body.pre_funding_chain) {
        (BoundarySince::Opened { frontier, counter }, None) => {
            crate::types::offline_account::OfflineAccount::open(*frontier, *counter).root()
        }
        (BoundarySince::Previous { account_root }, Some(_)) => *account_root,
        (BoundarySince::Opened { .. }, Some(_)) => return Err(DsmError::invalid_operation(
            "an offline account's first boundary starts from the account opened empty, and names \
                 no boundary before it",
        )),
        (BoundarySince::Previous { .. }, None) => {
            return Err(DsmError::invalid_operation(
                "a boundary after an account's first names the boundary before it",
            ))
        }
    };
    let chain_anchor = ChainAnchor {
        bundle: body.bundle,
        anchor_id: anchor.anchor_id,
        pk_chip: anchor.pk_chip.clone(),
        pk_host: anchor.pk_host.clone(),
    };
    let (payments, end) = verify_account_hops(&start, &chain_anchor, device_id, &hops)?;
    if end != body.pre_account_root {
        return Err(DsmError::invalid_operation(
            "the boundary's account is not the one its steps since the last boundary leave",
        ));
    }
    Ok(payments)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ASSET: [u8; 32] = [0xA1; 32];
    const OPENED: [u8; 32] = [0x01; 32];

    use crate::types::offline_chain::fixture::Payer;

    /// The anchor `p`'s account belongs to, as a boundary body names it.
    fn anchor_of(p: &Payer) -> BoundaryAnchor {
        BoundaryAnchor {
            anchor_id: p.pin.anchor_id,
            pk_chip: p.pin.pk_chip.clone(),
            pk_host: p.pin.pk_host.clone(),
            enrolled_counter: u64::from(p.enrolled_counter),
            birth_commitment: p.birth_commitment,
        }
    }

    /// Where `p`'s account stands: its counter and frontier.
    fn standing(p: &Payer) -> (u64, [u8; 32]) {
        let account = p
            .head
            .offline_account(&p.pin.bundle)
            .expect("the account is open");
        (account.counter(), account.frontier())
    }

    /// The body of the boundary `outcome` of `p`, its board's `release`, naming
    /// `since` and carrying `chain`.
    fn body_bytes(
        p: &Payer,
        outcome: &OfflineBoundaryOutcome,
        kind: OfflineBoundaryKind,
        amount: u64,
        since: BoundarySince,
        chain: Vec<Vec<u8>>,
        release: &[u8],
    ) -> Vec<u8> {
        OfflineBoundaryBody::of(
            outcome,
            kind,
            p.pin.bundle,
            p.token,
            amount,
            BoundaryAncestry {
                anchor: anchor_of(p),
                since,
                chain,
            },
            release.to_vec(),
        )
        .expect("body")
        .encode()
        .expect("encode")
    }

    /// `p`'s board signs the boundary `kind` of `amount`; its body names
    /// `since` and carries no steps. Answers the outcome, the release and the
    /// body.
    fn signed(
        p: &mut Payer,
        kind: OfflineBoundaryKind,
        amount: u64,
        since: BoundarySince,
    ) -> (OfflineBoundaryOutcome, Vec<u8>, Vec<u8>) {
        let (outcome, release) = p.boundary(kind, amount);
        let bytes = body_bytes(p, &outcome, kind, amount, since, Vec::new(), &release);
        (outcome, release, bytes)
    }

    fn verify(p: &Payer, bytes: &[u8]) -> Result<VerifiedOfflineBoundary, DsmError> {
        OfflineBoundaryBody::verify(
            bytes,
            &p.head.genesis(),
            &p.head.devid(),
            p.head.public_key(),
        )
        .map(|(verified, _)| verified)
    }

    fn refused<T: core::fmt::Debug>(result: Result<T, DsmError>, reason: &str) {
        let error = result.expect_err(reason);
        assert!(error.to_string().contains(reason), "{error}");
    }

    #[test]
    fn a_boundary_verifies_to_the_device_and_account_it_leaves() {
        let mut p = Payer::opened(0xE1);
        let (counter, frontier) = standing(&p);
        let (load, _, bytes) = signed(
            &mut p,
            OfflineBoundaryKind::Load,
            30,
            BoundarySince::Opened { frontier, counter },
        );
        let verified = verify(&p, &bytes).expect("the load verifies");
        assert_eq!(verified.operation_id(), load.operation_id);
        assert_eq!(
            verified.post_device_root(),
            Some(load.new_device_state.root())
        );
        assert_eq!(verified.post_account_root(), Some(p.account_root()));
        assert!(
            verified.departure().is_some(),
            "the board's message names it"
        );
        assert_eq!(
            OfflineBoundaryBody::decode(&bytes)
                .expect("decode")
                .encode()
                .expect("encode"),
            bytes,
            "the one encoding round-trips"
        );
        let after_load = p.account_root();
        let (unload, _, bytes) = signed(
            &mut p,
            OfflineBoundaryKind::Unload,
            12,
            BoundarySince::Previous {
                account_root: after_load,
            },
        );
        let verified = verify(&p, &bytes).expect("unload");
        assert_eq!(verified.kind(), OfflineBoundaryKind::Unload);
        assert_eq!(
            verified.post_device_root(),
            Some(unload.new_device_state.root())
        );
        assert_eq!(
            verified.since(),
            Some(BoundarySince::Previous {
                account_root: after_load
            })
        );
        assert_eq!(
            standing(&p).0,
            counter + 2,
            "each boundary moved the counter"
        );
    }

    /// A body that misstates what the account held, or names another device,
    /// another amount or another bundle, folds to another root or another
    /// identity and is refused.
    #[test]
    fn a_misstated_boundary_is_refused() {
        let mut p = Payer::opened(0xE2);
        let opened_root = p.head.root();
        let (counter, frontier) = standing(&p);
        signed(
            &mut p,
            OfflineBoundaryKind::Load,
            30,
            BoundarySince::Opened { frontier, counter },
        );
        let funded = p.account_root();
        let (_, _, bytes) = signed(
            &mut p,
            OfflineBoundaryKind::Unload,
            10,
            BoundarySince::Previous {
                account_root: funded,
            },
        );
        let honest = OfflineBoundaryBody::decode(&bytes).expect("decode");
        let check = |body: &OfflineBoundaryBody| verify(&p, &body.encode().expect("encode"));
        refused(
            check(&OfflineBoundaryBody {
                pre_allocation: Some(1_000),
                ..honest.clone()
            }),
            "the offline account step:",
        );
        refused(
            check(&OfflineBoundaryBody {
                amount: 31,
                ..honest.clone()
            }),
            "more than the offline allocation holds",
        );
        refused(
            check(&OfflineBoundaryBody {
                pre_device_root: opened_root,
                ..honest.clone()
            }),
            "does not commit the offline account",
        );
        // The same bytes under another device's identity are another boundary.
        let other = OfflineBoundaryBody::verify(
            &bytes,
            &p.head.genesis(),
            &[0x55; 32],
            p.head.public_key(),
        );
        refused(other, "does not recompute for its owner");
    }

    /// DSM Amendment A39 draft, option B: a load or an unload is its board's signed advance. A
    /// body carrying another boundary's release, another board's, or one whose frontier is not
    /// the one the account advanced to is refused: no boundary moves an account its board did not
    /// sign.
    /// MUTATION CONTROL: dropping the release check turns this red.
    #[test]
    fn a_boundary_its_board_did_not_sign_is_refused() {
        let mut p = Payer::opened(0xE3);
        let (counter, frontier) = standing(&p);
        let (_, load_release, _) = signed(
            &mut p,
            OfflineBoundaryKind::Load,
            30,
            BoundarySince::Opened { frontier, counter },
        );
        let funded = p.account_root();
        let (unload, _, bytes) = signed(
            &mut p,
            OfflineBoundaryKind::Unload,
            10,
            BoundarySince::Previous {
                account_root: funded,
            },
        );
        verify(&p, &bytes).expect("the honest unload");
        let since = BoundarySince::Previous {
            account_root: funded,
        };
        let another_boundarys = body_bytes(
            &p,
            &unload,
            OfflineBoundaryKind::Unload,
            10,
            since,
            Vec::new(),
            &load_release,
        );
        refused(
            verify(&p, &another_boundarys),
            "the boundary's board release:",
        );
        let mut stranger = Payer::opened(0xE4);
        let (s_counter, s_frontier) = standing(&stranger);
        let (_, strangers_release, _) = signed(
            &mut stranger,
            OfflineBoundaryKind::Load,
            30,
            BoundarySince::Opened {
                frontier: s_frontier,
                counter: s_counter,
            },
        );
        let another_boards = body_bytes(
            &p,
            &unload,
            OfflineBoundaryKind::Unload,
            10,
            since,
            Vec::new(),
            &strangers_release,
        );
        refused(verify(&p, &another_boards), "the boundary's board release:");
        let honest = OfflineBoundaryBody::decode(&bytes).expect("decode");
        refused(
            verify(
                &p,
                &OfflineBoundaryBody {
                    next_frontier: [0x4E; 32],
                    ..honest
                }
                .encode()
                .expect("encode"),
            ),
            "the boundary's board release:",
        );
    }

    /// DSM Amendment A39 draft, option B: a payer cannot unload what it already paid offline,
    /// whether or not the payment's receiver has published it. A wallet rolled back to before
    /// its payment asks its board for an unload of the whole allocation from there: the board,
    /// which signed the payment from that root and left it, refuses, so no such unload exists to
    /// be admitted.
    /// MUTATION CONTROL: a board that signs from a root it left (`PrevRootMismatch` dropped in
    /// anchor-core's prepare) turns this red.
    #[test]
    fn a_payer_cannot_unload_what_it_paid_offline() {
        let mut p = Payer::loaded(0xE5, 40);
        let before_payment = p.head.clone();
        let (paid, _, _) = p.spend([0xB0; 32], 30);
        assert_eq!(paid.release().cert.recipient, [0xB0; 32]);
        // The receiver has published nothing. The wallet rolls back to before the payment.
        p.head = before_payment;
        let refused_to_sign = p
            .try_boundary(OfflineBoundaryKind::Unload, 40)
            .expect_err("the board refuses to sign from a root it left");
        assert!(
            matches!(
                refused_to_sign,
                anchor_core::appliance::ApplianceError::PrevRootMismatch
                    | anchor_core::appliance::ApplianceError::IndexMismatch
            ),
            "{refused_to_sign:?}"
        );
    }

    /// Schema 2: `B` recomputes from the anchor the body names and the
    /// owner's online key and device id. Another key, other pin material or
    /// another bundle is refused before anything else is read.
    /// MUTATION CONTROL: dropping the recomputation in `verify_ancestry` turns
    /// this red.
    #[test]
    fn a_boundary_whose_bundle_is_not_its_owners_is_refused() {
        let mut p = Payer::opened(0xE6);
        let (counter, frontier) = standing(&p);
        let (_, _, bytes) = signed(
            &mut p,
            OfflineBoundaryKind::Load,
            30,
            BoundarySince::Opened { frontier, counter },
        );
        refused(
            OfflineBoundaryBody::verify(&bytes, &p.head.genesis(), &p.head.devid(), &[0x0F; 64]),
            "does not recompute for its owner",
        );
        let honest = OfflineBoundaryBody::decode(&bytes).expect("decode");
        let mut other_keys = honest.clone();
        other_keys.ancestry.anchor.pk_chip = vec![0xC9; 32];
        refused(
            verify(&p, &other_keys.encode().expect("encode")),
            "does not recompute for its owner",
        );
    }

    /// An account's first boundary starts from the account opened empty,
    /// with no spends; a later one names the boundary before it.
    /// MUTATION CONTROL: dropping the opened-empty check turns this red.
    #[test]
    fn a_first_boundary_starts_from_the_account_opened_empty() {
        let mut p = Payer::opened(0xE7);
        let opened = p.account_root();
        let (counter, frontier) = standing(&p);
        let (load, release, _) = signed(
            &mut p,
            OfflineBoundaryKind::Load,
            30,
            BoundarySince::Opened { frontier, counter },
        );
        let (_, _, second) = signed(
            &mut p,
            OfflineBoundaryKind::Load,
            5,
            BoundarySince::Opened { frontier, counter },
        );
        refused(verify(&p, &second), "starts from the account opened empty");
        let misplaced = body_bytes(
            &p,
            &load,
            OfflineBoundaryKind::Load,
            30,
            BoundarySince::Opened {
                frontier: [0x02; 32],
                counter,
            },
            Vec::new(),
            &release,
        );
        refused(
            verify(&p, &misplaced),
            "is not the one its steps since the last boundary leave",
        );
        let unnamed = body_bytes(
            &p,
            &load,
            OfflineBoundaryKind::Load,
            30,
            BoundarySince::Previous {
                account_root: opened,
            },
            Vec::new(),
            &release,
        );
        refused(verify(&p, &unnamed), "names the boundary before it");
    }

    /// The funding chain is a hash chain: a later boundary's identity hashes
    /// the account root it starts from, which holds the earlier boundary's
    /// identity. Change the earlier load and every later identity changes.
    #[test]
    fn the_funding_chain_commits_every_earlier_boundary() {
        let chain_after = |first: u64| {
            let mut p = Payer::opened(0xE8);
            let (earlier, _) = p.boundary(OfflineBoundaryKind::Load, first);
            let after_first = p.account_root();
            let (second, release) = p.boundary(OfflineBoundaryKind::Load, 5);
            let body = OfflineBoundaryBody::decode(&body_bytes(
                &p,
                &second,
                OfflineBoundaryKind::Load,
                5,
                BoundarySince::Previous {
                    account_root: after_first,
                },
                Vec::new(),
                &release,
            ))
            .expect("body");
            assert_eq!(
                body.pre_funding_chain,
                Some(earlier.operation_id),
                "the second load's body names the first load's identity"
            );
            second.operation_id
        };
        assert_ne!(chain_after(20), chain_after(21));
    }

    #[test]
    fn a_body_that_does_not_decode_is_refused() {
        let mut p = Payer::opened(0xE9);
        let (counter, frontier) = standing(&p);
        let (_, _, bytes) = signed(
            &mut p,
            OfflineBoundaryKind::Load,
            30,
            BoundarySince::Opened { frontier, counter },
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        refused(verify(&p, &trailing), "an offline boundary body:");
        refused(
            verify(&p, &bytes[..bytes.len() - 1]),
            "an offline boundary body:",
        );
    }

    /// A boundary after offline spends carries every spend since the last
    /// boundary, and exposes each payment: the chain verified from the account
    /// the last boundary left reaches the account the boundary starts from. A
    /// boundary that leaves a spend out is refused.
    /// MUTATION CONTROL: dropping the check that the chain reaches the
    /// boundary's account turns this red.
    #[test]
    fn a_boundary_carries_every_spend_since_the_last() {
        let mut payer = Payer::loaded(0x61, 40);
        let after_load = payer.account_root();
        let (first, _, _) = payer.spend([0xB0; 32], 10);
        let (second, _, _) = payer.spend([0xB1; 32], 5);
        let (unload, release) = payer.boundary(OfflineBoundaryKind::Unload, 25);
        let hop = |h: &crate::types::offline_chain::SpendHop| {
            crate::types::offline_chain::AccountHop::Spend(h.clone()).to_bytes()
        };
        let body = |chain: Vec<Vec<u8>>| {
            body_bytes(
                &payer,
                &unload,
                OfflineBoundaryKind::Unload,
                25,
                BoundarySince::Previous {
                    account_root: after_load,
                },
                chain,
                &release,
            )
        };
        let (verified, exposed) = OfflineBoundaryBody::verify(
            &body(vec![hop(&first), hop(&second)]),
            &payer.head.genesis(),
            &payer.head.devid(),
            payer.head.public_key(),
        )
        .expect("the unload carries both spends");
        assert_eq!(verified.kind(), OfflineBoundaryKind::Unload);
        assert_eq!(
            exposed
                .iter()
                .map(|p| (p.recipient, p.amount))
                .collect::<Vec<_>>(),
            vec![([0xB0; 32], 10), ([0xB1; 32], 5)]
        );
        refused(
            OfflineBoundaryBody::verify(
                &body(vec![hop(&first)]),
                &payer.head.genesis(),
                &payer.head.devid(),
                payer.head.public_key(),
            ),
            "is not the one its steps since the last boundary leave",
        );
    }

    /// The bearer transfer of `amount` of `ASSET` to the lineage
    /// `(genesis, to)`, as its canonical bytes.
    fn bearer_payment(to: [u8; 32], genesis: [u8; 32], amount: u64) -> Vec<u8> {
        crate::types::operations::Operation::Transfer {
            to_device_id: to.to_vec(),
            to_genesis: genesis,
            amount: crate::types::token_types::Balance::amount(amount),
            policy_commit: ASSET,
            terms_commitment: [0x5C; 32],
            token_policy: Vec::new(),
            signature: Vec::new(),
            authority_policy: Some(crate::types::operations::canonical_offline_bearer_policy()),
        }
        .to_bytes()
    }

    /// A payment of `amount` to `receiver` held, final, at the payer's origin
    /// cell: the settlement body naming it, the account the payer's load left,
    /// and the read of the cell (DSM Amendment A39 draft).
    fn held_at_cells(
        receiver: [u8; 32],
        amount: u64,
    ) -> (
        OfflineSettlementBody,
        [u8; 32],
        Vec<crate::offline_origin::OriginRead>,
    ) {
        use crate::offline_origin::{resolution, OriginCell, OriginWrite};
        use crate::types::offline_chain::fixture::{bearer_op, Payer};
        let mut p = Payer::loaded(0x51, 40);
        let start = p.account_root();
        let step = crate::types::offline_chain::AccountHop::Spend(p.spend(receiver, amount).0);
        let write = OriginWrite::new(
            p.head.public_key(),
            p.head.devid(),
            p.pin.bundle,
            &BoundaryAnchor {
                anchor_id: p.pin.anchor_id,
                pk_chip: p.pin.pk_chip.clone(),
                pk_host: p.pin.pk_host.clone(),
                enrolled_counter: u64::from(p.enrolled_counter),
                birth_commitment: p.birth_commitment,
            },
            &step,
        );
        let cell = OriginCell::new(
            &p.pin.bundle,
            &start,
            &crate::route_chain::fixtures::committed_set(),
            &crate::route_chain::fixtures::committed_set_id(),
        )
        .expect("a cell over the fixture set");
        let mut seats = crate::route_chain::fixtures::Cell::at(cell.routed());
        seats.write(&write.encode().expect("bytes"), 2, &[]);
        let read = resolution(&cell, &seats.evidence()).expect("the leader is read");
        let body = OfflineSettlementBody {
            payer_genesis: p.genesis,
            payer_device: p.head.devid(),
            boundary_position: 4,
            payment_root: start,
            release_message: step.board_message().expect("signed"),
            bundle: p.pin.bundle,
            asset: p.token,
            amount,
            payment_operation: bearer_op(receiver, p.token, &p.token_policy, amount).to_bytes(),
        };
        (body, start, vec![read])
    }

    /// The fixture payer's bearer transfers name this genesis.
    const PAYEE_GENESIS: [u8; 32] = [0x6E; 32];

    /// SA-91, DSM Amendment A39 draft. A settlement names exactly the payment
    /// the payer's origin cells hold, final, from the account the payer's
    /// boundary left, to the device that settles it; its identity is that
    /// device's one settlement of that spend. The payer is never needed.
    /// MUTATION CONTROL: dropping the check that the payment is to this device,
    /// or that the body names the payment the cells hold, turns this red.
    #[test]
    fn a_settlement_is_held_to_the_payment_its_payers_cells_hold() {
        let receiver = [0xB0; 32];
        let (honest, start, reads) = held_at_cells(receiver, 7);
        let bytes = honest.encode().expect("encodes");
        assert_eq!(
            OfflineSettlementBody::decode(&bytes).expect("decode"),
            honest,
            "the one encoding round-trips"
        );
        let verified =
            OfflineSettlementBody::verify(&bytes, &PAYEE_GENESIS, &receiver, &start, &reads)
                .expect("the settlement of the payment the cells hold");
        assert_eq!(verified.kind(), OfflineBoundaryKind::Settle);
        assert_eq!(
            verified.operation_id(),
            honest.operation_id(&PAYEE_GENESIS, &receiver)
        );
        assert_eq!((verified.asset(), verified.amount()), (honest.asset, 7));
        assert_eq!(
            verified.post_account_root(),
            None,
            "no offline account moves"
        );
        for (misstated, why) in [
            (
                OfflineSettlementBody {
                    amount: 8,
                    ..honest.clone()
                },
                "does not name the payment the payer's cells hold",
            ),
            (
                OfflineSettlementBody {
                    release_message: [0x35; 32],
                    ..honest.clone()
                },
                "another history",
            ),
            (
                OfflineSettlementBody {
                    payment_root: [0x36; 32],
                    ..honest.clone()
                },
                "does not end at the cell its payment starts from",
            ),
        ] {
            refused(
                OfflineSettlementBody::verify(
                    &misstated.encode().expect("encodes"),
                    &PAYEE_GENESIS,
                    &receiver,
                    &start,
                    &reads,
                ),
                why,
            );
        }
        refused(
            OfflineSettlementBody::verify(&bytes, &PAYEE_GENESIS, &[0xB1; 32], &start, &reads),
            "is not to the device that settles it",
        );
        refused(
            OfflineSettlementBody::verify(&bytes, &PAYEE_GENESIS, &receiver, &[0x37; 32], &reads),
            "it is not the cell of the root the path stands at",
        );
        assert_eq!(
            offline_body_kind(&bytes).expect("a body"),
            OfflineBodyKind::Settlement
        );
    }

    /// SA-133. A settlement pays the lineage its payment named: the transfer
    /// it carries must re-hash to the payload the payer's anchor signed, and
    /// that transfer must name the settling device's genesis as well as its
    /// device id. A lineage sharing the payee's device id cannot settle the
    /// payee's payment, and a settlement cannot carry some other transfer.
    /// MUTATION CONTROL: the payload re-hash dropped, or the genesis check
    /// dropped, each turns this red.
    #[test]
    fn a_settlement_pays_only_the_lineage_its_payment_named() {
        let receiver = [0xB0; 32];
        let (honest, start, reads) = held_at_cells(receiver, 7);
        let body = honest.encode().expect("encodes");
        OfflineSettlementBody::verify(&body, &PAYEE_GENESIS, &receiver, &start, &reads)
            .expect("the payee's lineage settles its payment");
        refused(
            OfflineSettlementBody::verify(&body, &[0x0C; 32], &receiver, &start, &reads),
            "is not a bearer transfer to this lineage",
        );
        let carried = OfflineSettlementBody {
            payment_operation: bearer_payment(receiver, [0x0C; 32], 7),
            ..honest
        }
        .encode()
        .expect("encodes");
        refused(
            OfflineSettlementBody::verify(&carried, &[0x0C; 32], &receiver, &start, &reads),
            "is not the transfer the payer's anchor signed",
        );
    }

    /// An account reopened at a board's counter (a wallet upgraded with its
    /// board already used) starts there: its first boundary names that
    /// counter, and receivers rebuild the start from it. Owner, 2026-11-15:
    /// "Change Core tonight". A boundary naming any other counter is refused.
    /// MUTATION CONTROL: `verify_ancestry` rebuilding the start at counter 0
    /// turns the first half red; ignoring the counter turns the second red.
    #[test]
    fn a_first_boundary_starts_at_the_counter_the_account_opened_at() {
        // A board already used: it signed a load and an unload, and the wallet's account
        // reopened empty at the counter and frontier the board stands at (the 11-15 upgrade).
        let mut p = Payer::opened(0xEA);
        p.boundary(OfflineBoundaryKind::Load, 10);
        p.boundary(OfflineBoundaryKind::Unload, 10);
        let (counter, frontier) = standing(&p);
        assert_eq!(counter, 2);
        p.head = crate::types::device_state::tests::fresh_device(0xEA)
            .created_token(p.token, 100)
            .expect("token created")
            .open_offline_account(&p.pin.bundle, frontier, counter)
            .expect("account reopened at the board's counter");
        let (load, release, bytes) = signed(
            &mut p,
            OfflineBoundaryKind::Load,
            30,
            BoundarySince::Opened { frontier, counter },
        );
        let verified = verify(&p, &bytes).expect("the load verifies from the board's counter");
        assert_eq!(verified.operation_id(), load.operation_id);
        let from_zero = body_bytes(
            &p,
            &load,
            OfflineBoundaryKind::Load,
            30,
            BoundarySince::Opened {
                frontier,
                counter: 0,
            },
            Vec::new(),
            &release,
        );
        refused(
            verify(&p, &from_zero),
            "the boundary's account is not the one its steps since the last boundary leave",
        );
    }
}
