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
    const SCHEMA: u16 = 2;
}

/// Envelope of an unload body.
struct UnloadBody;
impl CcbObject for UnloadBody {
    const CLASS: u16 = class::OFFLINE_UNLOAD_BOUNDARY_BODY;
    const SCHEMA: u16 = 2;
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
    /// The account's first boundary: it was opened empty, at this frontier,
    /// counter zero.
    Opened { frontier: [u8; 32] },
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
    },
    Settlement,
}

impl VerifiedOfflineBoundary {
    pub fn kind(&self) -> OfflineBoundaryKind {
        self.kind
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
    ) -> Result<Self, DsmError> {
        let StepBefore::Boundary {
            allocation,
            funding_chain,
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
        // 8: a boundary writes exactly two account leaves — its allocation
        // and the funding chain — so exactly two paths, in key order.
        let [first, second] = self.account_paths.as_slice() else {
            return Err(CcbError::FixedLength {
                field: "account_paths",
                expected: 2,
                got: self.account_paths.len(),
            });
        };
        push_path(&mut out, first)?;
        push_path(&mut out, second)?;
        push_path(&mut out, &self.device_path)?; // 9
        let anchor = &self.ancestry.anchor;
        push_digest32(&mut out, &anchor.anchor_id); // 10
        push_bytes(&mut out, &anchor.pk_chip)?; // 11
        push_bytes(&mut out, &anchor.pk_host)?; // 12
        push_u64(&mut out, anchor.enrolled_counter); // 13
        push_digest32(&mut out, &anchor.birth_commitment); // 14
        match &self.ancestry.since {
            // 15
            BoundarySince::Opened { frontier } => {
                out.push(SINCE_OPENED);
                push_digest32(&mut out, frontier);
            }
            BoundarySince::Previous { account_root } => {
                out.push(SINCE_PREVIOUS);
                push_digest32(&mut out, account_root);
            }
        }
        // 16: the spends since, each its canonical `OfflineSpendHop` bytes.
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

    /// Decode a body, strictly: its class, schema 1, every field, nothing after.
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
        // A boundary writes two account leaves: its allocation and the chain.
        let account_paths = vec![read_path(&mut c)?, read_path(&mut c)?];
        let device_path = read_path(&mut c)?;
        let anchor_id = c.digest32()?;
        let pk_chip = read_bytes(&mut c)?;
        let pk_host = read_bytes(&mut c)?;
        let enrolled_counter = c.u64()?;
        let birth_commitment = c.digest32()?;
        let since = match c.u8()? {
            SINCE_OPENED => BoundarySince::Opened {
                frontier: c.digest32()?,
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
        let step =
            match body.kind {
                OfflineBoundaryKind::Load => OfflineAccountStep::Load {
                    asset: body.asset,
                    amount: body.amount,
                    boundary_id: operation_id,
                },
                OfflineBoundaryKind::Unload => OfflineAccountStep::Unload {
                    asset: body.asset,
                    amount: body.amount,
                    boundary_id: operation_id,
                },
                OfflineBoundaryKind::Settle => return Err(DsmError::invalid_operation(
                    "an offline boundary body is a load or an unload of the device's own account",
                )),
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
        let payments = verify_ancestry(&body, device_id, owner_key)?;
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
            },
        };
        Ok((verified, payments))
    }
}

/// Envelope of a settlement body.
struct SettlementBody;
impl CcbObject for SettlementBody {
    const CLASS: u16 = class::OFFLINE_SETTLEMENT_BODY;
    const SCHEMA: u16 = 1;
}

/// The body of an offline settlement (SA-91): a receiver's admission of value
/// it received offline. It names the payer's spend by the root-advance message
/// `M` the payer's anchor signed for it, and the economic position of the
/// payer's boundary that exposed it online. Its credit is funded by that spend
/// and consumed once, as an unload's by its own debit: the settlement's
/// identity is `H(G ‖ DevID ‖ G_payer ‖ DevID_payer ‖ M)`, one per receiver and
/// spend, and the source it consumes is derived from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineSettlementBody {
    pub payer_genesis: [u8; 32],
    pub payer_device: [u8; 32],
    /// The economic position of the payer's boundary that exposed the spend.
    pub exposed_at: u64,
    /// `M`, the root-advance message the payer's anchor signed for the spend.
    pub release_message: [u8; 32],
    /// The payer's anchor bundle.
    pub bundle: [u8; 32],
    pub asset: [u8; 32],
    pub amount: u64,
}

impl OfflineSettlementBody {
    /// The settlement of the payment `exposure` records.
    pub fn of(exposure: &crate::economic::peer_lineage::PeerOfflineExposure) -> Self {
        let payment = exposure.payment();
        Self {
            payer_genesis: *exposure.genesis(),
            payer_device: *exposure.device_id(),
            exposed_at: exposure.economic_position(),
            release_message: payment.release_message,
            bundle: *exposure.bundle(),
            asset: payment.asset,
            amount: payment.amount,
        }
    }

    /// The body's canonical bytes, fields in registry order.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_envelope::<SettlementBody>(&mut out);
        push_digest32(&mut out, &self.payer_genesis); // 1
        push_digest32(&mut out, &self.payer_device); // 2
        push_u64(&mut out, self.exposed_at); // 3
        push_digest32(&mut out, &self.release_message); // 4
        push_digest32(&mut out, &self.bundle); // 5
        push_digest32(&mut out, &self.asset); // 6
        push_u64(&mut out, self.amount); // 7
        out
    }

    /// Decode a body, strictly: its class, schema 1, every field, nothing after.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        c.envelope(SettlementBody::CLASS, SettlementBody::SCHEMA)?;
        let body = Self {
            payer_genesis: c.digest32()?,
            payer_device: c.digest32()?,
            exposed_at: c.u64()?,
            release_message: c.digest32()?,
            bundle: c.digest32()?,
            asset: c.digest32()?,
            amount: c.u64()?,
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
        let mut h = dsm_domain_hasher(TAG_DSM_ECONOMIC_OPERATION_ID_OFFLINE_SETTLEMENT);
        h.update(genesis);
        h.update(device_id);
        h.update(&self.payer_genesis);
        h.update(&self.payer_device);
        h.update(&self.release_message);
        *h.finalize().as_bytes()
    }

    /// Verify the body at `body_bytes` as a settlement of the device
    /// `(genesis, device_id)`, against `exposure`: the payment a boundary of
    /// the payer's online history exposed, as a walk of the payer this
    /// verifier ran itself found it. The body must name exactly that payment —
    /// the payer, the position of the boundary, `M`, the bundle, the asset and
    /// the amount — and the payment must be to this device.
    pub fn verify(
        body_bytes: &[u8],
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        exposure: &crate::economic::peer_lineage::PeerOfflineExposure,
    ) -> Result<VerifiedOfflineBoundary, DsmError> {
        let body = Self::decode(body_bytes)
            .map_err(|e| DsmError::invalid_operation(format!("an offline settlement body: {e}")))?;
        if body != Self::of(exposure) {
            return Err(DsmError::invalid_operation(
                "the settlement does not name the payment the payer's boundary exposed",
            ));
        }
        if exposure.payment().recipient != *device_id {
            return Err(DsmError::invalid_operation(
                "the exposed payment is not to the device that settles it",
            ));
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
/// The ancestry marker of a boundary after the first.
const SINCE_PREVIOUS: u8 = 0x02;

fn read_bytes(c: &mut Cursor<'_>) -> Result<Vec<u8>, DecodeError> {
    let len = c.u32()? as usize;
    Ok(c.take(len)?.to_vec())
}

/// The account's ancestry since its last boundary, verified against `body`.
fn verify_ancestry(
    body: &OfflineBoundaryBody,
    device_id: &[u8; 32],
    owner_key: &[u8],
) -> Result<Vec<crate::types::offline_chain::ChainPayment>, DsmError> {
    use crate::types::offline_chain::{chain_end, verify_spend_chain, ChainAnchor, SpendHop};
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
    )?;
    let hops = body
        .ancestry
        .chain
        .iter()
        .map(|hop| {
            use prost::Message;
            SpendHop::from_proto(
                crate::types::proto::OfflineSpendHop::decode(hop.as_slice()).map_err(|e| {
                    DsmError::invalid_operation(format!("an offline boundary's spend: {e}"))
                })?,
            )
        })
        .collect::<Result<Vec<_>, DsmError>>()?;
    let start =
        match (
            &body.ancestry.since,
            body.pre_funding_chain,
            hops.as_slice(),
        ) {
            (BoundarySince::Opened { frontier }, None, []) => {
                crate::types::offline_account::OfflineAccount::open(*frontier, 0).root()
            }
            (BoundarySince::Previous { account_root }, Some(_), _) => *account_root,
            (BoundarySince::Opened { .. }, ..) => return Err(DsmError::invalid_operation(
                "an offline account's first boundary starts from the account opened empty, with \
                 no spends before it",
            )),
            (BoundarySince::Previous { .. }, None, _) => {
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
    let payments = verify_spend_chain(&start, &chain_anchor, &hops)?;
    if chain_end(&start, &payments) != body.pre_account_root {
        return Err(DsmError::invalid_operation(
            "the boundary's account is not the one its chain of spends leaves",
        ));
    }
    Ok(payments)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::device_state::DeviceState;

    const ASSET: [u8; 32] = [0xA1; 32];
    const OPENED: [u8; 32] = [0x01; 32];

    /// The anchor of the test device's account: pin material whose bundle
    /// recomputes for the device it belongs to.
    fn anchor() -> BoundaryAnchor {
        BoundaryAnchor {
            anchor_id: [0xA0; 32],
            pk_chip: vec![0xC1; 32],
            pk_host: vec![0xC2; 64],
            enrolled_counter: 16,
            birth_commitment: [0xB7; 32],
        }
    }

    /// The bundle `B` of [`anchor`] provisioned for `dev`.
    fn bundle_of(dev: &DeviceState) -> [u8; 32] {
        let a = anchor();
        anchor_core::enrollment::anchor_bundle(
            dev.public_key(),
            &a.anchor_id,
            &a.pk_chip,
            &a.pk_host,
            16,
            &dev.devid(),
            &crate::types::operations::canonical_offline_bearer_policy().policy_id,
            &a.birth_commitment,
        )
    }

    fn device() -> DeviceState {
        let dev = crate::types::device_state::tests::fresh_device(0xE1)
            .created_token(ASSET, 100)
            .expect("token created");
        let bundle = bundle_of(&dev);
        dev.open_offline_account(&bundle, OPENED, 0)
            .expect("account opened")
    }

    fn body_of(
        dev: &DeviceState,
        kind: OfflineBoundaryKind,
        amount: u64,
        since: BoundarySince,
    ) -> (OfflineBoundaryOutcome, Vec<u8>) {
        let bundle = bundle_of(dev);
        let outcome = dev
            .cross_offline_boundary(&bundle, kind, &ASSET, amount)
            .expect("the device takes the boundary");
        let bytes = OfflineBoundaryBody::of(
            &outcome,
            kind,
            bundle,
            ASSET,
            amount,
            BoundaryAncestry {
                anchor: anchor(),
                since,
                chain: Vec::new(),
            },
        )
        .expect("body")
        .encode()
        .expect("encode");
        (outcome, bytes)
    }

    fn account_root(dev: &DeviceState) -> [u8; 32] {
        dev.offline_account(&bundle_of(dev))
            .expect("the account is open")
            .root()
    }

    fn verify(dev: &DeviceState, bytes: &[u8]) -> Result<VerifiedOfflineBoundary, DsmError> {
        OfflineBoundaryBody::verify(bytes, &dev.genesis(), &dev.devid(), dev.public_key()).map(
            |(verified, exposed)| {
                assert!(exposed.is_empty(), "no spends, no exposure");
                verified
            },
        )
    }

    fn refused<T: core::fmt::Debug>(result: Result<T, DsmError>, reason: &str) {
        let error = result.expect_err(reason);
        assert!(error.to_string().contains(reason), "{error}");
    }

    #[test]
    fn a_boundary_verifies_to_the_device_and_account_it_leaves() {
        let dev = device();
        let (load, bytes) = body_of(
            &dev,
            OfflineBoundaryKind::Load,
            30,
            BoundarySince::Opened { frontier: OPENED },
        );
        let verified = verify(&dev, &bytes).expect("the load verifies");
        assert_eq!(verified.operation_id(), load.operation_id);
        assert_eq!(
            verified.post_device_root(),
            Some(load.new_device_state.root())
        );
        assert_eq!(
            verified.post_account_root(),
            Some(account_root(&load.new_device_state))
        );
        assert_eq!(
            OfflineBoundaryBody::decode(&bytes)
                .expect("decode")
                .encode()
                .expect("encode"),
            bytes,
            "the one encoding round-trips"
        );
        let after_load = account_root(&load.new_device_state);
        let (unload, bytes) = body_of(
            &load.new_device_state,
            OfflineBoundaryKind::Unload,
            12,
            BoundarySince::Previous {
                account_root: after_load,
            },
        );
        let verified = verify(&dev, &bytes).expect("unload");
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
    }

    /// A body that misstates what the account held, or names another device,
    /// another amount or another bundle, folds to another root or another
    /// identity and is refused.
    #[test]
    fn a_misstated_boundary_is_refused() {
        let dev = device();
        let (load, _) = body_of(
            &dev,
            OfflineBoundaryKind::Load,
            30,
            BoundarySince::Opened { frontier: OPENED },
        );
        let funded = load.new_device_state;
        let (_, bytes) = body_of(
            &funded,
            OfflineBoundaryKind::Unload,
            10,
            BoundarySince::Previous {
                account_root: account_root(&funded),
            },
        );
        let honest = OfflineBoundaryBody::decode(&bytes).expect("decode");
        let check = |body: &OfflineBoundaryBody| verify(&dev, &body.encode().expect("encode"));
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
                pre_device_root: dev.root(),
                ..honest.clone()
            }),
            "does not commit the offline account",
        );
        // The same bytes under another device's identity are another boundary.
        let other =
            OfflineBoundaryBody::verify(&bytes, &dev.genesis(), &[0x55; 32], dev.public_key());
        refused(other, "does not recompute for its owner");
    }

    /// Schema 2: `B` recomputes from the anchor the body names and the
    /// owner's online key and device id. Another key, other pin material or
    /// another bundle is refused before anything else is read.
    /// MUTATION CONTROL: dropping the recomputation in `verify_ancestry` turns
    /// this red.
    #[test]
    fn a_boundary_whose_bundle_is_not_its_owners_is_refused() {
        let dev = device();
        let (_, bytes) = body_of(
            &dev,
            OfflineBoundaryKind::Load,
            30,
            BoundarySince::Opened { frontier: OPENED },
        );
        refused(
            OfflineBoundaryBody::verify(&bytes, &dev.genesis(), &dev.devid(), &[0x0F; 64]),
            "does not recompute for its owner",
        );
        let honest = OfflineBoundaryBody::decode(&bytes).expect("decode");
        let mut other_keys = honest.clone();
        other_keys.ancestry.anchor.pk_chip = vec![0xC9; 32];
        refused(
            verify(&dev, &other_keys.encode().expect("encode")),
            "does not recompute for its owner",
        );
    }

    /// An account's first boundary starts from the account opened empty,
    /// with no spends; a later one names the boundary before it.
    /// MUTATION CONTROL: dropping the opened-empty check turns this red.
    #[test]
    fn a_first_boundary_starts_from_the_account_opened_empty() {
        let dev = device();
        let (load, _) = body_of(
            &dev,
            OfflineBoundaryKind::Load,
            30,
            BoundarySince::Opened { frontier: OPENED },
        );
        let (_, second) = body_of(
            &load.new_device_state,
            OfflineBoundaryKind::Load,
            5,
            BoundarySince::Opened { frontier: OPENED },
        );
        refused(
            verify(&dev, &second),
            "starts from the account opened empty",
        );
        let (_, misplaced) = body_of(
            &dev,
            OfflineBoundaryKind::Load,
            30,
            BoundarySince::Opened {
                frontier: [0x02; 32],
            },
        );
        refused(
            verify(&dev, &misplaced),
            "is not the one its chain of spends leaves",
        );
        let (_, unnamed) = body_of(
            &dev,
            OfflineBoundaryKind::Load,
            30,
            BoundarySince::Previous {
                account_root: account_root(&dev),
            },
        );
        refused(verify(&dev, &unnamed), "names the boundary before it");
    }

    /// The funding chain is a hash chain: a later boundary's identity hashes
    /// the account root it starts from, which holds the earlier boundary's
    /// identity. Change the earlier load and every later identity changes.
    #[test]
    fn the_funding_chain_commits_every_earlier_boundary() {
        let dev = device();
        let bundle = bundle_of(&dev);
        let chain_after = |first: u64| {
            let first = dev
                .cross_offline_boundary(&bundle, OfflineBoundaryKind::Load, &ASSET, first)
                .expect("first load");
            let second = first
                .new_device_state
                .cross_offline_boundary(&bundle, OfflineBoundaryKind::Load, &ASSET, 5)
                .expect("second load");
            let body = OfflineBoundaryBody::of(
                &second,
                OfflineBoundaryKind::Load,
                bundle,
                ASSET,
                5,
                BoundaryAncestry {
                    anchor: anchor(),
                    since: BoundarySince::Previous {
                        account_root: account_root(&first.new_device_state),
                    },
                    chain: Vec::new(),
                },
            )
            .expect("body");
            assert_eq!(
                body.pre_funding_chain,
                Some(first.operation_id),
                "the second load's body names the first load's identity"
            );
            second.operation_id
        };
        assert_ne!(chain_after(20), chain_after(21));
    }

    #[test]
    fn a_body_that_does_not_decode_is_refused() {
        let dev = device();
        let (_, bytes) = body_of(
            &dev,
            OfflineBoundaryKind::Load,
            30,
            BoundarySince::Opened { frontier: OPENED },
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        refused(verify(&dev, &trailing), "an offline boundary body:");
        refused(
            verify(&dev, &bytes[..bytes.len() - 1]),
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
        use crate::types::offline_chain::fixture::Payer;
        use prost::Message;
        let mut payer = Payer::loaded(0x61, 40);
        let after_load = payer.account_root();
        let (first, _, _) = payer.spend([0xB0; 32], 10);
        let (second, _, _) = payer.spend([0xB1; 32], 5);
        let unload = payer
            .head
            .cross_offline_boundary(
                &payer.pin.bundle,
                OfflineBoundaryKind::Unload,
                &payer.token,
                25,
            )
            .expect("the unload of what is left");
        let anchor = BoundaryAnchor {
            anchor_id: payer.pin.anchor_id,
            pk_chip: payer.pin.pk_chip.clone(),
            pk_host: payer.pin.pk_host.clone(),
            enrolled_counter: u64::from(payer.enrolled_counter),
            birth_commitment: payer.birth_commitment,
        };
        let body = |chain: Vec<Vec<u8>>| {
            OfflineBoundaryBody::of(
                &unload,
                OfflineBoundaryKind::Unload,
                payer.pin.bundle,
                payer.token,
                25,
                BoundaryAncestry {
                    anchor: anchor.clone(),
                    since: BoundarySince::Previous {
                        account_root: after_load,
                    },
                    chain,
                },
            )
            .expect("body")
            .encode()
            .expect("encode")
        };
        let hop = |h: &crate::types::offline_chain::SpendHop| h.to_proto().encode_to_vec();
        let (verified, exposed) = OfflineBoundaryBody::verify(
            &body(vec![hop(&first), hop(&second)]),
            &payer.genesis,
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
                &payer.genesis,
                &payer.head.devid(),
                payer.head.public_key(),
            ),
            "is not the one its chain of spends leaves",
        );
    }

    /// SA-91. A settlement names exactly the payment a boundary of the
    /// payer's online history exposed, to the device that settles it; its
    /// identity is that device's one settlement of that spend.
    /// MUTATION CONTROL: dropping the check that the body is the exposed
    /// payment, or that the payment is to this device, turns this red.
    #[test]
    fn a_settlement_is_held_to_the_payment_exposed_to_its_device() {
        use crate::economic::peer_lineage::PeerOfflineExposure;
        use crate::types::offline_chain::{AccountPoint, ChainPayment};
        let receiver = [0xB0; 32];
        let point = |b: u8, counter: u64| AccountPoint {
            root: [b; 32],
            counter,
            frontier: [b ^ 0x0F; 32],
        };
        let exposure = PeerOfflineExposure::rehydrate_recorded(
            [0x31; 32],
            [0x32; 32],
            4,
            [0x33; 32],
            ChainPayment {
                recipient: receiver,
                asset: ASSET,
                amount: 7,
                release_message: [0x34; 32],
                before: point(0x41, 0),
                after: point(0x42, 1),
            },
        );
        let honest = OfflineSettlementBody::of(&exposure);
        let bytes = honest.encode();
        assert_eq!(
            OfflineSettlementBody::decode(&bytes).expect("decode"),
            honest,
            "the one encoding round-trips"
        );
        let verified = OfflineSettlementBody::verify(&bytes, &[0x0B; 32], &receiver, &exposure)
            .expect("the settlement of the exposed payment");
        assert_eq!(verified.kind(), OfflineBoundaryKind::Settle);
        assert_eq!(
            verified.operation_id(),
            honest.operation_id(&[0x0B; 32], &receiver)
        );
        assert_eq!((verified.asset(), verified.amount()), (ASSET, 7));
        assert_eq!(
            verified.post_account_root(),
            None,
            "no offline account moves"
        );
        for misstated in [
            OfflineSettlementBody {
                amount: 8,
                ..honest.clone()
            },
            OfflineSettlementBody {
                release_message: [0x35; 32],
                ..honest.clone()
            },
            OfflineSettlementBody {
                exposed_at: 5,
                ..honest.clone()
            },
            OfflineSettlementBody {
                payer_device: [0x36; 32],
                ..honest.clone()
            },
        ] {
            refused(
                OfflineSettlementBody::verify(
                    &misstated.encode(),
                    &[0x0B; 32],
                    &receiver,
                    &exposure,
                ),
                "does not name the payment the payer's boundary exposed",
            );
        }
        refused(
            OfflineSettlementBody::verify(&bytes, &[0x0C; 32], &[0xB1; 32], &exposure),
            "is not to the device that settles it",
        );
        assert_eq!(
            offline_body_kind(&bytes).expect("a body"),
            OfflineBodyKind::Settlement
        );
    }
}
