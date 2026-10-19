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

use crate::ccb::decode::{Cursor, DecodeError};
use crate::ccb::{
    class, push_absent, push_bytes, push_digest32, push_envelope, push_present, push_u64, CcbError,
    CcbObject,
};
use crate::common::domain_tags::{
    TAG_DSM_ECONOMIC_OFFLINE_BOUNDARY_EVIDENCE, TAG_DSM_ECONOMIC_OPERATION_DIGEST_OFFLINE_BOUNDARY,
    TAG_DSM_ECON_SOURCE_OFFLINE_BOUNDARY_DEBIT,
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
    const SCHEMA: u16 = 1;
}

/// Envelope of an unload body.
struct UnloadBody;
impl CcbObject for UnloadBody {
    const CLASS: u16 = class::OFFLINE_UNLOAD_BOUNDARY_BODY;
    const SCHEMA: u16 = 1;
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
    pre_device_root: [u8; 32],
    post_device_root: [u8; 32],
    pre_account_root: [u8; 32],
    post_account_root: [u8; 32],
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
    pub fn pre_device_root(&self) -> [u8; 32] {
        self.pre_device_root
    }
    pub fn post_device_root(&self) -> [u8; 32] {
        self.post_device_root
    }
    pub fn pre_account_root(&self) -> [u8; 32] {
        self.pre_account_root
    }
    pub fn post_account_root(&self) -> [u8; 32] {
        self.post_account_root
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
        })
    }

    /// The body's canonical bytes, fields in registry order.
    pub fn encode(&self) -> Result<Vec<u8>, CcbError> {
        let mut out = Vec::new();
        match self.kind {
            OfflineBoundaryKind::Load => push_envelope::<LoadBody>(&mut out),
            OfflineBoundaryKind::Unload => push_envelope::<UnloadBody>(&mut out),
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
    pub fn verify(
        body_bytes: &[u8],
        genesis: &[u8; 32],
        device_id: &[u8; 32],
    ) -> Result<VerifiedOfflineBoundary, DsmError> {
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
        let step = match body.kind {
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
        Ok(VerifiedOfflineBoundary {
            kind: body.kind,
            bundle: body.bundle,
            asset: body.asset,
            amount: body.amount,
            operation_id,
            operation_digest: offline_boundary_operation_digest(body_bytes),
            pre_device_root: body.pre_device_root,
            post_device_root,
            pre_account_root: body.pre_account_root,
            post_account_root,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::device_state::DeviceState;

    const ASSET: [u8; 32] = [0xA1; 32];
    const BUNDLE: [u8; 32] = [0xB1; 32];

    fn device() -> DeviceState {
        crate::types::device_state::tests::fresh_device(0xE1)
            .created_token(ASSET, 100)
            .expect("token created")
            .open_offline_account(&BUNDLE, [0x01; 32], 0)
            .expect("account opened")
    }

    fn body_of(
        dev: &DeviceState,
        kind: OfflineBoundaryKind,
        amount: u64,
    ) -> (OfflineBoundaryOutcome, Vec<u8>) {
        let outcome = dev
            .cross_offline_boundary(&BUNDLE, kind, &ASSET, amount)
            .expect("the device takes the boundary");
        let bytes = OfflineBoundaryBody::of(&outcome, kind, BUNDLE, ASSET, amount)
            .expect("body")
            .encode()
            .expect("encode");
        (outcome, bytes)
    }

    fn refused<T: core::fmt::Debug>(result: Result<T, DsmError>, reason: &str) {
        let error = result.expect_err(reason);
        assert!(error.to_string().contains(reason), "{error}");
    }

    #[test]
    fn a_boundary_verifies_to_the_device_and_account_it_leaves() {
        let dev = device();
        let (load, bytes) = body_of(&dev, OfflineBoundaryKind::Load, 30);
        let verified = OfflineBoundaryBody::verify(&bytes, &dev.genesis(), &dev.devid())
            .expect("the load verifies");
        assert_eq!(verified.operation_id(), load.operation_id);
        assert_eq!(verified.post_device_root(), load.new_device_state.root());
        assert_eq!(
            verified.post_account_root(),
            load.new_device_state
                .offline_account(&BUNDLE)
                .expect("open")
                .root()
        );
        assert_eq!(
            OfflineBoundaryBody::decode(&bytes)
                .expect("decode")
                .encode()
                .expect("encode"),
            bytes,
            "the one encoding round-trips"
        );
        let (unload, bytes) = body_of(&load.new_device_state, OfflineBoundaryKind::Unload, 12);
        let verified =
            OfflineBoundaryBody::verify(&bytes, &dev.genesis(), &dev.devid()).expect("unload");
        assert_eq!(verified.kind(), OfflineBoundaryKind::Unload);
        assert_eq!(verified.post_device_root(), unload.new_device_state.root());
    }

    /// A body that misstates what the account held, or names another device,
    /// another amount or another bundle, folds to another root or another
    /// identity and is refused.
    #[test]
    fn a_misstated_boundary_is_refused() {
        let dev = device();
        let (load, _) = body_of(&dev, OfflineBoundaryKind::Load, 30);
        let funded = load.new_device_state;
        let (_, bytes) = body_of(&funded, OfflineBoundaryKind::Unload, 10);
        let honest = OfflineBoundaryBody::decode(&bytes).expect("decode");
        let verify = |body: &OfflineBoundaryBody| {
            OfflineBoundaryBody::verify(
                &body.encode().expect("encode"),
                &dev.genesis(),
                &dev.devid(),
            )
        };
        refused(
            verify(&OfflineBoundaryBody {
                pre_allocation: Some(1_000),
                ..honest.clone()
            }),
            "the offline account step:",
        );
        refused(
            verify(&OfflineBoundaryBody {
                amount: 31,
                ..honest.clone()
            }),
            "more than the offline allocation holds",
        );
        refused(
            verify(&OfflineBoundaryBody {
                bundle: [0xB2; 32],
                ..honest.clone()
            }),
            "does not commit the offline account",
        );
        refused(
            verify(&OfflineBoundaryBody {
                pre_device_root: dev.root(),
                ..honest.clone()
            }),
            "does not commit the offline account",
        );
        // The same bytes under another device's identity are another boundary.
        let other = OfflineBoundaryBody::verify(&bytes, &dev.genesis(), &[0x55; 32])
            .expect("the folds do not involve the identity");
        let own = OfflineBoundaryBody::verify(&bytes, &dev.genesis(), &dev.devid()).expect("own");
        assert_ne!(other.operation_id(), own.operation_id());
    }

    /// The funding chain is a hash chain: a later boundary's identity hashes
    /// the account root it starts from, which holds the earlier boundary's
    /// identity. Change the earlier load and every later identity changes.
    #[test]
    fn the_funding_chain_commits_every_earlier_boundary() {
        let dev = device();
        let chain_after = |first: u64| {
            let first = dev
                .cross_offline_boundary(&BUNDLE, OfflineBoundaryKind::Load, &ASSET, first)
                .expect("first load");
            let second = first
                .new_device_state
                .cross_offline_boundary(&BUNDLE, OfflineBoundaryKind::Load, &ASSET, 5)
                .expect("second load");
            let body =
                OfflineBoundaryBody::of(&second, OfflineBoundaryKind::Load, BUNDLE, ASSET, 5)
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
        let (_, bytes) = body_of(&dev, OfflineBoundaryKind::Load, 30);
        let mut trailing = bytes.clone();
        trailing.push(0);
        refused(
            OfflineBoundaryBody::verify(&trailing, &dev.genesis(), &dev.devid()),
            "an offline boundary body:",
        );
        refused(
            OfflineBoundaryBody::verify(&bytes[..bytes.len() - 1], &dev.genesis(), &dev.devid()),
            "an offline boundary body:",
        );
    }
}
