// SPDX-License-Identifier: MIT OR Apache-2.0

//! The chain of an offline account's spends.
//!
//! Between two of its boundaries an offline account moves only by spends, and
//! the anchor releases each one: the release's certificate carries the chip's
//! and the partition's signatures over one root-advance message that binds the
//! device roots before and after, the frontier before and after, and the
//! counter's step. A verifier holding an account it validated — the account a
//! boundary of the owner's online history left — checks a chain of spends from
//! it hop by hop:
//!
//! - the anchor signed exactly this advance, under the keys the owner's pinned
//!   bundle `B` commits (`σ^chip`, `σ^host` over `M`, `h_{i+1} = H(h_i ‖ D)`,
//!   and `D` recomputed from the release's transition);
//! - the release's device root before commits, under `B`, the account the
//!   chain stands at, with the counter and frontier the advance starts from;
//! - the spend's write set — the allocation's debit, the counter's step and
//!   the frontier's advance — folds that account into the next one;
//! - the device root after commits that next account, at the counter's step
//!   and the advanced frontier.
//!
//! So value only leaves an account along a chain, and every hop is the one
//! successor the counter allowed at its position. A receiver that holds the
//! account a payer's last boundary left takes a spend from wherever the
//! payer's chain of spends since then has brought the account (SA-116), and
//! nothing a hop states is taken on trust: each is folded and signed.

use anchor_core::accept::verify_cert_frontier_and_sigs;
use anchor_core::root_advance::{transition_digest, OfflineRelease};
use anchor_core::tropic::{ChipSig, HostSig};
use prost::Message;

use crate::crypto::anchor_enrollment::FusedAnchorPin;
use crate::types::error::DsmError;
use crate::types::offline_account::{verify_offline_state_at, SpendWitness};

/// The most spends one chain carries. A payer with more unexposed spends than
/// this goes online, where a boundary exposes them, before it pays offline
/// again.
pub const MAX_CHAIN_HOPS: usize = 64;

/// The chip's resident Ed25519 key (`σ^chip`).
struct Ed25519Chip;

impl ChipSig for Ed25519Chip {
    fn verify(pk_chip: &[u8], message: &[u8; 32], sig: &[u8]) -> bool {
        let key: Result<[u8; 32], _> = pk_chip.try_into();
        let signature: Result<[u8; 64], _> = sig.try_into();
        matches!(
            (key, signature),
            (Ok(pk), Ok(sig)) if matches!(
                crate::crypto::classical_verify::verify_ed25519(&pk, message, &sig),
                Ok(())
            )
        )
    }
}

/// The RP2350 partition key, BLAKE3-SPHINCS+ SPX128f (`σ^host`).
struct SphincsHost;

impl HostSig for SphincsHost {
    fn verify(pk_host: &[u8], message: &[u8; 32], sig: &[u8]) -> bool {
        matches!(
            crate::crypto::sphincs::verify(
                crate::crypto::sphincs::SphincsVariant::SPX128f,
                pk_host,
                message,
                sig
            ),
            Ok(valid) if valid
        )
    }
}

/// One spend of an offline account, as its anchor released it.
#[derive(Clone)]
pub struct SpendHop {
    release: OfflineRelease,
    witness: SpendWitness,
    asset: [u8; 32],
    amount: u64,
}

impl core::fmt::Debug for SpendHop {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SpendHop")
            .field("release_message", &self.release.cert.root_advance_message)
            .field("anchor_counter", &self.release.cert.anchor_counter)
            .field("asset", &self.asset)
            .field("amount", &self.amount)
            .finish()
    }
}

fn decode_release(bytes: &[u8]) -> Result<OfflineRelease, DsmError> {
    anchor_core::proto::pb::OfflineRelease::decode(bytes)
        .map_err(|e| DsmError::invalid_operation(format!("a spend's release: {e}")))?
        .to_release()
        .map_err(|e| DsmError::invalid_operation(format!("a spend's release: {e:?}")))
}

impl SpendHop {
    /// The spend `release` (a `dsm.anchor.OfflineRelease`, its offline-state
    /// proofs attached) made of `amount` of `asset`, with the account witness
    /// its receipt carried.
    pub fn new(
        release: &[u8],
        witness: SpendWitness,
        asset: [u8; 32],
        amount: u64,
    ) -> Result<Self, DsmError> {
        Ok(Self {
            release: decode_release(release)?,
            witness,
            asset,
            amount,
        })
    }

    /// The hop a wire form states.
    pub fn from_proto(p: crate::types::proto::OfflineSpendHop) -> Result<Self, DsmError> {
        let witness =
            SpendWitness::from_proto(p.spend.ok_or_else(|| {
                DsmError::invalid_operation("a spend carries no account witness")
            })?)?;
        let asset = p.asset.as_slice().try_into().map_err(|e| {
            DsmError::invalid_operation(format!("a spend's asset is not 32 bytes: {e}"))
        })?;
        Self::new(&p.release, witness, asset, p.amount)
    }

    /// The hop's wire form.
    pub fn to_proto(&self) -> crate::types::proto::OfflineSpendHop {
        crate::types::proto::OfflineSpendHop {
            release: anchor_core::proto::encode_release(&self.release.to_pb()),
            spend: Some(self.witness.to_proto()),
            asset: self.asset.to_vec(),
            amount: self.amount,
        }
    }

    /// The hop a wire form's canonical bytes state.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DsmError> {
        Self::from_proto(
            crate::types::proto::OfflineSpendHop::decode(bytes)
                .map_err(|e| DsmError::invalid_operation(format!("an offline spend: {e}")))?,
        )
    }

    /// The account root the spend states it started from. Taken on trust by
    /// nobody: [`verify_spend_chain`] holds it to the account the chain stands
    /// at.
    pub fn starts_from(&self) -> [u8; 32] {
        self.witness.pre_account_root
    }

    /// The root-advance message `M` the anchor signed for this spend: what
    /// names it.
    pub fn release_message(&self) -> [u8; 32] {
        self.release.cert.root_advance_message
    }
}

/// The hops of a chain's wire form.
pub fn chain_from_proto(
    chain: crate::types::proto::OfflineSpendChain,
) -> Result<Vec<SpendHop>, DsmError> {
    if chain.hops.len() > MAX_CHAIN_HOPS {
        return Err(DsmError::invalid_operation(format!(
            "a chain of {} spends; at most {MAX_CHAIN_HOPS} are carried",
            chain.hops.len()
        )));
    }
    chain.hops.into_iter().map(SpendHop::from_proto).collect()
}

/// The hops of a chain's canonical bytes.
pub fn chain_from_bytes(bytes: &[u8]) -> Result<Vec<SpendHop>, DsmError> {
    chain_from_proto(
        crate::types::proto::OfflineSpendChain::decode(bytes)
            .map_err(|e| DsmError::invalid_operation(format!("an offline spend chain: {e}")))?,
    )
}

/// A chain's wire form.
pub fn chain_to_proto(hops: &[SpendHop]) -> crate::types::proto::OfflineSpendChain {
    crate::types::proto::OfflineSpendChain {
        hops: hops.iter().map(SpendHop::to_proto).collect(),
    }
}

/// The anchor a chain's spends are verified under: its bundle `B` and the keys
/// `B` commits, as the verifier pinned them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainAnchor {
    pub bundle: [u8; 32],
    pub anchor_id: [u8; 32],
    /// `pk_chip`, which verifies `σ^chip`.
    pub pk_chip: Vec<u8>,
    /// `pk_host`, which verifies `σ^host`.
    pub pk_host: Vec<u8>,
}

impl From<&FusedAnchorPin> for ChainAnchor {
    fn from(pin: &FusedAnchorPin) -> Self {
        Self {
            bundle: pin.bundle,
            anchor_id: pin.anchor_id,
            pk_chip: pin.pk_chip.clone(),
            pk_host: pin.partition_pk.clone(),
        }
    }
}

/// Where an offline account stands: its root, and the counter and frontier it
/// holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountPoint {
    pub root: [u8; 32],
    pub counter: u64,
    pub frontier: [u8; 32],
}

/// One spend of a verified chain: whom it paid, what, under which release,
/// and the account before and after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainPayment {
    pub recipient: [u8; 32],
    pub asset: [u8; 32],
    pub amount: u64,
    pub release_message: [u8; 32],
    pub before: AccountPoint,
    pub after: AccountPoint,
}

/// Verify `hops` as the chain of spends of the offline account of `anchor`'s
/// bundle from the account whose root is `start`: each hop is the anchor's
/// signed advance from the account the chain stands at to the next, folded by
/// its spend. Answers the payments in order; the account the chain leaves is
/// the last one's `after`, or `start` for an empty chain.
pub fn verify_spend_chain(
    start: &[u8; 32],
    anchor: &ChainAnchor,
    hops: &[SpendHop],
) -> Result<Vec<ChainPayment>, DsmError> {
    if hops.len() > MAX_CHAIN_HOPS {
        return Err(DsmError::invalid_operation(format!(
            "a chain of {} spends; at most {MAX_CHAIN_HOPS} are carried",
            hops.len()
        )));
    }
    let mut at = *start;
    let mut payments: Vec<ChainPayment> = Vec::with_capacity(hops.len());
    for (index, hop) in hops.iter().enumerate() {
        let refused = |why: &str| {
            DsmError::invalid_operation(format!("the offline spend chain's hop {index}: {why}"))
        };
        let cert = &hop.release.cert;
        let t = &hop.release.transition;
        if cert.anchor_bundle != anchor.bundle || cert.anchor_id != anchor.anchor_id {
            return Err(refused("it is not the pinned anchor's"));
        }
        // The release's transition is the certificate's advance, and the
        // certificate's digest is the transition's.
        if t.prev_root != cert.prev_frontier
            || t.next_root != cert.next_frontier
            || t.anchor_counter != cert.anchor_counter
            || t.next_anchor_counter != cert.next_anchor_counter
            || t.recipient_device_id != cert.recipient
            || transition_digest(&t.as_transition(), &cert.receiver_challenge)
                != cert.transition_digest
        {
            return Err(refused(
                "its transition is not the advance its certificate signs",
            ));
        }
        verify_cert_frontier_and_sigs::<Ed25519Chip, SphincsHost>(
            cert,
            &anchor.pk_chip,
            &anchor.pk_host,
        )
        .map_err(|e| refused(&format!("the anchor did not sign this advance: {e:?}")))?;
        let before_root = verify_offline_state_at(
            &cert.sender_device_root_before,
            &anchor.bundle,
            &cert.prev_frontier,
            cert.anchor_counter,
            &hop.release.offline_state_proof_before,
        )
        .map_err(|e| refused(&format!("its device root before: {e}")))?;
        if before_root != at {
            return Err(refused(
                "it does not start from the account the chain stands at",
            ));
        }
        let w = &hop.witness;
        if w.pre_account_root != at
            || w.pre_counter != cert.anchor_counter
            || w.pre_frontier != cert.prev_frontier
            || w.next_frontier != cert.next_frontier
        {
            return Err(refused("its spend is not the advance its release signs"));
        }
        let after_root = w
            .post_account_root(&hop.asset, hop.amount)
            .map_err(|e| refused(&format!("its spend does not fold: {e}")))?;
        let committed_after = verify_offline_state_at(
            &cert.sender_device_root_after,
            &anchor.bundle,
            &cert.next_frontier,
            cert.next_anchor_counter,
            &hop.release.offline_state_proof_after,
        )
        .map_err(|e| refused(&format!("its device root after: {e}")))?;
        if committed_after != after_root {
            return Err(refused(
                "its device root after does not commit the account its spend leaves",
            ));
        }
        payments.push(ChainPayment {
            recipient: cert.recipient,
            asset: hop.asset,
            amount: hop.amount,
            release_message: cert.root_advance_message,
            before: AccountPoint {
                root: at,
                counter: cert.anchor_counter,
                frontier: cert.prev_frontier,
            },
            after: AccountPoint {
                root: after_root,
                counter: cert.next_anchor_counter,
                frontier: cert.next_frontier,
            },
        });
        at = after_root;
    }
    Ok(payments)
}

/// The account a verified chain leaves: its last payment's, or `start`.
pub fn chain_end(start: &[u8; 32], payments: &[ChainPayment]) -> [u8; 32] {
    payments.last().map_or(*start, |last| last.after.root)
}

/// A payer for tests: a device whose offline account was loaded, and its
/// anchor — the anchor-core appliance on a chip in software with a resident
/// Ed25519 key and the SPHINCS+ partition key receivers verify `σ^host` with —
/// spending to one counterparty through the device's own `advance`.
#[cfg(test)]
pub(crate) mod fixture {
    use std::cell::Cell;
    use std::rc::Rc;

    use anchor_core::appliance::Appliance;
    use anchor_core::enrollment::{birth, BirthInputs};
    use anchor_core::root_advance::{anchor_root_advance, OwnedTransition, Transition};
    use anchor_core::tropic::{PartitionSig, Tropic, TropicError};
    use ed25519_dalek::{Signer, SigningKey};

    use super::{transition_digest, ChainAnchor, SpendHop};
    use crate::types::device_state::{DeviceState, OfflineBoundaryKind, OfflineSpend};
    use crate::types::operations::Operation;
    use crate::types::receipt_types::{DeviceTreeAcceptanceCommitment, ReceiptLeaf, StitchedReceiptV2};
    use crate::verification::receipt_verification::BearerLeaves;

    const H0: u32 = 32;

    pub(crate) struct Chip {
        counter: Rc<Cell<u32>>,
        resident: SigningKey,
    }

    impl Tropic for Chip {
        fn counter_get(&mut self) -> Result<u32, TropicError> {
            Ok(self.counter.get())
        }
        fn counter_update(&mut self) -> Result<(), TropicError> {
            let h = self.counter.get();
            self.counter
                .set(h.checked_sub(1).ok_or(TropicError::CounterExhausted)?);
            Ok(())
        }
        fn chip_sign(&mut self, message: &[u8; 32]) -> Result<Vec<u8>, TropicError> {
            Ok(self.resident.sign(message).to_bytes().to_vec())
        }
    }

    pub(crate) struct Partition;

    impl PartitionSig for Partition {
        fn part_keygen(seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
            let kp = crate::crypto::sphincs::generate_keypair_from_seed(
                crate::crypto::sphincs::SphincsVariant::SPX128f,
                seed,
            )
            .expect("the partition keypair");
            (kp.secret_key.clone(), kp.public_key.clone())
        }
        fn part_sign(sk: &[u8], digest: &[u8; 32]) -> Vec<u8> {
            crate::crypto::sphincs::sign(
                crate::crypto::sphincs::SphincsVariant::SPX128f,
                sk,
                digest,
            )
            .expect("the partition signs")
        }
        fn part_verify(pk: &[u8], digest: &[u8; 32], sig: &[u8]) -> bool {
            matches!(
                crate::crypto::sphincs::verify(
                    crate::crypto::sphincs::SphincsVariant::SPX128f,
                    pk,
                    digest,
                    sig
                ),
                Ok(valid) if valid
            )
        }
    }

    fn derive(seed: u8, input: &str) -> [u8; 32] {
        blake3::derive_key(&format!("DSM Core offline chain test {input}"), &[seed; 32])
    }

    /// A payer's offline-bearer transfer of `amount` of `token`, whose
    /// committed policy is `policy`, to `to`.
    pub(crate) fn bearer_op(
        to: [u8; 32],
        token: [u8; 32],
        policy: &[u8],
        amount: u64,
    ) -> Operation {
        use crate::types::operations::{
            canonical_offline_bearer_policy, TransactionMode, TransferTerms,
        };
        Operation::Transfer {
            to_device_id: to.to_vec(),
            amount: crate::types::token_types::Balance::amount(amount),
            policy_commit: token,
            terms_commitment: TransferTerms {
                token_id: b"ERA".to_vec(),
                nonce: Vec::new(),
                mode: TransactionMode::Bilateral,
                memo: String::new(),
                salt: vec![0x5A; 32],
            }
            .commitment(),
            token_policy: policy.to_vec(),
            signature: Vec::new(),
            authority_policy: Some(canonical_offline_bearer_policy()),
        }
    }

    pub(crate) struct Payer {
        pub(crate) head: DeviceState,
        pub(crate) app: Appliance<Chip, Partition>,
        pub(crate) pin: ChainAnchor,
        /// `H₀`, the enrolled counter.
        pub(crate) enrolled_counter: u32,
        /// The birth commitment `S_birth` `B` commits.
        pub(crate) birth_commitment: [u8; 32],
        pub(crate) token: [u8; 32],
        /// The token's committed `TokenPolicyV3` bytes.
        pub(crate) token_policy: Vec<u8>,
        pub(crate) genesis: [u8; 32],
        related: Vec<[u8; 32]>,
    }

    impl Payer {
        /// A device `seed` whose anchor is born for it and whose offline
        /// account, opened at the anchor's origin, a load of `loaded` funded.
        pub(crate) fn loaded(seed: u8, loaded: u64) -> Self {
            Self::loaded_with(
                seed,
                loaded,
                crate::economic::token_policy::POLICY_FLAG_TRANSFERABLE,
            )
        }

        /// [`Self::loaded`], the token's committed policy carrying `flags`.
        pub(crate) fn loaded_with(seed: u8, loaded: u64, flags: u8) -> Self {
            Self::loaded_on(
                crate::types::device_state::tests::fresh_device(seed),
                derive(seed, "genesis"),
                seed,
                loaded,
                flags,
            )
        }

        /// [`Self::loaded_with`] on `device`, a head whose genesis is
        /// `genesis`.
        pub(crate) fn loaded_on(
            device: DeviceState,
            genesis: [u8; 32],
            seed: u8,
            loaded: u64,
            flags: u8,
        ) -> Self {
            let resident = SigningKey::from_bytes(&derive(seed, "resident key"));
            let chip_pk = resident.verifying_key().to_bytes().to_vec();
            let (token, token_policy) = crate::sofi::validation::fixtures::committed(
                crate::sofi::validation::fixtures::token_policy_bytes_with(seed, flags),
            );
            let mut head = device.created_token(token, 100).expect("token created");
            let born = birth::<Partition>(&BirthInputs {
                partition_trng: &derive(seed, "partition trng"),
                chip_birth_witness: &derive(seed, "chip birth witness"),
                host_nonce: &derive(seed, "host nonce"),
                device_id: &head.devid(),
                policy_hash: &crate::types::operations::canonical_offline_bearer_policy().policy_id,
                partition_device_id: &derive(seed, "partition device id"),
                anchor_id: &derive(seed, "anchor id"),
                chip_pk: &chip_pk,
                online_id_pk: head.public_key(),
                partition_key_seed: &derive(seed, "partition key seed"),
                enrolled_counter: H0,
                genesis_root: &genesis,
            });
            let pin = ChainAnchor {
                bundle: born.bundle,
                anchor_id: derive(seed, "anchor id"),
                pk_chip: chip_pk,
                pk_host: born.partition_pk.clone(),
            };
            let birth_commitment = born.birth_commitment;
            let frontier = born.genesis_frontier;
            let app = Appliance::new(
                Chip {
                    counter: Rc::new(Cell::new(H0)),
                    resident,
                },
                H0,
                pin.anchor_id,
                derive(seed, "partition device id"),
                born,
            );
            head = head
                .open_offline_account(&pin.bundle, frontier, 0)
                .expect("the account opens at the anchor's origin")
                .cross_offline_boundary(&pin.bundle, OfflineBoundaryKind::Load, &token, loaded)
                .expect("the load")
                .new_device_state
                .into_head();
            Self {
                head,
                app,
                pin,
                enrolled_counter: H0,
                birth_commitment,
                token,
                token_policy,
                genesis,
                related: Vec::new(),
            }
        }

        /// The device's advance for a spend of `amount` to `to` from where its
        /// anchor stands, without its anchor: what Core decides of the step.
        pub(crate) fn advance_spend(
            &mut self,
            to: [u8; 32],
            amount: u64,
        ) -> Result<crate::types::device_state::AdvanceOutcome, crate::types::error::DsmError>
        {
            let rk = crate::core::bilateral_transaction_manager::compute_smt_key(
                &self.head.devid(),
                &to,
            );
            if !self.related.contains(&to) {
                self.head = self.head.establish_relationship(to).expect("establish");
                self.related.push(to);
            }
            self.head.advance(
                rk,
                to,
                bearer_op(to, self.token, &self.token_policy, amount),
                &[],
                Some(OfflineSpend {
                    anchor_bundle_b: self.pin.bundle,
                    asset: self.token,
                    amount,
                    next_frontier: derive(0x77, "a successor frontier"),
                }),
            )
        }

        /// The root of the account the device holds now.
        pub(crate) fn account_root(&self) -> [u8; 32] {
            self.head
                .offline_account(&self.pin.bundle)
                .expect("the account is open")
                .root()
        }

        /// Spend `amount` to `to` the way the sender does — stage on the
        /// anchor's frontier, advance, prepare over the advance's device roots,
        /// commit, emit with the offline-state proofs attached, finalize — and
        /// answer the spend as a hop, with the step's stitched receipt.
        pub(crate) fn spend(
            &mut self,
            to: [u8; 32],
            amount: u64,
        ) -> (SpendHop, StitchedReceiptV2, BearerLeaves) {
            let rk = crate::core::bilateral_transaction_manager::compute_smt_key(
                &self.head.devid(),
                &to,
            );
            if !self.related.contains(&to) {
                self.head = self.head.establish_relationship(to).expect("establish");
                self.related.push(to);
            }
            let operation = bearer_op(to, self.token, &self.token_policy, amount);
            let frontier = self.app.active.root;
            let counter = self.app.active.anchor_counter;
            let challenge = derive(counter as u8, "challenge");
            let policy = crate::types::operations::canonical_offline_bearer_policy().policy_id;
            let object = derive(0, "object");
            let payload = *blake3::hash(&operation.to_bytes()).as_bytes();
            let devid = self.head.devid();
            let core = Transition {
                relationship_id: &rk,
                object_id: &object,
                sender_device_id: &devid,
                recipient_device_id: &to,
                prev_root: &frontier,
                next_root: &frontier,
                anchor_counter: counter,
                next_anchor_counter: counter + 1,
                action_type: 0,
                action_fields: &[],
                payload_hash: &payload,
                old_leaf_proof: &[],
                new_leaf_proof: &[],
                authority_policy_hash: &policy,
            };
            let next = anchor_root_advance(&frontier, &transition_digest(&core, &challenge));
            let t = OwnedTransition {
                next_root: next,
                ..OwnedTransition::from(&core)
            };
            let out = self
                .head
                .advance(
                    rk,
                    to,
                    operation,
                    &[],
                    Some(OfflineSpend {
                        anchor_bundle_b: self.pin.bundle,
                        asset: self.token,
                        amount,
                        next_frontier: next,
                    }),
                )
                .expect("the spend advances");
            self.app
                .prepare(
                    &t.as_transition(),
                    &challenge,
                    &out.transition.pre_root(),
                    &out.child_r_a,
                )
                .expect("prepared");
            self.app.commit().expect("committed");
            let mut release = self.app.emit().expect("emitted").clone();
            let proofs = out.offline_state_proofs.as_ref().expect("a spend's proofs");
            release.offline_state_proof_before = proofs.parent.clone();
            release.offline_state_proof_after = proofs.child.clone();
            self.app.finalize().expect("finalized");
            let commitment = DeviceTreeAcceptanceCommitment::from_root(
                crate::common::device_tree::DeviceTree::single(devid).root(),
            );
            let leaves = BearerLeaves {
                bundle: self.pin.bundle,
                counter,
                frontier,
                next_frontier: next,
            };
            let receipt = StitchedReceiptV2::of_step(
                self.genesis,
                devid,
                to,
                &out,
                Some(leaves),
                &commitment,
            )
            .expect("the step's receipt");
            let witness = receipt
                .step_writes
                .iter()
                .find_map(|w| match &w.leaf {
                    ReceiptLeaf::OfflineAccount(witness) => Some((**witness).clone()),
                    ReceiptLeaf::Relationship => None,
                })
                .expect("the receipt writes the account");
            let hop = SpendHop::new(
                &anchor_core::proto::encode_release(&release.to_pb()),
                witness,
                self.token,
                amount,
            )
            .expect("the hop");
            self.head = out.new_device_state.into_head();
            (hop, receipt, leaves)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::Payer;
    use super::*;

    const B: [u8; 32] = [0xB0; 32];

    fn refused<T: core::fmt::Debug>(result: Result<T, DsmError>, reason: &str) {
        let error = result.expect_err(reason);
        assert!(error.to_string().contains(reason), "{error}");
    }

    /// A chain of spends verifies hop by hop from the account the payer's load
    /// left to the account the payer holds after them, and answers each
    /// payment: whom, what, and the account before and after.
    #[test]
    fn a_chain_of_spends_verifies_from_the_account_it_starts_at() {
        let mut payer = Payer::loaded(0x31, 40);
        let start = payer.account_root();
        let (first, _, _) = payer.spend(B, 10);
        let (second, _, _) = payer.spend(B, 5);
        let payments = verify_spend_chain(&start, &payer.pin, &[first.clone(), second])
            .expect("the chain verifies");
        assert_eq!(payments.len(), 2);
        assert_eq!(
            (
                payments[0].amount,
                payments[1].amount,
                payments[0].recipient
            ),
            (10, 5, B)
        );
        assert_eq!(payments[0].before.root, start);
        assert_eq!(payments[1].before, payments[0].after);
        assert_eq!(
            chain_end(&start, &payments),
            payer.account_root(),
            "the chain leaves the account the payer holds"
        );
        assert_eq!(
            (payments[1].after.counter, payments[0].before.counter),
            (2, 0)
        );
        assert_eq!(
            verify_spend_chain(&start, &payer.pin, &[]).expect("an empty chain"),
            Vec::new(),
            "an empty chain stands at its start"
        );
        let round_trip = chain_from_proto(chain_to_proto(&[first])).expect("the wire form");
        assert_eq!(
            verify_spend_chain(&start, &payer.pin, &round_trip)
                .expect("decoded")
                .len(),
            1
        );
    }

    /// Owner question 9, offline: the sender's Core refuses its own bearer
    /// spend of a token whose committed policy does not let it move, or whose
    /// carried policy bytes are not the token's, before anything is written.
    /// The receiver's Core refuses such a transfer in its own advance.
    /// MUTATION CONTROL: dropping `bearer_token_moves` from
    /// `validate_conservation` lets the spend and the receipt through and
    /// turns this red.
    #[test]
    fn a_bearer_transfer_of_a_token_that_may_not_move_is_refused_by_both_sides_advance() {
        use crate::types::device_state::{BalanceDelta, BalanceDirection};
        let mut locked = Payer::loaded_with(0x51, 40, 0);
        refused(locked.advance_spend(B, 10), "non-transferable");
        let mut misnamed = Payer::loaded(0x52, 40);
        misnamed.token_policy = crate::sofi::validation::fixtures::token_policy_bytes_with(
            0x53,
            crate::economic::token_policy::POLICY_FLAG_TRANSFERABLE,
        );
        refused(
            misnamed.advance_spend(B, 10),
            "are not the committed policy",
        );

        let payer = Payer::loaded_with(0x54, 40, 0);
        let receiver = crate::types::device_state::tests::fresh_device(0xB0)
            .establish_relationship(payer.head.devid())
            .expect("related");
        let rk = crate::core::bilateral_transaction_manager::compute_smt_key(
            &receiver.devid(),
            &payer.head.devid(),
        );
        refused(
            receiver.advance(
                rk,
                payer.head.devid(),
                super::fixture::bearer_op(receiver.devid(), payer.token, &payer.token_policy, 10),
                &[BalanceDelta {
                    policy_commit: payer.token,
                    direction: BalanceDirection::Credit,
                    amount: 10,
                }],
                None,
            ),
            "non-transferable",
        );
    }

    /// A chain that does not start from the account the verifier holds, or
    /// skips a hop, or reorders its hops, is refused: every hop starts where
    /// the previous one left the account.
    /// MUTATION CONTROL: dropping the start check turns this red.
    #[test]
    fn a_chain_that_does_not_continue_from_the_account_held_is_refused() {
        let mut payer = Payer::loaded(0x32, 40);
        let start = payer.account_root();
        let (first, _, _) = payer.spend(B, 10);
        let (second, _, _) = payer.spend(B, 5);
        refused(
            verify_spend_chain(&start, &payer.pin, std::slice::from_ref(&second)),
            "does not start from the account the chain stands at",
        );
        refused(
            verify_spend_chain(&start, &payer.pin, &[second, first]),
            "does not start from the account the chain stands at",
        );
    }

    /// A hop is the anchor's: signed under the keys of the pinned bundle,
    /// with its certificate intact. Another anchor's keys, a certificate whose
    /// signature was altered, or another bundle are refused.
    /// MUTATION CONTROL: dropping the signature check, or the bundle check,
    /// turns this red.
    #[test]
    fn a_hop_the_pinned_anchor_did_not_sign_is_refused() {
        let mut payer = Payer::loaded(0x33, 40);
        let other = Payer::loaded(0x34, 40);
        let start = payer.account_root();
        let (hop, _, _) = payer.spend(B, 10);
        let mut foreign_keys = payer.pin.clone();
        foreign_keys.pk_chip = other.pin.pk_chip.clone();
        refused(
            verify_spend_chain(&start, &foreign_keys, std::slice::from_ref(&hop)),
            "the anchor did not sign this advance",
        );
        let mut forged = hop.clone();
        forged.release.cert.sigma_host[0] ^= 1;
        refused(
            verify_spend_chain(&start, &payer.pin, &[forged]),
            "the anchor did not sign this advance",
        );
        refused(
            verify_spend_chain(&start, &other.pin, &[hop]),
            "it is not the pinned anchor's",
        );
    }

    /// A hop's spend is the advance its release signs: a witness stating
    /// another amount, another asset, another starting counter or frontier, or
    /// a device root after that commits another account, is refused.
    /// MUTATION CONTROL: dropping the witness's binding to the certificate, or
    /// the check that the root after commits the account the spend leaves,
    /// turns this red.
    #[test]
    fn a_hop_whose_spend_is_not_its_releases_advance_is_refused() {
        let mut payer = Payer::loaded(0x35, 40);
        let start = payer.account_root();
        let (hop, _, _) = payer.spend(B, 10);
        let mut less = hop.clone();
        less.amount = 3;
        refused(
            verify_spend_chain(&start, &payer.pin, &[less]),
            "does not commit the account its spend leaves",
        );
        let mut counter = hop.clone();
        counter.witness.pre_counter += 1;
        refused(
            verify_spend_chain(&start, &payer.pin, &[counter]),
            "its spend is not the advance its release signs",
        );
        let mut frontier = hop.clone();
        frontier.witness.next_frontier = [0x77; 32];
        refused(
            verify_spend_chain(&start, &payer.pin, &[frontier]),
            "its spend is not the advance its release signs",
        );
        let mut swapped = hop.clone();
        swapped.release.offline_state_proof_after = hop.release.offline_state_proof_before.clone();
        refused(
            verify_spend_chain(&start, &payer.pin, &[swapped]),
            "its device root after",
        );
        let mut transition = hop;
        transition.release.transition.payload_hash = [0x66; 32];
        refused(
            verify_spend_chain(&start, &payer.pin, &[transition]),
            "its transition is not the advance its certificate signs",
        );
    }
}
