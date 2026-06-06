// SPDX-License-Identifier: MIT OR Apache-2.0

//! Recovery activation seal (P4) — all-contact identity succession.
//!
//! > **EVIDENCE MODEL PARTIALLY SUPERSEDED** (see spec `recovery-and-dlv` §0.5).
//! > Recovery authority is the set of counterparties whose own *online-posted,
//! > genesis-authenticated* state proves they processed the tombstone and bound the
//! > successor — NOT a standalone signed `ContactTombstoneAck`, and NOT a public key
//! > looked up in the mutable local contacts DB. The per-ack `signature` +
//! > `latest_accepted_height` floor in this module are the interim model and are
//! > being replaced by: (a) verifying the counterparty's posted per-device
//! > tree/root against its genesis, and (b) a **hash forward-ancestry** floor check
//! > (DSM acceptance uses hash adjacency / parent consumption — never numeric
//! > heights/counters). The pieces that SURVIVE the redesign are kept here:
//! > all-contact **set-equality** over the gate-set and the gate-set commitment.
//! > `RecoverySDK::verify_and_record_activation` is fail-closed until the posted-tree
//! > authority + forward-ancestry are wired; do NOT wire a live unlock on this
//! > interim model.
//!
//! Pure, transport-independent validation of the recovery activation seal. The
//! successor device becomes spend-authoritative ONLY after every gate-set member
//! has emitted a valid Contact Tombstone Acknowledgement (set-equality), each ack
//! is counterparty-signed, and each ack confirms or extends forward from the
//! capsule's anti-rollback floor. This is the keystone that closes the recovery
//! double-spend window (spec vectors V1 split-acceptance, V3 rollback, V4
//! partial-ack).
//!
//! The gate-set passed in is the AUTHORITATIVE union (capsule `contact_set_commit`
//! ∪ publicly-discoverable contact anchors ∪ ack-claimed relationships); this
//! module enforces that the seal accounts for EXACTLY that set — it cannot be
//! shrunk by omission nor padded by substitution.

use crate::crypto::blake3::dsm_domain_hasher;
use crate::crypto::sphincs::{self, SphincsVariant};
use crate::recovery::capsule::contact_set_commit_from_device_ids;
use crate::types::error::DsmError;
use std::collections::{BTreeMap, BTreeSet};

const ACK_DOMAIN: &str = crate::common::domain_tags::TAG_DSM_RECOVERY_ACK;
const ACK_ROOT_DOMAIN: &str = crate::common::domain_tags::TAG_DSM_RECOVERY_ACK_ROOT;
const ACTIVATION_DOMAIN: &str = crate::common::domain_tags::TAG_DSM_RECOVERY_ACTIVATION;

/// Post-quantum signature scheme for counterparty acks (repo invariant: SPHINCS+).
const ACK_SIG_VARIANT: SphincsVariant = SphincsVariant::SPX256f;

/// The owner's own sealed per-relationship anti-rollback floor (from the capsule).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FloorTip {
    pub height: u64,
    pub tip: [u8; 32],
}

/// Lean Contact Tombstone Acknowledgement — a latest-frontier ack (anti-rollback
/// floor), not a receipt dump. "For `old_device_id`, my latest accepted frontier
/// for this relationship is `(latest_accepted_height, latest_accepted_tip)`, and
/// I bind that relationship to `successor_device_id`."
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactTombstoneAck {
    pub old_device_id: [u8; 32],
    pub successor_device_id: [u8; 32],
    pub counterparty_device_id: [u8; 32],
    pub relationship_key: [u8; 32],
    pub latest_accepted_tip: [u8; 32],
    pub latest_accepted_height: u64,
    /// Counterparty SPHINCS+ signature over [`Self::signing_bytes`].
    pub signature: Vec<u8>,
}

impl ContactTombstoneAck {
    /// Canonical signing bytes: every field except the signature, domain-separated
    /// and fixed-width, so encoding is unambiguous.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ACK_DOMAIN.len() + 1 + 32 * 5 + 8);
        out.extend_from_slice(ACK_DOMAIN.as_bytes());
        out.push(0u8);
        out.extend_from_slice(&self.old_device_id);
        out.extend_from_slice(&self.successor_device_id);
        out.extend_from_slice(&self.counterparty_device_id);
        out.extend_from_slice(&self.relationship_key);
        out.extend_from_slice(&self.latest_accepted_tip);
        out.extend_from_slice(&self.latest_accepted_height.to_le_bytes());
        out
    }

    /// Digest over the FULL ack including its signature — the leaf committed by
    /// the seal's `ack_root`.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = dsm_domain_hasher(ACK_DOMAIN);
        hasher.update(&self.signing_bytes());
        hasher.update(&(self.signature.len() as u32).to_le_bytes());
        hasher.update(&self.signature);
        *hasher.finalize().as_bytes()
    }
}

/// Commit to the complete, ordered ack set (sorted by counterparty id). Any
/// omission, substitution, or reordering changes this root.
pub fn compute_ack_root(acks: &[ContactTombstoneAck]) -> [u8; 32] {
    let mut sorted: Vec<&ContactTombstoneAck> = acks.iter().collect();
    sorted.sort_unstable_by(|a, b| a.counterparty_device_id.cmp(&b.counterparty_device_id));
    let mut hasher = dsm_domain_hasher(ACK_ROOT_DOMAIN);
    hasher.update(&(sorted.len() as u32).to_le_bytes());
    for ack in sorted {
        hasher.update(&ack.digest());
    }
    *hasher.finalize().as_bytes()
}

/// The recovery activation seal. Existence of a VALID seal is the sole condition
/// under which the successor device may become spend-authoritative.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryActivationSeal {
    pub genesis_id: [u8; 32],
    pub old_device_id: [u8; 32],
    pub new_device_id: [u8; 32],
    pub recovery_intent_digest: [u8; 32],
    pub tombstone_proposal_digest: [u8; 32],
    pub contact_set_commit: [u8; 32],
    pub ack_root: [u8; 32],
    pub synced_contact_count: u64,
    pub final_per_device_smt_root: [u8; 32],
    pub final_receipt_roll: [u8; 32],
}

impl RecoveryActivationSeal {
    /// Deterministic digest binding the whole seal.
    pub fn activation_digest(&self) -> [u8; 32] {
        let mut h = dsm_domain_hasher(ACTIVATION_DOMAIN);
        for f in [
            &self.genesis_id,
            &self.old_device_id,
            &self.new_device_id,
            &self.recovery_intent_digest,
            &self.tombstone_proposal_digest,
            &self.contact_set_commit,
            &self.ack_root,
            &self.final_per_device_smt_root,
            &self.final_receipt_roll,
        ] {
            h.update(f);
        }
        h.update(&self.synced_contact_count.to_le_bytes());
        *h.finalize().as_bytes()
    }
}

/// Validate the activation seal (P4 keystone). Returns `Ok(())` only if the
/// successor may become spend-authoritative.
///
/// - `gate_set`: the authoritative union of counterparties that MUST acknowledge.
///   It is non-shrinkable by construction (the caller supplies the union of the
///   capsule contact set, publicly-discoverable anchors, and ack-claimed
///   relationships).
/// - `floor`: the owner's own sealed per-relationship anti-rollback floor.
/// - `counterparty_pubkeys`: each gate-set counterparty's SPHINCS+ public key.
///
/// Enforces: count == gate-set size; `contact_set_commit` == commit(gate-set);
/// ack counterparties == gate-set EXACTLY (no omission/substitution/duplicate);
/// `ack_root` commits exactly these acks; and per ack: old→successor binding, a
/// valid counterparty signature, and no regression below the anti-rollback floor.
pub fn validate_activation_seal(
    seal: &RecoveryActivationSeal,
    acks: &[ContactTombstoneAck],
    gate_set: &BTreeSet<[u8; 32]>,
    floor: &BTreeMap<[u8; 32], FloorTip>,
    counterparty_pubkeys: &BTreeMap<[u8; 32], Vec<u8>>,
) -> Result<(), DsmError> {
    // 1. The seal's count matches the gate-set exactly.
    if seal.synced_contact_count as usize != gate_set.len() {
        return Err(DsmError::verification(format!(
            "activation seal synced_contact_count {} != gate-set size {}",
            seal.synced_contact_count,
            gate_set.len()
        )));
    }

    // 2. The seal commits to EXACTLY the gate-set (non-shrinkable anchor, R4).
    if seal.contact_set_commit != contact_set_commit_from_device_ids(gate_set) {
        return Err(DsmError::verification(
            "activation seal contact_set_commit does not match the gate-set",
        ));
    }

    // 3. Set-equality: ack counterparties == gate-set, with no duplicates, no
    //    omission, and no counterparty from outside the gate-set (V4).
    let mut ack_ids: BTreeSet<[u8; 32]> = BTreeSet::new();
    for ack in acks {
        if !ack_ids.insert(ack.counterparty_device_id) {
            return Err(DsmError::verification(
                "activation seal contains a duplicate counterparty ack",
            ));
        }
    }
    if &ack_ids != gate_set {
        return Err(DsmError::verification(
            "activation seal ack set is not equal to the gate-set (omission or substitution)",
        ));
    }

    // 4. The ack_root commits to exactly this ack set.
    if seal.ack_root != compute_ack_root(acks) {
        return Err(DsmError::verification("activation seal ack_root mismatch"));
    }

    // 5. Per-ack checks: binding, anti-rollback floor, signature.
    for ack in acks {
        if ack.old_device_id != seal.old_device_id
            || ack.successor_device_id != seal.new_device_id
        {
            return Err(DsmError::verification(
                "ack does not bind the old device to this successor",
            ));
        }

        // Anti-rollback floor (spec §5, R1): the counterparty must confirm the
        // floor exactly (==) or report a strictly higher tip (forward extension).
        // A tip below the floor is a rollback and is rejected. The full co-signed
        // forward receipt-adjacent chain (height > floor) is verified by the
        // caller (relationship freshness); the floor check here guarantees no
        // regression below the owner's sealed view.
        if let Some(f) = floor.get(&ack.counterparty_device_id) {
            if ack.latest_accepted_height < f.height {
                return Err(DsmError::verification(
                    "ack reports a tip below the capsule anti-rollback floor",
                ));
            }
            if ack.latest_accepted_height == f.height && ack.latest_accepted_tip != f.tip {
                return Err(DsmError::verification(
                    "ack confirms the floor height with a different tip",
                ));
            }
        }

        // Counterparty signature over the ack.
        let pk = counterparty_pubkeys
            .get(&ack.counterparty_device_id)
            .ok_or_else(|| {
                DsmError::verification(
                    "missing counterparty public key for ack signature verification",
                )
            })?;
        let ok = sphincs::verify(ACK_SIG_VARIANT, pk, &ack.signing_bytes(), &ack.signature)
            .map_err(|e| DsmError::verification(format!("ack signature verify error: {e}")))?;
        if !ok {
            return Err(DsmError::verification("invalid counterparty ack signature"));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sphincs::generate_keypair_from_seed;

    struct Party {
        id: [u8; 32],
        pk: Vec<u8>,
        sk: Vec<u8>,
    }

    fn party(seed_byte: u8) -> Party {
        let kp = generate_keypair_from_seed(ACK_SIG_VARIANT, &[seed_byte; 32]).expect("keygen");
        let mut id = [0u8; 32];
        id[0] = seed_byte;
        id[31] = 0xA5;
        Party {
            id,
            pk: kp.public_key.clone(),
            sk: kp.secret_key.clone(),
        }
    }

    fn signed_ack(p: &Party, old: [u8; 32], successor: [u8; 32], height: u64, tip: [u8; 32]) -> ContactTombstoneAck {
        let mut ack = ContactTombstoneAck {
            old_device_id: old,
            successor_device_id: successor,
            counterparty_device_id: p.id,
            relationship_key: [0x77; 32],
            latest_accepted_tip: tip,
            latest_accepted_height: height,
            signature: Vec::new(),
        };
        ack.signature = sphincs::sign(ACK_SIG_VARIANT, &p.sk, &ack.signing_bytes()).expect("sign");
        ack
    }

    /// Build a valid (gate_set, floor, pubkeys, acks, seal) fixture for `n` parties.
    fn fixture(n: u8) -> (
        BTreeSet<[u8; 32]>,
        BTreeMap<[u8; 32], FloorTip>,
        BTreeMap<[u8; 32], Vec<u8>>,
        Vec<ContactTombstoneAck>,
        RecoveryActivationSeal,
    ) {
        let old = [0x01; 32];
        let successor = [0x02; 32];
        let mut gate_set = BTreeSet::new();
        let mut floor = BTreeMap::new();
        let mut pubkeys = BTreeMap::new();
        let mut acks = Vec::new();
        for i in 0..n {
            let p = party(i + 1);
            gate_set.insert(p.id);
            // floor at height i; ack confirms it exactly.
            let tip = [i.wrapping_add(0x10); 32];
            floor.insert(p.id, FloorTip { height: i as u64, tip });
            pubkeys.insert(p.id, p.pk.clone());
            acks.push(signed_ack(&p, old, successor, i as u64, tip));
        }
        let seal = RecoveryActivationSeal {
            genesis_id: [0x09; 32],
            old_device_id: old,
            new_device_id: successor,
            recovery_intent_digest: [0x03; 32],
            tombstone_proposal_digest: [0x04; 32],
            contact_set_commit: contact_set_commit_from_device_ids(&gate_set),
            ack_root: compute_ack_root(&acks),
            synced_contact_count: gate_set.len() as u64,
            final_per_device_smt_root: [0x05; 32],
            final_receipt_roll: [0x06; 32],
        };
        (gate_set, floor, pubkeys, acks, seal)
    }

    #[test]
    fn valid_seal_passes() {
        let (gate, floor, pk, acks, seal) = fixture(3);
        validate_activation_seal(&seal, &acks, &gate, &floor, &pk).expect("valid seal");
    }

    #[test]
    fn omitted_member_fails() {
        let (gate, floor, pk, mut acks, mut seal) = fixture(3);
        acks.pop(); // drop one gate-set member's ack
        seal.ack_root = compute_ack_root(&acks);
        seal.synced_contact_count = acks.len() as u64; // even self-consistent seal must fail
        assert!(validate_activation_seal(&seal, &acks, &gate, &floor, &pk).is_err());
    }

    #[test]
    fn substituted_outsider_fails() {
        let (gate, floor, mut pk, mut acks, mut seal) = fixture(3);
        // Replace the last ack with one from a counterparty NOT in the gate-set.
        let outsider = party(0xEE);
        pk.insert(outsider.id, outsider.pk.clone());
        let old = seal.old_device_id;
        let succ = seal.new_device_id;
        *acks.last_mut().unwrap() = signed_ack(&outsider, old, succ, 0, [0x10; 32]);
        seal.ack_root = compute_ack_root(&acks);
        assert!(validate_activation_seal(&seal, &acks, &gate, &floor, &pk).is_err());
    }

    #[test]
    fn duplicate_ack_fails() {
        let (gate, floor, pk, mut acks, mut seal) = fixture(3);
        acks[2] = acks[0].clone(); // duplicate first, drop third
        seal.ack_root = compute_ack_root(&acks);
        assert!(validate_activation_seal(&seal, &acks, &gate, &floor, &pk).is_err());
    }

    #[test]
    fn below_floor_ack_fails() {
        let old = [0x01; 32];
        let successor = [0x02; 32];
        let p = party(5);
        let mut gate = BTreeSet::new();
        gate.insert(p.id);
        let mut floor = BTreeMap::new();
        floor.insert(p.id, FloorTip { height: 10, tip: [0x10; 32] });
        let mut pk = BTreeMap::new();
        pk.insert(p.id, p.pk.clone());
        // ack reports height 9 < floor 10 → rollback.
        let acks = vec![signed_ack(&p, old, successor, 9, [0x10; 32])];
        let seal = RecoveryActivationSeal {
            genesis_id: [0; 32],
            old_device_id: old,
            new_device_id: successor,
            recovery_intent_digest: [0; 32],
            tombstone_proposal_digest: [0; 32],
            contact_set_commit: contact_set_commit_from_device_ids(&gate),
            ack_root: compute_ack_root(&acks),
            synced_contact_count: 1,
            final_per_device_smt_root: [0; 32],
            final_receipt_roll: [0; 32],
        };
        assert!(validate_activation_seal(&seal, &acks, &gate, &floor, &pk).is_err());
    }

    #[test]
    fn floor_confirm_with_wrong_tip_fails() {
        let (gate, mut floor, pk, acks, seal) = fixture(1);
        // Same height as the ack but a different floor tip.
        let id = *gate.iter().next().unwrap();
        let h = floor[&id].height;
        floor.insert(id, FloorTip { height: h, tip: [0xFF; 32] });
        assert!(validate_activation_seal(&seal, &acks, &gate, &floor, &pk).is_err());
    }

    #[test]
    fn forward_extension_above_floor_passes() {
        let old = [0x01; 32];
        let successor = [0x02; 32];
        let p = party(7);
        let mut gate = BTreeSet::new();
        gate.insert(p.id);
        let mut floor = BTreeMap::new();
        floor.insert(p.id, FloorTip { height: 3, tip: [0x10; 32] });
        let mut pk = BTreeMap::new();
        pk.insert(p.id, p.pk.clone());
        // height 8 > floor 3 → forward extension allowed.
        let acks = vec![signed_ack(&p, old, successor, 8, [0x42; 32])];
        let seal = RecoveryActivationSeal {
            genesis_id: [0; 32],
            old_device_id: old,
            new_device_id: successor,
            recovery_intent_digest: [0; 32],
            tombstone_proposal_digest: [0; 32],
            contact_set_commit: contact_set_commit_from_device_ids(&gate),
            ack_root: compute_ack_root(&acks),
            synced_contact_count: 1,
            final_per_device_smt_root: [0; 32],
            final_receipt_roll: [0; 32],
        };
        validate_activation_seal(&seal, &acks, &gate, &floor, &pk).expect("forward extension ok");
    }

    #[test]
    fn tampered_signature_fails() {
        let (gate, floor, pk, mut acks, seal) = fixture(2);
        // Flip a byte in one ack's signature; ack_root still matches (seal built
        // from the tampered ack) so this isolates the signature check.
        acks[0].signature[0] ^= 0x01;
        let mut seal = seal;
        seal.ack_root = compute_ack_root(&acks);
        assert!(validate_activation_seal(&seal, &acks, &gate, &floor, &pk).is_err());
    }

    #[test]
    fn contact_set_commit_mismatch_fails() {
        let (gate, floor, pk, acks, mut seal) = fixture(2);
        seal.contact_set_commit[0] ^= 0x01;
        assert!(validate_activation_seal(&seal, &acks, &gate, &floor, &pk).is_err());
    }

    #[test]
    fn count_mismatch_fails() {
        let (gate, floor, pk, acks, mut seal) = fixture(2);
        seal.synced_contact_count = 1;
        assert!(validate_activation_seal(&seal, &acks, &gate, &floor, &pk).is_err());
    }

    #[test]
    fn ack_root_mismatch_fails() {
        let (gate, floor, pk, acks, mut seal) = fixture(2);
        seal.ack_root[0] ^= 0x01;
        assert!(validate_activation_seal(&seal, &acks, &gate, &floor, &pk).is_err());
    }
}
