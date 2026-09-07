// SPDX-License-Identifier: Apache-2.0

//! WHO AUTHORIZED A VAULT CLOSE.
//!
//! `x_close = H_dom(DSM/dlv-close-commit, vault_id ‖ parent_sequence)` is a
//! public derivation. It says a generation is consumed by a CLOSE rather than a
//! trade; it says nothing about who did it. Anyone can recompute it, put it in
//! a bundle naming a victim's vault at its current `c_n`, and bind that bundle
//! — the binding register is application-blind by design (§22 #12) and never
//! inspects the value, and `proposer_id` is 32 self-asserted bytes.
//!
//! So a composer that folded a close on binding finality alone would zero any
//! vault a stranger pointed at. The register establishes OCCUPANCY; it cannot
//! establish AUTHORITY, and nothing about making it Rev-15-conformant changes
//! that. The write-once register this replaces supplied the missing half
//! implicitly, by carrying an owner-signed claim envelope — which is exactly
//! the dependency that has to be made explicit here.
//!
//! **The proof is the operation DSM already signs.** [`Operation::DlvClose`]
//! binds the whole transition — the vault, both legs with their amounts, the
//! parent and terminal generation, and the fee that fixes the terminal vault
//! state — and its own documentation records the property that makes it usable
//! here: every field is DERIVED by the handler from the owner's verified
//! frontier, never supplied by a caller. A composer standing on that same
//! frontier can therefore RECONSTRUCT the exact operation and check the owner's
//! signature over it. `bundle_signatures[0]` carries only that signature.
//!
//! That is deliberately not a new commitment over `x_close` plus coordinates.
//! A parallel authorization would be a second canonical form of one object, and
//! the two could disagree; worse, a signature over a close DISCRIMINATOR is not
//! a signature over the release successor, which is what Rev-15 requires and
//! what actually moves the reserves. Reconstruction keeps exactly one signed
//! artifact in the system.
//!
//! **The reconstruction must stay total.** Every field below is derived from
//! the transition and the composed parent state. If one ever becomes free —
//! a `mode` that can vary, a field a composer cannot derive — the bundle must
//! carry the canonical operation bytes instead. Loosening the reconstruction
//! to accommodate a free field would silently unbind that field from the
//! signature, which is the failure this module exists to prevent.

use crate::crypto::sphincs::{sphincs_sign, sphincs_verify};
use crate::dlv::settlement_bundle::{self, BundleShape};
use crate::types::operations::{Operation, TransactionMode};
use crate::types::proto as generated;

/// Why a close is not authorized. Every variant is fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloseAuthError {
    /// The bundle is not a single owner-close (see `settlement_bundle::shape`).
    NotACloseBundle,
    /// The bundle carries no `bundle_signatures[0]`, or more than one.
    SignatureCount(usize),
    /// The signature does not verify under the vault owner's authority key.
    NotTheOwner,
    /// The signature is structurally unusable.
    Malformed(&'static str),
}

impl core::fmt::Display for CloseAuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CloseAuthError::NotACloseBundle => {
                write!(f, "this bundle is not a single owner-close")
            }
            CloseAuthError::SignatureCount(n) => {
                write!(f, "a close carries exactly one bundle signature, not {n}")
            }
            CloseAuthError::NotTheOwner => write!(
                f,
                "the close successor is not signed by the vault owner's authority key"
            ),
            CloseAuthError::Malformed(w) => write!(f, "close authorization is malformed: {w}"),
        }
    }
}
impl std::error::Error for CloseAuthError {}

/// The coordinates of the exact release successor, all of them derived from the
/// composed frontier the fold is standing on. This struct exists so the
/// reconstruction is stated once and both the signer and the verifier consume
/// it — a signer and verifier that each rebuilt the operation could disagree
/// about one field, and the signature would then cover less than it appears to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseSuccessor {
    pub vault_id: [u8; 32],
    /// The lex-lower and lex-higher legs of the vault's pair, with the FULL
    /// remaining reserves being released.
    pub leg_a_policy_commit: [u8; 32],
    pub leg_a_amount: u64,
    pub leg_b_policy_commit: [u8; 32],
    pub leg_b_amount: u64,
    /// The generation consumed. The terminal generation is `parent_sequence+1`
    /// — exactly one step, so it is derived rather than carried.
    pub parent_sequence: u64,
    pub fee_bps: u32,
}

/// Rebuild the exact `Operation::DlvClose` these coordinates authorize, with an
/// empty signature — the signed preimage is the operation with its signature
/// cleared, so this IS the preimage's source in both directions.
pub fn close_operation(s: &CloseSuccessor) -> Operation {
    Operation::DlvClose {
        vault_id: s.vault_id.to_vec(),
        leg_a_policy_commit: s.leg_a_policy_commit,
        leg_a_amount: s.leg_a_amount,
        leg_b_policy_commit: s.leg_b_policy_commit,
        leg_b_amount: s.leg_b_amount,
        parent_sequence: s.parent_sequence,
        new_sequence: s.parent_sequence.saturating_add(1),
        fee_bps: s.fee_bps,
        signature: Vec::new(),
        // Fixed for a close. Not a default: a close is a unilateral release of
        // the owner's own encumbered reserves, and the single production
        // construction site says so. A varying mode would have to be carried,
        // not assumed — see the module note on totality.
        mode: TransactionMode::Unilateral,
    }
}

/// The bytes the owner signs: the canonical operation with its signature
/// cleared. The repo's one signing preimage for operations, reused verbatim.
pub fn close_signing_payload(s: &CloseSuccessor) -> Vec<u8> {
    close_operation(s).with_cleared_signature().to_bytes()
}

/// Produce the owner's authorization over this exact successor. The returned
/// bytes are what `bundle_signatures[0]` carries.
pub fn sign_close_authorization(
    s: &CloseSuccessor,
    owner_secret_key: &[u8],
) -> Result<Vec<u8>, CloseAuthError> {
    sphincs_sign(owner_secret_key, &close_signing_payload(s))
        .map_err(|_| CloseAuthError::Malformed("the owner key could not sign"))
}

/// Verify that this bundle's close is authorized by `owner_ak_pk` for exactly
/// `successor`.
///
/// The caller supplies `successor` from the frontier it composed, NOT from the
/// bundle: reading the amounts out of the bundle and then checking a signature
/// over those same amounts would verify the bundle against itself. The
/// signature binds the successor the OWNER authorized; the transition's own
/// coordinates are checked against the same frontier by the occupancy layer.
pub fn verify_close_authorization(
    b: &generated::SettlementBundleV1,
    successor: &CloseSuccessor,
    owner_ak_pk: &[u8],
) -> Result<(), CloseAuthError> {
    if settlement_bundle::shape(b) != Ok(BundleShape::OwnerClose) {
        return Err(CloseAuthError::NotACloseBundle);
    }
    if b.bundle_signatures.len() != 1 {
        return Err(CloseAuthError::SignatureCount(b.bundle_signatures.len()));
    }
    let Some(sig) = b.bundle_signatures.first() else {
        return Err(CloseAuthError::SignatureCount(0));
    };
    if sig.is_empty() {
        return Err(CloseAuthError::Malformed("the signature is empty"));
    }
    if owner_ak_pk.is_empty() {
        return Err(CloseAuthError::Malformed("no owner authority key"));
    }
    match sphincs_verify(owner_ak_pk, &close_signing_payload(successor), sig) {
        Ok(true) => Ok(()),
        _ => Err(CloseAuthError::NotTheOwner),
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use crate::dlv::settlement_bundle::{close_slot_commitment, SETTLEMENT_BUNDLE_VERSION_V1};

    fn successor() -> CloseSuccessor {
        CloseSuccessor {
            vault_id: [0x77; 32],
            leg_a_policy_commit: [0xE0; 32],
            leg_a_amount: 10_000,
            leg_b_policy_commit: [0xF0; 32],
            leg_b_amount: 5_000,
            parent_sequence: 3,
            fee_bps: 30,
        }
    }

    fn close_bundle(sigs: Vec<Vec<u8>>, s: &CloseSuccessor) -> generated::SettlementBundleV1 {
        generated::SettlementBundleV1 {
            version: SETTLEMENT_BUNDLE_VERSION_V1,
            storage_set_id: vec![0x6B; 32],
            q: 2,
            intent_commitment: vec![0u8; 32],
            route_set_commitment: vec![0u8; 32],
            selected_route: Vec::new(),
            trader_parent: vec![0xC0; 32],
            trader_successor: close_slot_commitment(&s.vault_id, s.parent_sequence).to_vec(),
            vault_transitions: vec![generated::VaultTransitionV1 {
                vault_id: s.vault_id.to_vec(),
                parent_generation: s.parent_sequence,
                parent_state_commitment: vec![0xC0; 32],
                parent_reserves_digest: vec![0x0A; 32],
                successor_ccb: close_slot_commitment(&s.vault_id, s.parent_sequence).to_vec(),
                reserve_deltas: Vec::new(),
                witnesses: Vec::new(),
            }],
            proof_material: Vec::new(),
            bundle_signatures: sigs,
            recovery_material: Vec::new(),
        }
    }

    fn keypair() -> (Vec<u8>, Vec<u8>) {
        crate::crypto::sphincs::generate_sphincs_keypair().expect("keypair")
    }

    #[test]
    fn the_owners_signature_over_the_exact_successor_authorizes_the_close() {
        let (owner_pk, owner_sk) = keypair();
        let s = successor();
        let sig = sign_close_authorization(&s, &owner_sk).expect("sign");
        let b = close_bundle(vec![sig], &s);
        assert_eq!(verify_close_authorization(&b, &s, &owner_pk), Ok(()));
    }

    /// THE PROPERTY THIS MODULE EXISTS FOR. `x_close` is public, so a stranger
    /// can build a byte-identical close bundle for a victim's vault and bind
    /// it. What they cannot produce is this signature — and without it the
    /// composer must refuse rather than zero the vault.
    #[test]
    fn a_stranger_cannot_authorize_a_close_of_someone_elses_vault() {
        let (owner_pk, _) = keypair();
        let (_, stranger_sk) = keypair();
        let s = successor();
        let forged = sign_close_authorization(&s, &stranger_sk).expect("sign");
        let b = close_bundle(vec![forged], &s);
        assert_eq!(
            verify_close_authorization(&b, &s, &owner_pk),
            Err(CloseAuthError::NotTheOwner)
        );
    }

    /// A GENUINE owner signature is still not authorization for a DIFFERENT
    /// successor. Every field the fold consumes is inside the preimage, so a
    /// signature cannot be lifted from one close onto another — not to another
    /// vault, another generation, or another amount.
    #[test]
    fn a_genuine_signature_does_not_transfer_to_another_successor() {
        let (owner_pk, owner_sk) = keypair();
        let s = successor();
        let sig = sign_close_authorization(&s, &owner_sk).expect("sign");
        for mutate in [
            (|mut m: CloseSuccessor| {
                m.leg_b_amount += 1;
                m
            }) as fn(CloseSuccessor) -> CloseSuccessor,
            |mut m: CloseSuccessor| {
                m.leg_a_amount = 0;
                m
            },
            |mut m: CloseSuccessor| {
                m.vault_id = [0x78; 32];
                m
            },
            |mut m: CloseSuccessor| {
                m.parent_sequence += 1;
                m
            },
            |mut m: CloseSuccessor| {
                m.fee_bps += 1;
                m
            },
            |mut m: CloseSuccessor| {
                m.leg_a_policy_commit = [0xE1; 32];
                m
            },
        ] {
            let other = mutate(s.clone());
            let b = close_bundle(vec![sig.clone()], &other);
            assert_eq!(
                verify_close_authorization(&b, &other, &owner_pk),
                Err(CloseAuthError::NotTheOwner),
                "a signature over the original close must not authorize {other:?}"
            );
        }
    }

    /// The terminal generation is derived, not carried, so it cannot be moved
    /// independently of the parent it is one step above.
    #[test]
    fn the_terminal_generation_is_exactly_one_step_above_the_parent() {
        let s = successor();
        match close_operation(&s) {
            Operation::DlvClose {
                parent_sequence,
                new_sequence,
                ..
            } => {
                assert_eq!(parent_sequence, 3);
                assert_eq!(new_sequence, 4);
            }
            other => panic!("expected DlvClose, got {other:?}"),
        }
    }

    #[test]
    fn a_close_with_no_signature_or_several_is_refused() {
        let (owner_pk, owner_sk) = keypair();
        let s = successor();
        let sig = sign_close_authorization(&s, &owner_sk).expect("sign");
        assert_eq!(
            verify_close_authorization(&close_bundle(vec![], &s), &s, &owner_pk),
            Err(CloseAuthError::SignatureCount(0))
        );
        assert_eq!(
            verify_close_authorization(
                &close_bundle(vec![sig.clone(), sig.clone()], &s),
                &s,
                &owner_pk
            ),
            Err(CloseAuthError::SignatureCount(2))
        );
        assert_eq!(
            verify_close_authorization(&close_bundle(vec![Vec::new()], &s), &s, &owner_pk),
            Err(CloseAuthError::Malformed("the signature is empty"))
        );
    }

    /// A market bundle has no close to authorize, and asking is a category
    /// error rather than a signature failure.
    #[test]
    fn a_market_bundle_is_not_a_close_to_authorize() {
        let (owner_pk, owner_sk) = keypair();
        let s = successor();
        let sig = sign_close_authorization(&s, &owner_sk).expect("sign");
        let mut market = close_bundle(vec![sig], &s);
        market.vault_transitions[0].successor_ccb = vec![0x5C; 32];
        market.trader_successor = vec![0x5C; 32];
        assert_eq!(
            verify_close_authorization(&market, &s, &owner_pk),
            Err(CloseAuthError::NotACloseBundle)
        );
    }

    #[test]
    fn an_absent_owner_key_authorizes_nothing() {
        let (_, owner_sk) = keypair();
        let s = successor();
        let sig = sign_close_authorization(&s, &owner_sk).expect("sign");
        assert_eq!(
            verify_close_authorization(&close_bundle(vec![sig], &s), &s, &[]),
            Err(CloseAuthError::Malformed("no owner authority key"))
        );
    }
}
