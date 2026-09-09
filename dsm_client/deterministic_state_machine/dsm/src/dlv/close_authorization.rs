// SPDX-License-Identifier: Apache-2.0

//! WHO AUTHORIZED A VAULT CLOSE.
//!
//! A close bundle's SHAPE — `market_terms` absent, `close_authorization`
//! present (registry §5.19) — is public structure. It says a generation is
//! consumed by a CLOSE rather than a trade; it says nothing about who did it.
//! Anyone can build a bundle of that shape naming a victim's vault at its
//! current `c_n`, with the drained successor inside it and 49,856 bytes of
//! anything in field 4, and bind it — the binding register is
//! application-blind by design (§22 #12) and never inspects the value, and
//! `proposer_id` is 32 self-asserted bytes.
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
//! signature over it. `0x000F` field 4 `close_authorization` carries only that
//! signature — 2c-B froze the bytes it covers as `CloseAuthorizationPreimageV1`,
//! which is exactly `Operation::DlvClose` with its signature cleared.
//!
//! That is deliberately not a new commitment over `c_{n+1}` plus coordinates.
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
use crate::dlv::settlement_bundle::{self, BundleShape, SettlementBundle};
use crate::types::operations::{Operation, TransactionMode};

/// Why a close is not authorized. Every variant is fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloseAuthError {
    /// The bundle is not an owner close (see `settlement_bundle::shape`).
    NotACloseBundle,
    /// The signature does not verify under the vault owner's authority key.
    NotTheOwner,
    /// The signature is structurally unusable.
    Malformed(&'static str),
}

impl core::fmt::Display for CloseAuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CloseAuthError::NotACloseBundle => {
                write!(f, "this bundle is not an owner close")
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
/// bytes are what `0x000F` field 4 carries.
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
    b: &SettlementBundle,
    successor: &CloseSuccessor,
    owner_ak_pk: &[u8],
) -> Result<(), CloseAuthError> {
    if settlement_bundle::shape(b) != BundleShape::OwnerClose {
        return Err(CloseAuthError::NotACloseBundle);
    }
    // A close carries exactly one transition and it carries exactly one
    // authorization of exactly 49,856 bytes — by construction, so there is no
    // count or emptiness to check here.
    let Some(sig) = b
        .transitions()
        .first()
        .and_then(|t| t.close_authorization())
    else {
        return Err(CloseAuthError::NotACloseBundle);
    };
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
    use crate::ccb::settlement::fixtures;
    use crate::ccb::SPX256F_SIGNATURE_LEN;

    const PARENT: [u8; 32] = [0xC0; 32];

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

    /// The canonical close bundle for `s`: the drained successor at
    /// `parent_sequence + 1`, and `sig` in field 4.
    fn close_bundle(sig: Vec<u8>, s: &CloseSuccessor) -> SettlementBundle {
        fixtures::owner_close_bundle_with(
            PARENT,
            fixtures::successor_of(PARENT, s.vault_id, s.parent_sequence + 1, 0, 0),
            sig,
        )
    }

    fn keypair() -> (Vec<u8>, Vec<u8>) {
        crate::crypto::sphincs::generate_sphincs_keypair().expect("keypair")
    }

    #[test]
    fn the_owners_signature_over_the_exact_successor_authorizes_the_close() {
        let (owner_pk, owner_sk) = keypair();
        let s = successor();
        let sig = sign_close_authorization(&s, &owner_sk).expect("sign");
        assert_eq!(
            sig.len(),
            SPX256F_SIGNATURE_LEN,
            "the grammar's fixed length"
        );
        let b = close_bundle(sig, &s);
        assert_eq!(verify_close_authorization(&b, &s, &owner_pk), Ok(()));
    }

    /// THE PROPERTY THIS MODULE EXISTS FOR. The close SHAPE is public, so a
    /// stranger can build a canonical close bundle for a victim's vault and
    /// bind it. What they cannot produce is this signature — and without it
    /// the composer must refuse rather than zero the vault.
    #[test]
    fn a_stranger_cannot_authorize_a_close_of_someone_elses_vault() {
        let (owner_pk, _) = keypair();
        let (_, stranger_sk) = keypair();
        let s = successor();
        let forged = sign_close_authorization(&s, &stranger_sk).expect("sign");
        let b = close_bundle(forged, &s);
        assert_eq!(
            verify_close_authorization(&b, &s, &owner_pk),
            Err(CloseAuthError::NotTheOwner)
        );
        // …and so must a pattern of the right length that was never signed.
        let b = close_bundle(fixtures::signature_bytes(0x11), &s);
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
            let b = close_bundle(sig.clone(), &other);
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

    /// There is no close bundle with zero or several authorizations to refuse:
    /// the canonical object cannot carry them. What used to be a count check is
    /// now a construction refusal.
    #[test]
    fn a_close_without_one_authorization_of_the_fixed_length_cannot_be_built() {
        let s = successor();
        let v = fixtures::successor_of(PARENT, s.vault_id, s.parent_sequence + 1, 0, 0);
        assert!(crate::ccb::ConsumedDlvTransition::owner_close(PARENT, v.clone(), vec![]).is_err());
        assert!(crate::ccb::ConsumedDlvTransition::owner_close(
            PARENT,
            v,
            vec![0; SPX256F_SIGNATURE_LEN * 2]
        )
        .is_err());
    }

    /// A market bundle has no close to authorize, and asking is a category
    /// error rather than a signature failure.
    #[test]
    fn a_market_bundle_is_not_a_close_to_authorize() {
        let (owner_pk, _) = keypair();
        let s = successor();
        let market = fixtures::market_bundle(
            PARENT,
            fixtures::successor_of(PARENT, s.vault_id, s.parent_sequence + 1, 1, 1),
            [0x5C; 32],
        );
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
            verify_close_authorization(&close_bundle(sig, &s), &s, &[]),
            Err(CloseAuthError::Malformed("no owner authority key"))
        );
    }
}
