// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cert resync: the jointly authorized restart of one device's per-step EK
//! cert chain on a relationship, after that device lost its record of the
//! chain (DSM Amendment A20).
//!
//! A restart step stands in the restarting device's chain where an ordinary
//! step would. It continues the chain from the exact step its counterparty
//! holds as that device's latest, and its authority is both devices' AK
//! signatures over one statement: the relationship, that predecessor, the
//! agreed accepted tip, the epoch, the preserved acceptance commitment and
//! the new key. This module holds what both devices and every verifier
//! compute identically: the statement, the restart step's bytes, the
//! signature check, the check a chain walk runs on a restart step, and the
//! epoch rule. The head writes, the send gate, the pending-obligation guard
//! and the audit row are each device's own state, and are the SDK's.

use crate::common::domain_tags::{
    TAG_DSM_CERT_RESTART, TAG_DSM_CERT_RESTART_DONE, TAG_DSM_CERT_RESTART_REQUEST,
};
use crate::crypto::sphincs::{public_key_bytes, signature_bytes, sphincs_verify, SphincsVariant};
use crate::types::error::DsmError;
use crate::types::proto as generated;

/// The fields of one restart, as both devices and every verifier read them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartFields<'a> {
    /// The relationship: the two devices' own `compute_smt_key`.
    pub relationship_key: [u8; 32],
    /// The address of the step the restart continues: the restarting
    /// device's latest step, as its counterparty holds it.
    pub predecessor: [u8; 32],
    /// The relationship's tip at the agreed accepted step.
    pub agreed_tip: [u8; 32],
    pub epoch: u64,
    /// The acceptance commitment of the agreed accepted step.
    pub preserved_acceptance_commitment: [u8; 32],
    /// The restarting device's new per-step key.
    pub new_key: &'a [u8],
}

impl RestartFields<'_> {
    /// The statement both AKs sign:
    /// `BLAKE3("DSM/cert-restart/v1" ‖ 0x00 ‖ relationship ‖ predecessor ‖
    /// agreed tip ‖ epoch (u64, little-endian) ‖ preserved commitment ‖ new
    /// key)`. Every field but the last is fixed-length, so the bytes are
    /// unambiguous; a signature over one restart cannot be moved to another.
    pub fn statement(&self) -> [u8; 32] {
        let mut h = crate::crypto::blake3::dsm_domain_hasher(TAG_DSM_CERT_RESTART);
        h.update(&self.relationship_key);
        h.update(&self.predecessor);
        h.update(&self.agreed_tip);
        h.update(&self.epoch.to_le_bytes());
        h.update(&self.preserved_acceptance_commitment);
        h.update(self.new_key);
        *h.finalize().as_bytes()
    }

    /// The restart step both devices record and publish: the new key, the
    /// agreed tip as the step's `h_n`, the predecessor as its prior, and the
    /// restart authority carrying both signatures. Both devices build the
    /// same bytes, so the step has one address.
    pub fn step(
        &self,
        restarting_sig: Vec<u8>,
        counterparty_sig: Vec<u8>,
    ) -> generated::EkCertStepV1 {
        generated::EkCertStepV1 {
            ek_pk: self.new_key.to_vec(),
            authority: Some(generated::ek_cert_step_v1::Authority::Restart(
                generated::CertRestartV1 {
                    epoch: self.epoch,
                    preserved_acceptance_commitment: self.preserved_acceptance_commitment.to_vec(),
                    restarting_sig,
                    counterparty_sig,
                },
            )),
            h_n: self.agreed_tip.to_vec(),
            prior_step_addr: Some(self.predecessor.to_vec()),
        }
    }
}

/// Why a restart signature is refused. Each is its own reason: a key that is
/// not a key is never reported as a signature that does not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CosignatureRefusal {
    /// The signer's AK is not an SPX256f public key.
    MalformedKey { len: usize },
    /// The signature is not an SPX256f signature.
    MalformedSignature { len: usize },
    /// A well-formed signature that does not verify under the signer's AK
    /// over the statement.
    DoesNotVerify,
    /// The verifier refused its inputs.
    VerifierError(String),
}

impl std::fmt::Display for CosignatureRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedKey { len } => write!(
                f,
                "the signer's AK is {len} bytes, not an SPX256f public key ({})",
                public_key_bytes(SphincsVariant::SPX256f)
            ),
            Self::MalformedSignature { len } => write!(
                f,
                "the signature is {len} bytes, not an SPX256f signature ({})",
                signature_bytes(SphincsVariant::SPX256f)
            ),
            Self::DoesNotVerify => write!(
                f,
                "the signature does not verify under the signer's AK over the restart statement"
            ),
            Self::VerifierError(e) => write!(f, "the signature could not be verified: {e}"),
        }
    }
}

/// `signer_ak` signed exactly `statement`.
pub fn verify_restart_signature(
    signer_ak: &[u8],
    statement: &[u8; 32],
    signature: &[u8],
) -> Result<(), CosignatureRefusal> {
    if signer_ak.len() != public_key_bytes(SphincsVariant::SPX256f) {
        return Err(CosignatureRefusal::MalformedKey {
            len: signer_ak.len(),
        });
    }
    if signature.len() != signature_bytes(SphincsVariant::SPX256f) {
        return Err(CosignatureRefusal::MalformedSignature {
            len: signature.len(),
        });
    }
    let verified = sphincs_verify(signer_ak, statement, signature)
        .map_err(|e| CosignatureRefusal::VerifierError(e.to_string()))?;
    if !verified {
        return Err(CosignatureRefusal::DoesNotVerify);
    }
    Ok(())
}

/// One device of a relationship, as a restart check reads it.
#[derive(Debug, Clone, Copy)]
pub struct RestartParty<'a> {
    pub devid: [u8; 32],
    /// The device's P0–P6-proven AK — never a key found beside the step.
    pub proven_ak: &'a [u8],
}

/// Why a restart step does not chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestartRefusal {
    /// It names no step it continues: that would be a re-root.
    NoPredecessor,
    /// A field is not its fixed length.
    MalformedField { what: &'static str, cause: String },
    /// The new key is not an SPX256f public key.
    NewKeyNotAKey { len: usize },
    /// Its epoch does not exceed that of an earlier restart in the same walk.
    EpochNotAfter { epoch: u64, earlier: u64 },
    /// The restarting device's AK did not sign this restart.
    Restarting(CosignatureRefusal),
    /// The counterparty's AK did not sign this restart.
    Counterparty(CosignatureRefusal),
}

impl std::fmt::Display for RestartRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoPredecessor => write!(f, "a restart step names no step it continues"),
            Self::MalformedField { what, cause } => {
                write!(f, "the restart step's {what} is not 32 bytes ({cause})")
            }
            Self::NewKeyNotAKey { len } => write!(
                f,
                "the restart's new key is {len} bytes, not an SPX256f public key ({})",
                public_key_bytes(SphincsVariant::SPX256f)
            ),
            Self::EpochNotAfter { epoch, earlier } => write!(
                f,
                "the restart's epoch {epoch} does not exceed an earlier restart's, {earlier}"
            ),
            Self::Restarting(r) => write!(f, "the restarting device's signature: {r}"),
            Self::Counterparty(r) => write!(f, "the counterparty's signature: {r}"),
        }
    }
}

fn fixed(bytes: &[u8], what: &'static str) -> Result<[u8; 32], RestartRefusal> {
    <[u8; 32]>::try_from(bytes).map_err(|e| RestartRefusal::MalformedField {
        what,
        cause: e.to_string(),
    })
}

/// The check a walk of `restarting`'s chain runs on one restart step. The
/// statement is recomputed from the step's own fields and the relationship
/// the two devices form; both devices' AKs must have signed it, and its epoch
/// must exceed `earlier_epoch`, the last restart the same walk passed. The
/// step's new key is then the next expected key; returns the epoch.
pub fn check_restart_step(
    step: &generated::EkCertStepV1,
    restart: &generated::CertRestartV1,
    restarting: RestartParty<'_>,
    counterparty: RestartParty<'_>,
    earlier_epoch: Option<u64>,
) -> Result<u64, RestartRefusal> {
    let predecessor = match &step.prior_step_addr {
        Some(p) => fixed(p, "predecessor")?,
        None => return Err(RestartRefusal::NoPredecessor),
    };
    if step.ek_pk.len() != public_key_bytes(SphincsVariant::SPX256f) {
        return Err(RestartRefusal::NewKeyNotAKey {
            len: step.ek_pk.len(),
        });
    }
    if let Some(earlier) = earlier_epoch {
        if restart.epoch <= earlier {
            return Err(RestartRefusal::EpochNotAfter {
                epoch: restart.epoch,
                earlier,
            });
        }
    }
    let fields = RestartFields {
        relationship_key: crate::core::bilateral_transaction_manager::compute_smt_key(
            &restarting.devid,
            &counterparty.devid,
        ),
        predecessor,
        agreed_tip: fixed(&step.h_n, "agreed tip")?,
        epoch: restart.epoch,
        preserved_acceptance_commitment: fixed(
            &restart.preserved_acceptance_commitment,
            "preserved acceptance commitment",
        )?,
        new_key: &step.ek_pk,
    };
    let statement = fields.statement();
    verify_restart_signature(restarting.proven_ak, &statement, &restart.restarting_sig)
        .map_err(RestartRefusal::Restarting)?;
    verify_restart_signature(
        counterparty.proven_ak,
        &statement,
        &restart.counterparty_sig,
    )
    .map_err(RestartRefusal::Counterparty)?;
    Ok(restart.epoch)
}

/// The statement the restarting device's AK signs to ask for a restart:
/// `BLAKE3("DSM/cert-restart-request/v1" ‖ 0x00 ‖ relationship ‖ agreed tip
/// ‖ epoch (u64, little-endian) ‖ preserved commitment ‖ new key)`. The
/// predecessor is not in it: the counterparty supplies that.
pub fn restart_request_statement(
    relationship_key: &[u8; 32],
    agreed_tip: &[u8; 32],
    epoch: u64,
    preserved_acceptance_commitment: &[u8; 32],
    new_key: &[u8],
) -> [u8; 32] {
    let mut h = crate::crypto::blake3::dsm_domain_hasher(TAG_DSM_CERT_RESTART_REQUEST);
    h.update(relationship_key);
    h.update(agreed_tip);
    h.update(&epoch.to_le_bytes());
    h.update(preserved_acceptance_commitment);
    h.update(new_key);
    *h.finalize().as_bytes()
}

/// The statement the counterparty's AK signs once it recorded a restart step:
/// `BLAKE3("DSM/cert-restart-done/v1" ‖ 0x00 ‖ restart step address ‖ the
/// counterparty's own latest step address)`. The restarting device takes the
/// restart only on it.
pub fn restart_done_statement(restart_step: &[u8; 32], counterparty_step: &[u8; 32]) -> [u8; 32] {
    let mut h = crate::crypto::blake3::dsm_domain_hasher(TAG_DSM_CERT_RESTART_DONE);
    h.update(restart_step);
    h.update(counterparty_step);
    *h.finalize().as_bytes()
}

/// The relationship's latest accepted step, as a device's own record holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgreedStep {
    /// Its tip: the relationship's current tip.
    pub tip: [u8; 32],
    /// Its acceptance commitment.
    pub commitment: [u8; 32],
    /// The tip its receipt was taken from: the `h_n` both devices' ordinary
    /// steps at it are certified at.
    pub receipt_parent: [u8; 32],
}

/// Why an offered step is not at the agreed accepted step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfferedStepRefusal {
    /// An ordinary step certified at another tip than the agreed step's.
    NotAtTheAgreedStep,
    /// A restart step at another agreed tip.
    AnotherRestartTip,
    /// A step that carries no authority.
    NoAuthority,
}

impl std::fmt::Display for OfferedStepRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAtTheAgreedStep => write!(
                f,
                "the step was certified at another tip than the agreed accepted step's"
            ),
            Self::AnotherRestartTip => {
                write!(f, "the step is a restart at another agreed tip")
            }
            Self::NoAuthority => write!(f, "the step carries no authority"),
        }
    }
}

/// An offered step (the predecessor a counterparty supplies, or its own
/// latest step) is at the agreed accepted step: an ordinary step was
/// certified at that step's receipt parent, and a restart step (no step since
/// an earlier restart) names the agreed tip itself.
pub fn check_offered_step_position(
    step: &generated::EkCertStepV1,
    agreed: &AgreedStep,
) -> Result<(), OfferedStepRefusal> {
    match &step.authority {
        Some(generated::ek_cert_step_v1::Authority::EkCert(_)) => {
            if step.h_n.as_slice() != agreed.receipt_parent.as_slice() {
                return Err(OfferedStepRefusal::NotAtTheAgreedStep);
            }
        }
        Some(generated::ek_cert_step_v1::Authority::Restart(_)) => {
            if step.h_n.as_slice() != agreed.tip.as_slice() {
                return Err(OfferedStepRefusal::AnotherRestartTip);
            }
        }
        None => return Err(OfferedStepRefusal::NoAuthority),
    }
    Ok(())
}

/// A resync's epoch is strictly greater than the last one the relationship
/// recorded, so a captured request cannot re-apply.
pub fn cert_resync_epoch_advances(epoch: i64, last_epoch: i64) -> Result<(), DsmError> {
    if epoch <= last_epoch {
        return Err(DsmError::invalid_operation(format!(
            "cert resync epoch {epoch} is not greater than the last, {last_epoch}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sphincs::{generate_keypair_from_seed, sphincs_sign, SphincsKeyPair};

    fn ak(seed: u8) -> SphincsKeyPair {
        generate_keypair_from_seed(SphincsVariant::SPX256f, &[seed; 32]).expect("an AK")
    }

    /// The statement, on fixed inputs, is the digest `b3sum` gives for
    /// `"DSM/cert-restart/v1" ‖ 0x00 ‖ relationship ‖ predecessor ‖ agreed
    /// tip ‖ epoch (u64, little-endian) ‖ preserved commitment ‖ new key`.
    #[test]
    fn the_restart_statement_is_the_pinned_bytes() {
        const STATEMENT: [u8; 32] = [
            0xB7, 0xA7, 0x59, 0x56, 0xC4, 0x6B, 0x86, 0x24, 0xB6, 0x66, 0xAE, 0xFF, 0x36, 0xF4,
            0xBE, 0xD8, 0x41, 0x90, 0xF9, 0x17, 0xE6, 0xCB, 0x91, 0xF3, 0x74, 0x02, 0x7A, 0xC9,
            0x02, 0x17, 0x17, 0xCB,
        ];
        let key = [0x55u8; 64];
        let fields = RestartFields {
            relationship_key: [0x11; 32],
            predecessor: [0x22; 32],
            agreed_tip: [0x33; 32],
            epoch: 7,
            preserved_acceptance_commitment: [0x44; 32],
            new_key: &key,
        };
        assert_eq!(fields.statement(), STATEMENT);
    }

    /// The statement binds every field: changing any one changes it.
    #[test]
    fn the_restart_statement_binds_every_field() {
        let (key, other_key) = ([1u8; 64], [9u8; 64]);
        let base = RestartFields {
            relationship_key: [1; 32],
            predecessor: [2; 32],
            agreed_tip: [3; 32],
            epoch: 4,
            preserved_acceptance_commitment: [5; 32],
            new_key: &key,
        };
        let changed = [
            RestartFields {
                relationship_key: [9; 32],
                ..base.clone()
            },
            RestartFields {
                predecessor: [9; 32],
                ..base.clone()
            },
            RestartFields {
                agreed_tip: [9; 32],
                ..base.clone()
            },
            RestartFields {
                epoch: 9,
                ..base.clone()
            },
            RestartFields {
                preserved_acceptance_commitment: [9; 32],
                ..base.clone()
            },
            RestartFields {
                new_key: &other_key,
                ..base.clone()
            },
        ];
        for (i, c) in changed.iter().enumerate() {
            assert_ne!(base.statement(), c.statement(), "field {i}");
        }
    }

    /// A restart step for `restarting` (seed 0x51) and its counterparty (seed
    /// 0x52) on the relationship of devices 0xA1 and 0xB2, continuing the step
    /// at 0x22.., both signatures over its own fields.
    struct Fixture {
        restarting: SphincsKeyPair,
        counterparty: SphincsKeyPair,
        new_key: SphincsKeyPair,
    }

    const DEV_R: [u8; 32] = [0xA1; 32];
    const DEV_C: [u8; 32] = [0xB2; 32];

    impl Fixture {
        fn new() -> Self {
            Self {
                restarting: ak(0x51),
                counterparty: ak(0x52),
                new_key: ak(0x53),
            }
        }

        fn fields(&self, epoch: u64) -> RestartFields<'_> {
            RestartFields {
                relationship_key: crate::core::bilateral_transaction_manager::compute_smt_key(
                    &DEV_R, &DEV_C,
                ),
                predecessor: [0x22; 32],
                agreed_tip: [0x33; 32],
                epoch,
                preserved_acceptance_commitment: [0x44; 32],
                new_key: &self.new_key.public_key,
            }
        }

        fn step(&self, epoch: u64) -> generated::EkCertStepV1 {
            let fields = self.fields(epoch);
            let statement = fields.statement();
            fields.step(
                sphincs_sign(&self.restarting.secret_key, &statement).expect("sign"),
                sphincs_sign(&self.counterparty.secret_key, &statement).expect("sign"),
            )
        }

        fn check(
            &self,
            step: &generated::EkCertStepV1,
            earlier: Option<u64>,
        ) -> Result<u64, RestartRefusal> {
            let Some(generated::ek_cert_step_v1::Authority::Restart(restart)) = &step.authority
            else {
                panic!("not a restart step");
            };
            check_restart_step(
                step,
                restart,
                RestartParty {
                    devid: DEV_R,
                    proven_ak: &self.restarting.public_key,
                },
                RestartParty {
                    devid: DEV_C,
                    proven_ak: &self.counterparty.public_key,
                },
                earlier,
            )
        }
    }

    fn restart_of(step: &mut generated::EkCertStepV1) -> &mut generated::CertRestartV1 {
        match &mut step.authority {
            Some(generated::ek_cert_step_v1::Authority::Restart(r)) => r,
            _ => panic!("not a restart step"),
        }
    }

    /// A restart step both AKs signed over its own fields chains, and its
    /// epoch is returned. Each field the statement binds, changed after
    /// signing, leaves a step that does not chain; so does a step one device
    /// alone signed, a signature by another key, and the two signatures
    /// swapped between the roles.
    #[test]
    fn a_restart_step_chains_only_with_both_signatures_over_its_own_fields() {
        let fx = Fixture::new();
        let step = fx.step(3);
        assert_eq!(fx.check(&step, None), Ok(3));

        let does_not_verify = |who: &str, r: Result<u64, RestartRefusal>| match r {
            Err(RestartRefusal::Restarting(CosignatureRefusal::DoesNotVerify))
            | Err(RestartRefusal::Counterparty(CosignatureRefusal::DoesNotVerify)) => {}
            other => panic!("{who}: {other:?}"),
        };

        let mut predecessor = step.clone();
        predecessor.prior_step_addr = Some(vec![0x23; 32]);
        does_not_verify("another predecessor", fx.check(&predecessor, None));

        let mut tip = step.clone();
        tip.h_n = vec![0x34; 32];
        does_not_verify("another agreed tip", fx.check(&tip, None));

        let mut epoch = step.clone();
        restart_of(&mut epoch).epoch = 4;
        does_not_verify("another epoch", fx.check(&epoch, None));

        let mut commitment = step.clone();
        restart_of(&mut commitment).preserved_acceptance_commitment = vec![0x45; 32];
        does_not_verify("another commitment", fx.check(&commitment, None));

        let mut key = step.clone();
        key.ek_pk = ak(0x54).public_key.clone();
        does_not_verify("another new key", fx.check(&key, None));

        let statement = fx.fields(3).statement();
        let forged = sphincs_sign(&ak(0x55).secret_key, &statement).expect("sign");
        let mut by_another = step.clone();
        restart_of(&mut by_another).counterparty_sig = forged;
        assert_eq!(
            fx.check(&by_another, None),
            Err(RestartRefusal::Counterparty(
                CosignatureRefusal::DoesNotVerify
            ))
        );

        let mut swapped = step.clone();
        let r = restart_of(&mut swapped);
        std::mem::swap(&mut r.restarting_sig, &mut r.counterparty_sig);
        assert_eq!(
            fx.check(&swapped, None),
            Err(RestartRefusal::Restarting(
                CosignatureRefusal::DoesNotVerify
            ))
        );

        let mut alone = step.clone();
        restart_of(&mut alone).counterparty_sig = Vec::new();
        assert_eq!(
            fx.check(&alone, None),
            Err(RestartRefusal::Counterparty(
                CosignatureRefusal::MalformedSignature { len: 0 }
            ))
        );
        let mut unsigned = step.clone();
        restart_of(&mut unsigned).restarting_sig = Vec::new();
        assert_eq!(
            fx.check(&unsigned, None),
            Err(RestartRefusal::Restarting(
                CosignatureRefusal::MalformedSignature { len: 0 }
            ))
        );
    }

    /// A restart that names no step it continues is a re-root and does not
    /// chain, however it is signed; a new key that is not a key does not
    /// either.
    #[test]
    fn a_restart_naming_no_predecessor_or_no_key_does_not_chain() {
        let fx = Fixture::new();
        let mut rerooted = fx.step(1);
        rerooted.prior_step_addr = None;
        assert_eq!(
            fx.check(&rerooted, None),
            Err(RestartRefusal::NoPredecessor)
        );

        let mut keyless = fx.step(1);
        keyless.ek_pk = vec![0x53; 63];
        assert_eq!(
            fx.check(&keyless, None),
            Err(RestartRefusal::NewKeyNotAKey { len: 63 })
        );
    }

    /// Within one walk, a restart's epoch must exceed that of the restart
    /// before it: the same epoch again, or a lower one, does not chain.
    #[test]
    fn a_restart_whose_epoch_does_not_exceed_an_earlier_one_does_not_chain() {
        let fx = Fixture::new();
        for (epoch, earlier) in [(5, 5), (4, 5)] {
            assert_eq!(
                fx.check(&fx.step(epoch), Some(earlier)),
                Err(RestartRefusal::EpochNotAfter { epoch, earlier })
            );
        }
        assert_eq!(fx.check(&fx.step(6), Some(5)), Ok(6));
    }

    /// A key that is not an SPX256f public key and a signature that is not an
    /// SPX256f signature are each refused as what they are.
    #[test]
    fn a_malformed_key_or_signature_is_refused_as_itself() {
        let signer = ak(0x61);
        let statement = [0x62u8; 32];
        let sig = sphincs_sign(&signer.secret_key, &statement).expect("sign");
        verify_restart_signature(&signer.public_key, &statement, &sig).expect("its own statement");
        let short_key = &signer.public_key[1..];
        assert_eq!(
            verify_restart_signature(short_key, &statement, &sig),
            Err(CosignatureRefusal::MalformedKey {
                len: short_key.len()
            })
        );
        let short_sig = &sig[1..];
        assert_eq!(
            verify_restart_signature(&signer.public_key, &statement, short_sig),
            Err(CosignatureRefusal::MalformedSignature {
                len: short_sig.len()
            })
        );
    }

    /// The request and done statements, on fixed inputs, are the digests
    /// `b3sum` gives for their tags followed by their fields.
    #[test]
    fn the_request_and_done_statements_are_the_pinned_bytes() {
        const REQUEST: [u8; 32] = [
            0x8B, 0x01, 0x12, 0xD7, 0x08, 0x2E, 0x1A, 0x80, 0xA5, 0xB1, 0x95, 0x10, 0xCB, 0xD0,
            0xCC, 0x1F, 0xEE, 0x14, 0xFE, 0xD2, 0xB3, 0x3A, 0x74, 0x70, 0xD2, 0x70, 0xD2, 0xFE,
            0xA2, 0x58, 0x20, 0x83,
        ];
        const DONE: [u8; 32] = [
            0xED, 0x1B, 0x3D, 0xA5, 0x93, 0xE7, 0xF4, 0xAC, 0xFF, 0xDD, 0x3C, 0xDD, 0x84, 0x5F,
            0x2E, 0x6A, 0xA1, 0x01, 0x57, 0x0B, 0x92, 0x46, 0x91, 0xD9, 0x26, 0xFB, 0x04, 0xCB,
            0xA9, 0x69, 0xF8, 0x08,
        ];
        assert_eq!(
            restart_request_statement(&[0x11; 32], &[0x33; 32], 7, &[0x44; 32], &[0x55; 64]),
            REQUEST
        );
        assert_eq!(restart_done_statement(&[0x66; 32], &[0x77; 32]), DONE);
    }

    /// An ordinary step is at the agreed step only when certified at its
    /// receipt parent; a restart step only when it names the agreed tip.
    #[test]
    fn an_offered_step_is_at_the_agreed_step_only_at_its_tip() {
        let agreed = AgreedStep {
            tip: [0x01; 32],
            commitment: [0x02; 32],
            receipt_parent: [0x03; 32],
        };
        let ordinary = |h: [u8; 32]| generated::EkCertStepV1 {
            ek_pk: vec![0x04; 64],
            authority: Some(generated::ek_cert_step_v1::Authority::EkCert(vec![0x05; 8])),
            h_n: h.to_vec(),
            prior_step_addr: None,
        };
        assert_eq!(
            check_offered_step_position(&ordinary([0x03; 32]), &agreed),
            Ok(())
        );
        assert_eq!(
            check_offered_step_position(&ordinary([0x01; 32]), &agreed),
            Err(OfferedStepRefusal::NotAtTheAgreedStep)
        );
        let fx = Fixture::new();
        let mut restart = fx.step(1);
        restart.h_n = vec![0x01; 32];
        assert_eq!(check_offered_step_position(&restart, &agreed), Ok(()));
        restart.h_n = vec![0x03; 32];
        assert_eq!(
            check_offered_step_position(&restart, &agreed),
            Err(OfferedStepRefusal::AnotherRestartTip)
        );
        let mut bare = ordinary([0x03; 32]);
        bare.authority = None;
        assert_eq!(
            check_offered_step_position(&bare, &agreed),
            Err(OfferedStepRefusal::NoAuthority)
        );
    }

    /// An epoch is taken only past the last one recorded: the last itself and
    /// anything below it are refused, and the next is taken.
    #[test]
    fn an_epoch_is_taken_only_past_the_last() {
        for stale in [i64::MIN, 4, 5] {
            let err = cert_resync_epoch_advances(stale, 5).expect_err("a stale epoch");
            assert!(err.to_string().contains("not greater"), "{stale}: {err}");
        }
        cert_resync_epoch_advances(6, 5).expect("the next epoch");
        cert_resync_epoch_advances(i64::MAX, 5).expect("any later epoch");
    }
}
