// SPDX-License-Identifier: Apache-2.0

//! `EconomicRootClaimBody` (`0x001B`) and `EconomicAdmissionManifest`
//! (`0x001C`) — the two objects that connect a registered economic root to the
//! evidence a verifier needs to decide whether it is a *valid* one.
//!
//! ## Registered is not validated
//!
//! A claim is what a trader writes into the write-once root register. Writing
//! it establishes exactly one thing: **non-equivocation**. The register proves
//! that this identity named one and only one root at this economic position —
//! it says nothing whatever about whether that root is the result of a valid
//! transition. A malicious trader registers an arbitrary root perfectly
//! consistently. `accepted_root != valid_root`, and the two must never be
//! allowed to coerce into one another.
//!
//! ## One edge into the evidence
//!
//! The claim names `admission_manifest_addr` and nothing else about the
//! evidence. Earlier shapes carried a transition-witness digest and an
//! evidence digest alongside it; both are deleted. A second digest beside the
//! first is a second place for the claim and the manifest to disagree, and
//! there is no principled resolution when they do.

use crate::ccb::genesis::sigalg;
use crate::ccb::{
    class, push_absent, push_bytes, push_digest32, push_envelope, push_present, push_u16, push_u32,
    push_u64, CcbError, CcbObject,
};
use crate::common::domain_tags::{
    TAG_DSM_ECONOMIC_ADMISSION_MANIFEST, TAG_DSM_ECONOMIC_ROOT_CLAIM_SIGN,
};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::economic::witness::EconomicTransitionWitness;

/// Which substrate carried the local acceptance this economic transition
/// corresponds to.
///
/// Exactly one is present in a manifest, and the object shape is what states
/// which. An enum discriminant plus two optional fields would allow a manifest
/// whose tag and whose contents disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionSubstrate {
    /// An ordinary DSM successor: the exact `C_dsm+` / `sigma_dsm` accepted.
    DsmSuccessor { evidence_addr: [u8; 32] },
    /// An offline account boundary: the exact `OfflineBoundaryAttestationV1`
    /// accepted.
    OfflineBoundary { evidence_addr: [u8; 32] },
}

/// `0x001C` schema 1 — everything a verifier must reach to validate one
/// economic transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EconomicAdmissionManifest {
    /// The bound device-tree position — a **digest**, `t_0`, never a counter.
    /// Authority resolution proves descent *at a position*; it does not and
    /// cannot prove frontier, so a counter here would invite reading it as a
    /// height.
    pub authority_position: [u8; 32],
    pub transition_witness_addr: [u8; 32],
    pub authority_evidence_addr: [u8; 32],
    pub substrate: AdmissionSubstrate,
    /// Content addresses of the provenance objects funding this transition's
    /// credits.
    ///
    /// **Derived and non-authoritative.** This field is a publication and
    /// durability index — the set of objects a quorum must be holding before
    /// the admission is verifiable — and NOT a second description of
    /// provenance. The semantics live in the witness's inline credit sources;
    /// this must equal
    ///
    /// ```text
    /// sort_unique(every direct external evidence address referenced by
    ///             witness.credit_sources)
    /// ```
    ///
    /// and a mismatch rejects. Keeping it derived is what stops the manifest
    /// and the witness from disagreeing about what funds the transition:
    /// there is only one description, and this is an index over it. See
    /// [`verify_manifest_provenance_index`].
    provenance_evidence_addrs: Vec<[u8; 32]>,
}

impl CcbObject for EconomicAdmissionManifest {
    const CLASS: u16 = class::ECONOMIC_ADMISSION_MANIFEST;
    const SCHEMA: u16 = 1;
}

impl EconomicAdmissionManifest {
    pub fn new(
        authority_position: [u8; 32],
        transition_witness_addr: [u8; 32],
        authority_evidence_addr: [u8; 32],
        substrate: AdmissionSubstrate,
        provenance_evidence_addrs: Vec<[u8; 32]>,
    ) -> Result<Self, CcbError> {
        let mut addrs = provenance_evidence_addrs;
        addrs.sort_unstable();
        if addrs.windows(2).any(|w| w[0] == w[1]) {
            return Err(CcbError::DuplicateSetElement {
                class: class::ECONOMIC_ADMISSION_MANIFEST,
            });
        }
        Ok(Self {
            authority_position,
            transition_witness_addr,
            authority_evidence_addr,
            substrate,
            provenance_evidence_addrs: addrs,
        })
    }

    pub fn provenance_evidence_addrs(&self) -> &[[u8; 32]] {
        &self.provenance_evidence_addrs
    }

    /// Fields 1..6 in registry order. Both substrate slots are written, one
    /// present and one absent, so the field positions never shift.
    pub fn encode(&self) -> Result<Vec<u8>, CcbError> {
        let mut out = Vec::new();
        push_envelope::<Self>(&mut out);
        push_digest32(&mut out, &self.authority_position); // 1
        push_digest32(&mut out, &self.transition_witness_addr); // 2
        push_digest32(&mut out, &self.authority_evidence_addr); // 3
        match &self.substrate {
            // 4, 5
            AdmissionSubstrate::DsmSuccessor { evidence_addr } => {
                push_present(&mut out);
                push_digest32(&mut out, evidence_addr);
                push_absent(&mut out);
            }
            AdmissionSubstrate::OfflineBoundary { evidence_addr } => {
                push_absent(&mut out);
                push_present(&mut out);
                push_digest32(&mut out, evidence_addr);
            }
        }
        let count = u32::try_from(self.provenance_evidence_addrs.len())
            .map_err(|_| CcbError::LengthOverflow)?;
        push_u32(&mut out, count); // 6
        for addr in &self.provenance_evidence_addrs {
            push_digest32(&mut out, addr);
        }
        Ok(out)
    }

    /// `admission_manifest_addr = H_dom(DSM/economic-admission-manifest/v1,
    /// CCB(EconomicAdmissionManifest))`.
    pub fn addr(&self) -> Result<[u8; 32], CcbError> {
        let ccb = self.encode()?;
        let mut h = dsm_domain_hasher(TAG_DSM_ECONOMIC_ADMISSION_MANIFEST);
        h.update(&ccb);
        Ok(*h.finalize().as_bytes())
    }
}

/// `0x001B` schema 1 — the signed body a trader registers at its economic
/// position.
///
/// `root_register_storage_set_id` is a member of the **signed** body, not
/// transport context. A claim that did not commit the set it was written to
/// could be lifted from one network's register into another's, which is
/// precisely the substitution the network scoping exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EconomicRootClaimBody {
    pub trader_genesis: [u8; 32],
    pub trader_devid: [u8; 32],
    pub economic_position: u64,
    pub post_economic_root: [u8; 32],
    pub admission_manifest_addr: [u8; 32],
    pub root_register_storage_set_id: [u8; 32],
    pub signature_alg: u16,
    pub claimant_public_key: Vec<u8>,
}

impl CcbObject for EconomicRootClaimBody {
    const CLASS: u16 = class::ECONOMIC_ROOT_CLAIM_BODY;
    const SCHEMA: u16 = 1;
}

impl EconomicRootClaimBody {
    /// Validates the algorithm against the declared enumeration and the key
    /// against that algorithm's declared width, the same way Genesis v3 does.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        trader_genesis: [u8; 32],
        trader_devid: [u8; 32],
        economic_position: u64,
        post_economic_root: [u8; 32],
        admission_manifest_addr: [u8; 32],
        root_register_storage_set_id: [u8; 32],
        signature_alg: u16,
        claimant_public_key: &[u8],
    ) -> Result<Self, CcbError> {
        let expected = sigalg::public_key_len(signature_alg)
            .ok_or(CcbError::UnknownSignatureAlg { alg: signature_alg })?;
        if claimant_public_key.len() != expected {
            return Err(CcbError::KeyLengthMismatch {
                alg: signature_alg,
                expected,
                got: claimant_public_key.len(),
            });
        }
        Ok(Self {
            trader_genesis,
            trader_devid,
            economic_position,
            post_economic_root,
            admission_manifest_addr,
            root_register_storage_set_id,
            signature_alg,
            claimant_public_key: claimant_public_key.to_vec(),
        })
    }

    /// Fields 1..8 in registry order.
    pub fn encode(&self) -> Result<Vec<u8>, CcbError> {
        let mut out = Vec::new();
        push_envelope::<Self>(&mut out);
        push_digest32(&mut out, &self.trader_genesis); // 1
        push_digest32(&mut out, &self.trader_devid); // 2
        push_u64(&mut out, self.economic_position); // 3
        push_digest32(&mut out, &self.post_economic_root); // 4
        push_digest32(&mut out, &self.admission_manifest_addr); // 5
        push_digest32(&mut out, &self.root_register_storage_set_id); // 6
        push_u16(&mut out, self.signature_alg); // 7
        push_bytes(&mut out, &self.claimant_public_key)?; // 8
        Ok(out)
    }

    /// `m = H_dom(DSM/economic-root-claim-sign/v1, CCB(body))` — the digest
    /// the claimant's authority key signs.
    pub fn signing_digest(&self) -> Result<[u8; 32], CcbError> {
        let ccb = self.encode()?;
        let mut h = dsm_domain_hasher(TAG_DSM_ECONOMIC_ROOT_CLAIM_SIGN);
        h.update(&ccb);
        Ok(*h.finalize().as_bytes())
    }
}

/// Check the manifest's provenance index against the witness it names.
///
/// The manifest is reached first and the witness hangs off it, so this is the
/// edge where a producer could otherwise publish an index that does not cover
/// the evidence its own sources reference — leaving a verifier to discover a
/// missing object only after fetching, or worse, to treat the index as the
/// authority on what provenance exists.
///
/// `SameTransitionMove` contributes nothing here, by design: it is
/// intra-transition and references no external object, so a transition funded
/// entirely by internal moves has an empty index and that is correct.
pub fn verify_manifest_provenance_index(
    manifest: &EconomicAdmissionManifest,
    witness: &EconomicTransitionWitness,
) -> Result<(), CcbError> {
    let derived = witness.derived_provenance_index();
    if manifest.provenance_evidence_addrs() != derived.as_slice() {
        return Err(CcbError::ManifestProvenanceIndexMismatch {
            manifest_count: manifest.provenance_evidence_addrs().len(),
            derived_count: derived.len(),
        });
    }
    Ok(())
}
