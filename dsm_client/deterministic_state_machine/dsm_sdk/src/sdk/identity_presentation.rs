// SPDX-License-Identifier: MIT OR Apache-2.0

//! `AnchorPresentationV3` — the owner's complete verification bundle for one
//! vault state, and the foreign verifier that consumes it.
//!
//! The presentation is **transport only** (registry §2.10). Nothing in it is
//! trusted as presented: the consumer recomputes `G` from the genesis
//! parameters, authenticates every delegation and transition under the keys
//! those recomputations prove, re-derives `d_o` from `ak_pk ‖ atta`, and
//! enforces `K_cand == K_proven` byte for byte — the full P0–P6 staging in
//! [`dsm::core::identity::authority_resolver`]. This module adds no trust
//! decisions of its own; it is the serialization seam between that resolver
//! and the wire.
//!
//! ## Builder (owner side)
//!
//! Beta profile: one device, one delegation (`D_0`, sentinel-activated), one
//! transition (`T_0`, establishing the single-device tree). All of it is
//! re-derived from the wallet seed on demand — no authority object is
//! persisted, exactly like `s0` and `Smaster`. The re-derived `G` is checked
//! against the caller's stored genesis id so a wrong network id or seed
//! refuses loudly instead of publishing a presentation for an identity this
//! device does not hold.
//!
//! ## Verifier (foreign side)
//!
//! Strict parse → CCB decoders (burned schemas refused, trailing bytes
//! refused) → [`authenticate_anchor_owner`] on the exact fetched `CCB(V_n)`
//! bytes. The verified output is the decoded `V_n` plus the proven authority
//! at the state's own committed position — the ONLY owner-key source the
//! composer is permitted to quote against.

use dsm::ccb::{
    decode_delegation, decode_genesis_params, decode_transition, decode_vault_state,
    delegation_genesis_sentinel, role, sigalg, transition_genesis_sentinel,
    DeviceTreeRootTransition, RootProgressionDelegation, VaultStateV2,
};
use dsm::common::device_tree::{DevTreeProof, DeviceTree};
use dsm::core::identity::authority_resolver::{
    authenticate_anchor_owner, OwnerAuthorityAtPosition, PresentedIdentity, SignedDelegation,
    SignedTransition,
};
use dsm::core::identity::genesis_v2::derive_atta;
use dsm::core::identity::genesis_v3::derive_genesis_v3_self_attested;
use dsm::crypto::sphincs::sphincs_sign;
use dsm::dlv::vault_state_anchor_v3::{sign_vault_state_anchor_v3, SignedVaultStateAnchorV3};
use dsm::types::error::DsmError;

use crate::generated;

/// The non-secret inputs the owner re-derives their authority chain from.
///
/// Everything else — GRK, `D_0`, `T_0`, `AttA`, the device key — is a pure
/// function of these plus the wallet seed. `network_id` is the value the
/// genesis was CREATED under (persisted in the genesis record); passing a
/// different one derives a different `G` and the builder refuses.
#[derive(Debug, Clone, Copy)]
pub struct OwnerIdentityInputs<'a> {
    pub network_id: &'a [u8],
    pub wallet_index: u32,
    pub device_slot: u32,
    pub genesis_version: u32,
}

/// The owner's derived authority facts: the identity, the device, and the
/// authority position a `V_n` must commit (field 13). This is what an
/// owner-side state CONSTRUCTOR needs — the presentation builder re-derives
/// the same chain and signs it.
#[derive(Debug, Clone)]
pub struct OwnAuthorityContext {
    pub g: [u8; 32],
    pub devid: [u8; 32],
    pub ak_public: Vec<u8>,
    /// `t_0` — the digest of the beta chain's single transition; the value
    /// `owner_authority_transition_digest` carries in every state this owner
    /// authors, invariant across market successors.
    pub position: [u8; 32],
}

/// Re-derive the owner's authority context from the wallet seed. Pure
/// derivation — nothing is signed and nothing leaves the device.
pub fn derive_own_authority_context(
    wallet_seed: &[u8],
    inputs: OwnerIdentityInputs<'_>,
) -> Result<OwnAuthorityContext, DsmError> {
    let aph = dsm::core::identity::genesis_session::genesis_authority_policy_hash();
    let genesis = derive_genesis_v3_self_attested(
        wallet_seed,
        inputs.network_id,
        inputs.wallet_index,
        inputs.device_slot,
        inputs.genesis_version,
        &aph,
    )?;
    let d0 = RootProgressionDelegation {
        genesis_id: genesis.g,
        role: role::DEVICE_TREE_ROOT_PROGRESSION,
        role_version: role::BETA_ROLE_VERSION,
        delegated_alg_id: sigalg::SPHINCS_PLUS_SPX256F,
        delegated_pk: genesis.ak_public.clone(),
        delegation_number: 0,
        parent_delegation_digest: delegation_genesis_sentinel(),
        activation_transition_digest: transition_genesis_sentinel(),
    };
    let tree = DeviceTree::single(genesis.devid);
    let t0 = DeviceTreeRootTransition {
        genesis_id: genesis.g,
        predecessor_transition_digest: transition_genesis_sentinel(),
        new_root: tree.root(),
        version_number: 0,
        delegation_digest: d0
            .digest()
            .map_err(|e| DsmError::invalid_parameter(format!("authority context: D_0: {e}")))?,
    };
    Ok(OwnAuthorityContext {
        g: genesis.g,
        devid: genesis.devid,
        ak_public: genesis.ak_public.clone(),
        position: t0.digest(),
    })
}

/// Build the owner's `AnchorPresentationV3` for one state commitment.
///
/// `expected_g` is the stored genesis id — the identity this device actually
/// holds. The re-derivation must land exactly there; a mismatch means the
/// inputs describe some OTHER identity (wrong network id, wrong index, or a
/// pre-v3 genesis) and publishing would be an equivocation, so it refuses.
pub fn build_own_anchor_presentation(
    wallet_seed: &[u8],
    inputs: OwnerIdentityInputs<'_>,
    expected_g: &[u8; 32],
    c_n: &[u8; 32],
) -> Result<generated::AnchorPresentationV3, DsmError> {
    let aph = dsm::core::identity::genesis_session::genesis_authority_policy_hash();
    let genesis = derive_genesis_v3_self_attested(
        wallet_seed,
        inputs.network_id,
        inputs.wallet_index,
        inputs.device_slot,
        inputs.genesis_version,
        &aph,
    )?;
    if genesis.g != *expected_g {
        return Err(DsmError::verification(
            "anchor presentation: re-derived G does not match this device's stored genesis id \
             — the inputs describe a different identity (fail closed)",
        ));
    }

    let params = dsm::ccb::GenesisParamsV3::new(
        genesis.genesis_nonce,
        inputs.network_id,
        inputs.genesis_version,
        sigalg::SPHINCS_PLUS_SPX256F,
        &genesis.grk_public,
    )
    .map_err(|e| DsmError::invalid_parameter(format!("anchor presentation: params: {e}")))?;

    // Beta authority chain: D_0 sentinel-activated under the GRK, T_0
    // establishing the single-device tree under the delegated key.
    let d0 = RootProgressionDelegation {
        genesis_id: genesis.g,
        role: role::DEVICE_TREE_ROOT_PROGRESSION,
        role_version: role::BETA_ROLE_VERSION,
        delegated_alg_id: sigalg::SPHINCS_PLUS_SPX256F,
        delegated_pk: genesis.ak_public.clone(),
        delegation_number: 0,
        parent_delegation_digest: delegation_genesis_sentinel(),
        activation_transition_digest: transition_genesis_sentinel(),
    };
    let d0_signing = d0
        .signing_digest()
        .map_err(|e| DsmError::invalid_parameter(format!("anchor presentation: D_0: {e}")))?;
    let d0_sig = sphincs_sign(&genesis.grk_secret, &d0_signing)?;
    let d0_digest = d0
        .digest()
        .map_err(|e| DsmError::invalid_parameter(format!("anchor presentation: D_0: {e}")))?;

    let tree = DeviceTree::single(genesis.devid);
    let t0 = DeviceTreeRootTransition {
        genesis_id: genesis.g,
        predecessor_transition_digest: transition_genesis_sentinel(),
        new_root: tree.root(),
        version_number: 0,
        delegation_digest: d0_digest,
    };
    let t0_sig = sphincs_sign(&genesis.ak_secret, &t0.signing_digest())?;

    let proof = tree.proof(&genesis.devid).ok_or_else(|| {
        DsmError::verification(
            "anchor presentation: single-device tree has no proof for its own leaf",
        )
    })?;
    let atta = derive_atta(wallet_seed, &genesis.g, inputs.device_slot);

    let anchor = sign_vault_state_anchor_v3(c_n, &genesis.ak_secret, &genesis.ak_public)?;

    Ok(generated::AnchorPresentationV3 {
        state_commitment: c_n.to_vec(),
        candidate_public_key: anchor.candidate_public_key,
        anchor_signature: anchor.signature,
        genesis_params_ccb: params.encode().map_err(|e| {
            DsmError::invalid_parameter(format!("anchor presentation: params: {e}"))
        })?,
        delegations: vec![generated::SignedAuthorityObjectV1 {
            ccb: d0.encode().map_err(|e| {
                DsmError::invalid_parameter(format!("anchor presentation: D_0: {e}"))
            })?,
            signature: d0_sig,
        }],
        transitions: vec![generated::SignedAuthorityObjectV1 {
            ccb: t0.encode(),
            signature: t0_sig,
        }],
        inclusion_proof: proof.to_bytes(),
        ak_public_key: genesis.ak_public.clone(),
        atta: atta.to_vec(),
    })
}

/// Build the portable ECONOMIC authority evidence for this device — the
/// exact bytes the admission manifest's `authority_evidence_addr` names.
///
/// `AnchorPresentationV3` minus the vault-anchor fields: no state
/// commitment, no candidate key, no anchor signature — economic lineage
/// binds identity through the register claim and `sigma_dsm`, not through a
/// vault anchor. Returns `(evidence_bytes, t0_digest)` — the second value is
/// the manifest's `authority_position`: the TRANSITION digest `t_0`, which
/// P3 matches against, never a device-tree root.
pub fn build_authority_evidence(
    wallet_seed: &[u8],
    inputs: OwnerIdentityInputs<'_>,
    expected_g: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 32]), DsmError> {
    use prost::Message;
    let aph = dsm::core::identity::genesis_session::genesis_authority_policy_hash();
    let genesis = derive_genesis_v3_self_attested(
        wallet_seed,
        inputs.network_id,
        inputs.wallet_index,
        inputs.device_slot,
        inputs.genesis_version,
        &aph,
    )?;
    if genesis.g != *expected_g {
        return Err(DsmError::verification(
            "authority evidence: re-derived G does not match this device's stored genesis id \
             — the inputs describe a different identity (fail closed)",
        ));
    }
    let params = dsm::ccb::GenesisParamsV3::new(
        genesis.genesis_nonce,
        inputs.network_id,
        inputs.genesis_version,
        sigalg::SPHINCS_PLUS_SPX256F,
        &genesis.grk_public,
    )
    .map_err(|e| DsmError::invalid_parameter(format!("authority evidence: params: {e}")))?;
    let d0 = RootProgressionDelegation {
        genesis_id: genesis.g,
        role: role::DEVICE_TREE_ROOT_PROGRESSION,
        role_version: role::BETA_ROLE_VERSION,
        delegated_alg_id: sigalg::SPHINCS_PLUS_SPX256F,
        delegated_pk: genesis.ak_public.clone(),
        delegation_number: 0,
        parent_delegation_digest: delegation_genesis_sentinel(),
        activation_transition_digest: transition_genesis_sentinel(),
    };
    let d0_signing = d0
        .signing_digest()
        .map_err(|e| DsmError::invalid_parameter(format!("authority evidence: D_0: {e}")))?;
    let d0_sig = sphincs_sign(&genesis.grk_secret, &d0_signing)?;
    let d0_digest = d0
        .digest()
        .map_err(|e| DsmError::invalid_parameter(format!("authority evidence: D_0: {e}")))?;
    let tree = DeviceTree::single(genesis.devid);
    let t0 = DeviceTreeRootTransition {
        genesis_id: genesis.g,
        predecessor_transition_digest: transition_genesis_sentinel(),
        new_root: tree.root(),
        version_number: 0,
        delegation_digest: d0_digest,
    };
    let t0_sig = sphincs_sign(&genesis.ak_secret, &t0.signing_digest())?;
    let t0_digest = t0.digest();
    let proof = tree.proof(&genesis.devid).ok_or_else(|| {
        DsmError::verification(
            "authority evidence: single-device tree has no proof for its own leaf",
        )
    })?;
    let atta = derive_atta(wallet_seed, &genesis.g, inputs.device_slot);
    let evidence = generated::AuthorityEvidenceV1 {
        genesis_params_ccb: params
            .encode()
            .map_err(|e| DsmError::invalid_parameter(format!("authority evidence: params: {e}")))?,
        delegations: vec![generated::SignedAuthorityObjectV1 {
            ccb: d0.encode().map_err(|e| {
                DsmError::invalid_parameter(format!("authority evidence: D_0: {e}"))
            })?,
            signature: d0_sig,
        }],
        transitions: vec![generated::SignedAuthorityObjectV1 {
            ccb: t0.encode(),
            signature: t0_sig,
        }],
        inclusion_proof: proof.to_bytes(),
        ak_public_key: genesis.ak_public.clone(),
        atta: atta.to_vec(),
    };
    Ok((evidence.encode_to_vec(), t0_digest))
}

/// The verified join of a presentation and the `CCB(V_n)` bytes it anchors:
/// the decoded state and the owner authority proven at the state's own
/// committed position.
#[derive(Debug, Clone)]
pub struct VerifiedVaultState {
    pub state: VaultStateV2,
    pub c_n: [u8; 32],
    pub owner: OwnerAuthorityAtPosition,
}

fn take32(bytes: &[u8], what: &str) -> Result<[u8; 32], DsmError> {
    <[u8; 32]>::try_from(bytes)
        .map_err(|_| DsmError::verification(format!("anchor presentation: {what} is not 32 bytes")))
}

/// Verify a foreign presentation against the exact `CCB(V_n)` bytes.
///
/// `vn_bytes` must come from the immutable store already re-hashed against
/// the `c_n` the caller asked for ([`fetch_vault_state_bytes`] does that);
/// [`authenticate_anchor_owner`] re-hashes them again against the anchor's
/// own commitment, so a presentation for a DIFFERENT state refuses here even
/// if the caller wired the wrong bytes through.
///
/// [`fetch_vault_state_bytes`]: crate::sdk::vault_state_v3_codec::fetch_vault_state_bytes
pub fn verify_anchor_presentation(
    presentation: &generated::AnchorPresentationV3,
    vn_bytes: &[u8],
) -> Result<VerifiedVaultState, DsmError> {
    let state_commitment = take32(&presentation.state_commitment, "state_commitment")?;
    let atta = take32(&presentation.atta, "atta")?;

    let params = decode_genesis_params(&presentation.genesis_params_ccb)
        .map_err(|e| DsmError::verification(format!("anchor presentation: params: {e}")))?;

    let mut delegations = Vec::with_capacity(presentation.delegations.len());
    for obj in &presentation.delegations {
        delegations.push(SignedDelegation {
            delegation: decode_delegation(&obj.ccb).map_err(|e| {
                DsmError::verification(format!("anchor presentation: delegation: {e}"))
            })?,
            grk_signature: obj.signature.clone(),
        });
    }
    let mut transitions = Vec::with_capacity(presentation.transitions.len());
    for obj in &presentation.transitions {
        transitions.push(SignedTransition {
            transition: decode_transition(&obj.ccb).map_err(|e| {
                DsmError::verification(format!("anchor presentation: transition: {e}"))
            })?,
            delegate_signature: obj.signature.clone(),
        });
    }

    let inclusion = DevTreeProof::from_bytes(&presentation.inclusion_proof).ok_or_else(|| {
        DsmError::verification("anchor presentation: inclusion proof does not parse")
    })?;

    let anchor = SignedVaultStateAnchorV3 {
        state_commitment,
        candidate_public_key: presentation.candidate_public_key.clone(),
        signature: presentation.anchor_signature.clone(),
    };
    let presented = PresentedIdentity {
        genesis_params: &params,
        delegations: &delegations,
        transitions: &transitions,
        inclusion: &inclusion,
        ak_pk: &presentation.ak_public_key,
        atta: &atta,
    };

    let owner = authenticate_anchor_owner(&anchor, vn_bytes, &presented)
        .map_err(|e| DsmError::verification(format!("anchor presentation: {e}")))?;

    // authenticate_anchor_owner already decoded these bytes to read the bound
    // position; decode again for the caller's copy — same strict decoder, so
    // the two cannot disagree.
    let state = decode_vault_state(vn_bytes)
        .map_err(|e| DsmError::verification(format!("anchor presentation: state: {e}")))?;

    Ok(VerifiedVaultState {
        state,
        c_n: state_commitment,
        owner,
    })
}
