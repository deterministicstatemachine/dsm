// SPDX-License-Identifier: MIT OR Apache-2.0

//! # Receipt construction and per-step signing
//!
//! Builds the canonical stitched receipt of a relationship step and derives the
//! per-step ephemeral keys that answer it. Verification is Core's
//! (`dsm::verification::receipt_verification`); nothing here re-implements it.

use dsm::types::error::DsmError;
use dsm::types::receipt_types::{
    compute_receipt_challenge_response_target, DeviceTreeAcceptanceCommitment, StitchedReceiptV2,
};
#[cfg(test)]
use dsm::verification::receipt_verification::{verify_per_step_ek_signing, BilateralSide};

/// Inputs for per-step ephemeral SPHINCS+ key derivation (whitepaper §11.1/§12 Eq.14).
///
/// The signer's per-step EK is derived as:
///   `E_{n+1} = keyed-BLAKE3(Smaster, "DSM/ek/v1\0" || alg_id || chain_id || h_n || C_pre || k_step)`
///   `(EK_pk_{n+1}, EK_sk_{n+1}) = SPHINCS+.KeyGen(E_{n+1})`
///
/// All four context inputs MUST be 32 bytes; the secret root is the device master seed
/// `Smaster` (re-derived from the wallet seed, never persisted — there is no C-DBRW).
/// `k_step` comes from a Kyber exchange between the parties.
#[derive(Debug, Clone, Copy)]
pub struct PerStepEkContext {
    /// Relationship / chain identifier (the per-relationship SMT key) bound into the seed.
    pub chain_id: [u8; 32],
    /// Current bilateral chain tip h_n (parent_tip of the receipt being built).
    pub h_n: [u8; 32],
    /// Pre-commitment hash C_pre for this step (whitepaper §4.1).
    pub c_pre: [u8; 32],
    /// Kyber-derived step key: `BLAKE3("DSM/kyber-ss\0" || ss)` where ss
    /// is the Kyber shared secret for this step.
    pub k_step: [u8; 32],
}

/// Derive the per-step ephemeral SPHINCS+ keypair (whitepaper §11.1/§12 Eq.14).
///
/// Wraps the underlying primitives `derive_ephemeral_seed` +
/// `generate_ephemeral_keypair` from `dsm::crypto::ephemeral_key`. Returns
/// `(EK_pk, EK_sk)`. The result is fully deterministic in `(s_master, chain_id,
/// h_n, c_pre, k_step)` — same inputs always produce the same keypair. `s_master`
/// is the device master seed `Smaster` (the keyed-BLAKE3 key / secret root).
pub fn derive_per_step_ek(
    ctx: &PerStepEkContext,
    s_master: &[u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), DsmError> {
    let seed = dsm::crypto::ephemeral_key::derive_ephemeral_seed(
        s_master,
        dsm::crypto::ephemeral_key::ALG_ID_SPX256F,
        &ctx.chain_id,
        &ctx.h_n,
        &ctx.c_pre,
        &ctx.k_step,
    );
    dsm::crypto::ephemeral_key::generate_ephemeral_keypair(&seed)
}

/// Result of the sender-side per-step Kyber encapsulation.
#[derive(Debug)]
pub struct KyberStepEncap {
    /// The 32-byte `k_step = BLAKE3("DSM/kyber-ss\0" || ss)` mixed into
    /// the per-step EK derivation (keyed under Smaster).
    pub k_step: [u8; 32],
    /// Kyber ciphertext that travels in the receipt envelope; recipient
    /// decapsulates with their Kyber secret key to recover the same `ss`
    /// and derive identical `k_step`.
    pub ciphertext: Vec<u8>,
}

/// Sender-side: derive `k_step` for the per-step EK by deterministically
/// encapsulating against the recipient's Kyber public key (whitepaper §11).
///
/// The encapsulation coins are derived from public chain context keyed by the
/// device master seed `Smaster` (whitepaper §12):
///   coins = keyed-BLAKE3(Smaster, "DSM/kyber-coins/v1\0" || kyber_alg_id
///             || recipient_kem_pub_hash || h_n || C_pre || DevID_sender)
///
/// Returns the `k_step` to use as input to `derive_per_step_ek` AND the
/// ciphertext to embed in `receipt.kyber_ct_a` (or `_b` for B's side) so
/// the recipient can recover the same `k_step`.
pub fn derive_kyber_k_step_for_send(
    h_n: &[u8; 32],
    c_pre: &[u8; 32],
    devid_sender: &[u8; 32],
    s_master: &[u8; 32],
    recipient_kyber_pk: &[u8],
) -> Result<KyberStepEncap, DsmError> {
    if recipient_kyber_pk.is_empty() {
        return Err(DsmError::invalid_operation(
            "derive_kyber_k_step_for_send: recipient Kyber public key is empty; \
             contact must be re-established with a Kyber pubkey to upgrade for \
             per-step EK signing",
        ));
    }
    // coins = keyed-BLAKE3(Smaster, "DSM/kyber-coins/v1\0" || ML-KEM-768
    //           || H(recipient_kem_pub) || h_n || C_pre || DevID_sender)
    let recipient_kem_pub_hash = dsm::crypto::blake3::domain_hash_bytes(
        dsm::common::domain_tags::TAG_DSM_KYBER_RECIPIENT_PUB_V1,
        recipient_kyber_pk,
    );
    let coins = dsm::crypto::ephemeral_key::derive_kyber_coins(
        s_master,
        dsm::crypto::ephemeral_key::KYBER_ALG_ID_MLKEM768,
        &recipient_kem_pub_hash,
        h_n,
        c_pre,
        devid_sender,
    );
    // (ct, ss) = KyberEncDet(recipient_pk, coins)
    let (ss, ct) = dsm::crypto::kyber::kyber_encapsulate_deterministic(recipient_kyber_pk, &coins)?;
    // k_step = BLAKE3("DSM/kyber-ss\0" || ss)
    let k_step = dsm::crypto::ephemeral_key::derive_kyber_step_key(&ss);
    Ok(KyberStepEncap {
        k_step,
        ciphertext: ct,
    })
}

/// Recipient-side: decapsulate the sender's Kyber ciphertext with the local
/// Kyber secret key, recovering the same `ss` and deriving identical
/// `k_step`. The verifier uses this to reconstruct the per-step EK derivation
/// inputs and check that `receipt.ek_pk_a` matches what the sender claims.
pub fn derive_kyber_k_step_for_verify(
    sender_ciphertext: &[u8],
    local_kyber_sk: &[u8],
) -> Result<[u8; 32], DsmError> {
    if sender_ciphertext.is_empty() {
        return Err(DsmError::invalid_operation(
            "derive_kyber_k_step_for_verify: receipt does not carry a Kyber \
             ciphertext; cannot derive k_step",
        ));
    }
    let ss = dsm::crypto::kyber::kyber_decapsulate(local_kyber_sk, sender_ciphertext)?;
    Ok(dsm::crypto::ephemeral_key::derive_kyber_step_key(&ss))
}

/// Inputs to the high-level per-step EK signing helper.
///
/// The helper handles the full whitepaper §11.1 per-step signing flow:
/// loading the prior chain head SK (or the root AK at relationship genesis), deriving a
/// fresh `EK_{n+1}` keypair, signing the cert, answering the receipt challenge,
/// and returning all artifacts. Callers do post-acceptance advancement
/// separately via `advance_local_chain_head_after_signing`.
pub struct PerStepSigningInputs<'a> {
    /// The receipt commitment hash (output of
    /// `StitchedReceiptV2::compute_commitment`) — the transition commitment
    /// fed into the receipt challenge-response target.
    pub commitment: &'a [u8; 32],
    /// Parent tip h_n — the bilateral chain tip before this transition.
    pub h_n: [u8; 32],
    /// Pre-commitment hash C_pre for this step (whitepaper §4.1).
    pub c_pre: [u8; 32],
    /// Local device ID — used in the deterministic Kyber `coins` derivation
    /// per whitepaper §11 (DevID_sender input to coins).
    pub devid_sender: [u8; 32],
    /// Per-Device SMT relationship key (used to look up chain head AND as the
    /// `chain_id` bound into the per-step EK seed).
    pub relationship_key: [u8; 32],
    /// Root AK keypair, used only when the relationship has no chain head
    /// recorded yet at relationship genesis / step 0.
    /// `(ak_pk, ak_sk)`. Pass `None` to require chain-head presence.
    pub root_ak_keypair: Option<(&'a [u8], &'a [u8])>,
    /// Recipient's Kyber/ML-KEM public key. Required: the helper
    /// encapsulates against this to derive `k_step` deterministically per
    /// whitepaper §11. Caller pulls this from the recipient contact's
    /// `kyber_public_key` field. An empty value causes the helper to
    /// fail-closed. Relationships must be
    /// established with peer Kyber pubkey before per-step EK signing
    /// can run.
    pub recipient_kyber_pk: &'a [u8],
    /// Bilateral session binding (whitepaper §11.1 Item 7). The per-step EK
    /// signature is computed over a session-bound receipt challenge-response target:
    /// `BLAKE3("DSM/receipt-bind-session\0" || receipt_commitment ||
    /// commitment_hash)`.
    /// Cryptographically binds `sig_a` / `sig_b` to a specific bilateral
    /// session, defeating cross-session receipt substitution.
    ///
    /// The §4.2.1 canonical commit form stays unchanged.
    pub session_binding: &'a [u8; 32],
}

/// Output of the high-level per-step EK signing helper.
#[derive(Debug)]
pub struct PerStepSigningOutput {
    /// New EK public key — caller should set this on `receipt.ek_pk_a`
    /// (or `ek_pk_b` if they're co-signing on B's side).
    pub ek_pk: Vec<u8>,
    /// New EK secret key — kept in memory for `advance_local_chain_head_after_signing`.
    /// Caller MUST wipe this from memory after advancement.
    pub ek_sk: Vec<u8>,
    /// Cert chaining `EK_pk` back to the prior chain head — caller should
    /// set this on `receipt.ek_cert_a` (or `ek_cert_b`).
    pub ek_cert: Vec<u8>,
    /// SPHINCS+ response over the receipt challenge target using `EK_sk` —
    /// caller passes this to `receipt.add_sig_a` (or `add_sig_b`).
    pub sig: Vec<u8>,
    /// Per-step Kyber ciphertext that travels in `receipt.kyber_ct_a`
    /// (or `_b`). The recipient decapsulates this with their Kyber
    /// secret key to derive the same `k_step` and reconstruct the per-step
    /// EK derivation inputs at verify time.
    pub kyber_ct: Vec<u8>,
    /// True if the helper used the root AK because the relationship is not yet
    /// initialized in cert_chain_heads). Caller should initialize the
    /// chain head with the new EK after acceptance via
    /// `init_local_cert_chain_head_with_sk` rather than `advance`.
    pub used_root_ak: bool,
}

/// Sign a receipt challenge target with a per-step ephemeral SPHINCS+ key, building
/// the cert chain back to the device's AK in the process (whitepaper §11.1).
///
/// Flow:
/// 1. Load prior chain head SK (encrypted, decrypted in-memory). If absent at
///    relationship genesis, use `inputs.root_ak_keypair`.
/// 2. Run deterministic Kyber encapsulation against
///    `inputs.recipient_kyber_pk` to derive `k_step` per whitepaper §11
///    The recipient's Kyber pubkey is mandatory.
///    The resulting Kyber ciphertext travels in `receipt.kyber_ct_a` so
///    the recipient can reconstruct the same `k_step`.
/// 3. Derive `EK_{n+1}` from `(h_n, C_pre, k_step) keyed under Smaster`.
/// 4. Sign `cert_{n+1} = Sign_{prior_SK}(BLAKE3("DSM/ek-cert\0" ||
///    EK_pk_{n+1} || h_n))`.
/// 5. Sign `inputs.commitment` with the new `EK_sk_{n+1}` to produce sig.
/// 6. Return all artifacts; caller stamps them onto the receipt and calls
///    `advance_local_chain_head_after_signing` post-acceptance.
pub fn sign_receipt_with_per_step_ek(
    inputs: &PerStepSigningInputs,
) -> Result<PerStepSigningOutput, DsmError> {
    let signing_target =
        compute_receipt_challenge_response_target(inputs.commitment, inputs.session_binding);
    sign_receipt_with_per_step_ek_target(inputs, &signing_target)
}

/// [`sign_receipt_with_per_step_ek`] over an EXPLICIT response target. The
/// per-step EK derivation, Kyber encapsulation and cert are identical; only the
/// bytes `EK_sk` signs differ. The online recipient passes
/// [`compute_receipt_b_canonical_target`](dsm::types::receipt_types::compute_receipt_b_canonical_target) so `sig_b` also authenticates its
/// canonical pair; every other caller uses the standard-target wrapper.
pub fn sign_receipt_with_per_step_ek_target(
    inputs: &PerStepSigningInputs,
    signing_target: &[u8; 32],
) -> Result<PerStepSigningOutput, DsmError> {
    use crate::storage::client_db::load_local_chain_head_sk;
    use dsm::crypto::ephemeral_key::sign_ek_cert;
    use dsm::crypto::sphincs::sphincs_sign;

    // 0. Re-derive the session secrets from the unlocked wallet (never persisted; no
    //    C-DBRW). `Smaster` roots the per-step EK seed + ML-KEM coins; the chain-head
    //    at-rest key (s0-rooted, domain-separated) unlocks the prior signer SK. Both fail
    //    closed when the wallet is locked.
    let s_master = crate::init::current_smaster()?;
    let at_rest_key = crate::init::current_chain_head_at_rest_key()?;

    // 1. Resolve prior signer's SK.
    let (prior_sk, used_root_ak) =
        match load_local_chain_head_sk(&inputs.relationship_key, &at_rest_key)
            .map_err(|e| DsmError::invalid_operation(format!("chain-head SK load: {e}")))?
        {
            Some(sk) => (sk, false),
            None => match inputs.root_ak_keypair {
                Some((_pk, sk)) => (sk.to_vec(), true),
                None => {
                    return Err(DsmError::invalid_operation(
                        "per-step signing requires chain-head SK or root AK keypair; \
                     neither was available — call init_local_cert_chain_head_with_sk first",
                    ))
                }
            },
        };

    // 2. Per-step Kyber encapsulation per §11. No stubs — the recipient's
    //    Kyber pubkey is mandatory and validated inside the helper.
    let kyber_step = derive_kyber_k_step_for_send(
        &inputs.h_n,
        &inputs.c_pre,
        &inputs.devid_sender,
        &s_master,
        inputs.recipient_kyber_pk,
    )?;

    // 3. Derive new EK keypair using the Kyber-derived k_step.
    let ek_ctx = PerStepEkContext {
        chain_id: inputs.relationship_key,
        h_n: inputs.h_n,
        c_pre: inputs.c_pre,
        k_step: kyber_step.k_step,
    };
    let (ek_pk, ek_sk) = derive_per_step_ek(&ek_ctx, &s_master)?;

    // 4. Sign cert.
    let cert = sign_ek_cert(&prior_sk, &ek_pk, &inputs.h_n)?;

    // 5. Answer the receipt challenge with the new EK_sk over the caller's
    //    response target (standard: session-bound commitment; online B side:
    //    that plus the recipient's canonical pair).
    let sig = sphincs_sign(&ek_sk, signing_target).map_err(|e| {
        DsmError::crypto(
            format!("per-step receipt challenge response sign failed: {e}"),
            None::<String>,
        )
    })?;

    Ok(PerStepSigningOutput {
        ek_pk,
        ek_sk,
        ek_cert: cert,
        sig,
        kyber_ct: kyber_step.ciphertext,
        used_root_ak,
    })
}

/// Persist the new chain head after a receipt has been accepted.
///
/// Distinguishes between the relationship-genesis case (where the chain
/// head has never been initialized — caller passes `init = true`) and the
/// steady-state case (caller passes `init = false`). In both cases the
/// new `EK_pk_{n+1}` becomes the current chain head, encrypted SK stored
/// for the next step's signing.
///
/// Caller MUST wipe `ek_sk_in_memory` (zeroize) after this returns.
pub fn advance_local_chain_head_after_signing(
    relationship_key: &[u8; 32],
    new_ek_pk: &[u8],
    new_ek_sk_in_memory: &[u8],
    at_rest_key: &[u8; 32],
    init: bool,
) -> Result<(), DsmError> {
    use crate::storage::client_db::{
        advance_local_cert_chain_head_with_sk, init_local_cert_chain_head_with_sk,
    };

    if init {
        // First-ever advance for this relationship — write Local row with the
        // new EK as the chain head. Counterparty side still needs separate
        // initialization with their AK_pk by the caller (typically at contact
        // establishment time via init_cert_chain_for_relationship).
        init_local_cert_chain_head_with_sk(
            relationship_key,
            new_ek_pk,
            new_ek_sk_in_memory,
            at_rest_key,
        )
        .map_err(|e| DsmError::invalid_operation(format!("chain-head SK init: {e}")))?;
    } else {
        advance_local_cert_chain_head_with_sk(
            relationship_key,
            new_ek_pk,
            new_ek_sk_in_memory,
            at_rest_key,
        )
        .map_err(|e| DsmError::invalid_operation(format!("chain-head SK advance: {e}")))?;
    }
    Ok(())
}

/// Build the canonical receipt of one relationship step (§4.2).
///
/// The single stitched-receipt constructor in the SDK. `parent_path` is the
/// tree's own path at the relationship key, taken from the advance that made
/// the step (`AdvanceOutcome::smt_proofs.parent_proof`): it must carry
/// `parent_tip`, it is the receipt's one relationship proof, and the same
/// siblings folded with `child_tip` are `child_root` — there is no second
/// proof. `transition_entropy` is the same advance's derivation (Part VII
/// step 3), the receipt's canonical field 21.
///
/// Refused when a part is missing or wrong: no genesis hash in the app state, a
/// path that is not at the key or does not carry the parent tip, or a receipt
/// that fails
/// [`verify_receipt_state`](dsm::verification::receipt_verification::verify_receipt_state)
/// against `device_tree_commitment`, the sender's authenticated `R_G`.
#[allow(clippy::too_many_arguments)]
pub fn build_bilateral_receipt_with_smt(
    devid_a: [u8; 32],
    devid_b: [u8; 32],
    parent_tip: [u8; 32],
    child_tip: [u8; 32],
    parent_root: [u8; 32],
    child_root: [u8; 32],
    parent_path: &dsm::merkle::sparse_merkle_tree::SmtInclusionProof,
    device_tree_commitment: &DeviceTreeAcceptanceCommitment,
    transition_entropy: [u8; 32],
) -> Result<Vec<u8>, DsmError> {
    use dsm::common::device_tree;

    let genesis = crate::sdk::app_state::AppState::get_genesis_hash()
        .and_then(|g| <[u8; 32]>::try_from(g.as_slice()).ok())
        .ok_or_else(|| {
            DsmError::invalid_operation("receipt: the app state holds no 32-byte genesis hash")
        })?;

    let relationship_key =
        dsm::core::bilateral_transaction_manager::compute_smt_key(&devid_a, &devid_b);
    if parent_path.key != relationship_key || parent_path.value != Some(parent_tip) {
        return Err(DsmError::invalid_operation(
            "receipt: the relationship path is not the parent tip's path at the relationship key",
        ));
    }

    let dev_proof = device_tree::DeviceTree::single(devid_a)
        .proof(&devid_a)
        .ok_or_else(|| {
            DsmError::invalid_operation(
                "receipt: the single-device tree has no path for the sender",
            )
        })?;

    let mut receipt = StitchedReceiptV2::new(
        genesis,
        devid_a,
        devid_b,
        parent_tip,
        child_tip,
        parent_root,
        child_root,
        parent_path.to_bytes(),
        dev_proof.to_bytes(),
    );
    receipt.set_transition_entropy(transition_entropy);

    // The sender checks the state rules before anything is signed or sent.
    dsm::verification::receipt_verification::verify_receipt_state(
        &receipt,
        device_tree_commitment,
    )?;
    receipt.to_canonical_protobuf()
}

/// Deterministically encode a protocol-only transition payload.
///
/// This is used for sovereign DLV/faucet/bitcoin transitions that need a stable
/// commitment domain but are not bilateral stitched receipts.
pub fn encode_protocol_transition_payload(label: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(label.len() as u32).to_le_bytes());
    out.extend_from_slice(label);
    for part in parts {
        out.extend_from_slice(&(part.len() as u32).to_le_bytes());
        out.extend_from_slice(part);
    }
    out
}

/// Deterministically derive a protocol-transition commitment.
///
/// This must be used for sovereign protocol actors instead of the bilateral
/// `DSM/receipt-commit` domain.
pub fn compute_protocol_transition_commitment(payload_bytes: &[u8]) -> [u8; 32] {
    dsm::crypto::blake3::domain_hash_bytes(
        dsm::common::domain_tags::TAG_DSM_PROTOCOL_TRANSITION,
        payload_bytes,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsm::types::operations::Operation;

    const TEST_SESSION_BINDING: [u8; 32] = [0x5A; 32];

    // ── derive_per_step_ek (whitepaper §11.1) ──

    fn ek_ctx() -> PerStepEkContext {
        PerStepEkContext {
            chain_id: [0x77; 32],
            h_n: [0x11; 32],
            c_pre: [0x22; 32],
            k_step: [0x33; 32],
        }
    }

    /// Derivation is deterministic in (h_n, c_pre, k_step, s_master).
    #[test]
    fn derive_per_step_ek_deterministic() {
        let ctx = ek_ctx();
        let s_master = [0x44; 32];
        let (pk1, sk1) = derive_per_step_ek(&ctx, &s_master).unwrap();
        let (pk2, sk2) = derive_per_step_ek(&ctx, &s_master).unwrap();
        assert_eq!(pk1, pk2);
        assert_eq!(sk1, sk2);
    }

    /// Distinct h_n produces distinct keypairs.
    #[test]
    fn derive_per_step_ek_diverges_on_h_n() {
        let mut ctx_a = ek_ctx();
        let mut ctx_b = ek_ctx();
        ctx_b.h_n = [0xAA; 32];
        let s_master = [0x44; 32];
        let (pk_a, _) = derive_per_step_ek(&ctx_a, &s_master).unwrap();
        let (pk_b, _) = derive_per_step_ek(&ctx_b, &s_master).unwrap();
        // Suppress "unused mut" since we want explicit construction
        let _ = (&mut ctx_a, &mut ctx_b);
        assert_ne!(pk_a, pk_b);
    }

    /// Distinct k_step produces distinct keypairs (the spec's per-step
    /// freshness property when fed real Kyber output).
    #[test]
    fn derive_per_step_ek_diverges_on_k_step() {
        let ctx_a = ek_ctx();
        let mut ctx_b = ek_ctx();
        ctx_b.k_step = [0xBB; 32];
        let s_master = [0x44; 32];
        let (pk_a, _) = derive_per_step_ek(&ctx_a, &s_master).unwrap();
        let (pk_b, _) = derive_per_step_ek(&ctx_b, &s_master).unwrap();
        assert_ne!(pk_a, pk_b);
    }

    /// Distinct Smaster produces distinct keypairs (the master-seed root binds the EK).
    #[test]
    fn derive_per_step_ek_diverges_on_smaster() {
        let ctx = ek_ctx();
        let (pk_a, _) = derive_per_step_ek(&ctx, &[0x44; 32]).unwrap();
        let (pk_b, _) = derive_per_step_ek(&ctx, &[0x55; 32]).unwrap();
        assert_ne!(pk_a, pk_b);
    }

    /// Distinct chain_id produces distinct keypairs (the relationship/chain binding).
    #[test]
    fn derive_per_step_ek_diverges_on_chain_id() {
        let ctx_a = ek_ctx();
        let mut ctx_b = ek_ctx();
        ctx_b.chain_id = [0xCC; 32];
        let s_master = [0x44; 32];
        let (pk_a, _) = derive_per_step_ek(&ctx_a, &s_master).unwrap();
        let (pk_b, _) = derive_per_step_ek(&ctx_b, &s_master).unwrap();
        assert_ne!(pk_a, pk_b);
    }

    /// Resulting keypair signs and verifies correctly under SPHINCS+.
    #[test]
    fn derive_per_step_ek_keypair_signs_and_verifies() {
        let ctx = ek_ctx();
        let s_master = [0x44; 32];
        let (pk, sk) = derive_per_step_ek(&ctx, &s_master).unwrap();
        let msg = b"receipt commitment";
        let sig = dsm::crypto::sphincs::sphincs_sign(&sk, msg).expect("sign");
        assert!(dsm::crypto::sphincs::sphincs_verify(&pk, msg, &sig).expect("verify"));
    }

    // ── derive_kyber_k_step (whitepaper §11) ──

    /// Sender encap + recipient decap produce the same `k_step`. Round-trip
    /// over real Kyber-768 with deterministic coins.
    #[test]
    fn kyber_k_step_send_decap_round_trip() {
        let recipient_kp = dsm::crypto::kyber::generate_kyber_keypair().expect("keygen");
        let h_n = [0x11u8; 32];
        let c_pre = [0x22u8; 32];
        let devid_sender = [0x33u8; 32];
        let s_master = [0x44u8; 32];

        let encap = derive_kyber_k_step_for_send(
            &h_n,
            &c_pre,
            &devid_sender,
            &s_master,
            &recipient_kp.public_key,
        )
        .expect("encap");

        let decap = derive_kyber_k_step_for_verify(&encap.ciphertext, &recipient_kp.secret_key)
            .expect("decap");

        assert_eq!(
            encap.k_step, decap,
            "sender and recipient must derive identical k_step"
        );
    }

    /// Distinct chain context produces distinct `k_step` (per-step
    /// freshness property). Two consecutive steps in the same relationship
    /// MUST yield different k_steps so each step's EK derivation is
    /// cryptographically distinct.
    #[test]
    fn kyber_k_step_distinct_per_step() {
        let recipient_kp = dsm::crypto::kyber::generate_kyber_keypair().expect("keygen");
        let c_pre = [0x22u8; 32];
        let devid_sender = [0x33u8; 32];
        let s_master = [0x44u8; 32];

        let encap_1 = derive_kyber_k_step_for_send(
            &[0xAA; 32],
            &c_pre,
            &devid_sender,
            &s_master,
            &recipient_kp.public_key,
        )
        .expect("encap step 1");
        let encap_2 = derive_kyber_k_step_for_send(
            &[0xBB; 32],
            &c_pre,
            &devid_sender,
            &s_master,
            &recipient_kp.public_key,
        )
        .expect("encap step 2");

        assert_ne!(encap_1.k_step, encap_2.k_step);
        assert_ne!(encap_1.ciphertext, encap_2.ciphertext);
    }

    /// Same chain context but different recipient pubkey produces
    /// different k_step. This binds the EK derivation to a specific
    /// recipient — a receipt encapsulated to one recipient cannot be
    /// "replayed" against another.
    #[test]
    fn kyber_k_step_binds_to_recipient_pubkey() {
        let kp1 = dsm::crypto::kyber::generate_kyber_keypair().expect("kp1");
        let kp2 = dsm::crypto::kyber::generate_kyber_keypair().expect("kp2");
        let h_n = [0x11u8; 32];
        let c_pre = [0x22u8; 32];
        let devid_sender = [0x33u8; 32];
        let s_master = [0x44u8; 32];

        let to_1 =
            derive_kyber_k_step_for_send(&h_n, &c_pre, &devid_sender, &s_master, &kp1.public_key)
                .expect("encap to kp1");
        let to_2 =
            derive_kyber_k_step_for_send(&h_n, &c_pre, &devid_sender, &s_master, &kp2.public_key)
                .expect("encap to kp2");
        assert_ne!(to_1.k_step, to_2.k_step);
    }

    /// Sender helper rejects an empty recipient Kyber pubkey (no root).
    #[test]
    fn kyber_k_step_rejects_empty_recipient_pubkey() {
        let result =
            derive_kyber_k_step_for_send(&[0x11; 32], &[0x22; 32], &[0x33; 32], &[0x44; 32], &[]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("recipient Kyber public key is empty"));
    }

    /// Verifier helper rejects an empty ciphertext.
    #[test]
    fn kyber_k_step_verify_rejects_empty_ct() {
        let kp = dsm::crypto::kyber::generate_kyber_keypair().expect("keygen");
        let result = derive_kyber_k_step_for_verify(&[], &kp.secret_key);
        assert!(result.is_err());
    }

    // ── sign_receipt_with_per_step_ek + advance_local_chain_head_after_signing ──

    /// Set up AppState identity (`G` + `DevID`) + a cached wallet seed so the per-step signing
    /// helpers can re-derive `Smaster` (EK/coins) and the chain-head at-rest key internally
    /// (replaces the old explicit K_DBRW argument). Returns the at-rest key for
    /// `advance_local_chain_head_after_signing` calls.
    fn setup_signing_identity() -> [u8; 32] {
        crate::economic_fixtures::local_device(0x11);
        crate::init::current_chain_head_at_rest_key().expect("the chain head's at-rest key")
    }

    /// Helper: build minimal valid signing inputs for tests.
    fn signing_inputs<'a>(
        commitment: &'a [u8; 32],
        rel_key: &[u8; 32],
        ak_pk: &'a [u8],
        ak_sk: &'a [u8],
        recipient_kyber_pk: &'a [u8],
    ) -> PerStepSigningInputs<'a> {
        PerStepSigningInputs {
            commitment,
            h_n: [0xAA; 32],
            c_pre: [0xBB; 32],
            devid_sender: [0x11; 32],
            relationship_key: *rel_key,
            root_ak_keypair: Some((ak_pk, ak_sk)),
            recipient_kyber_pk,
            session_binding: &TEST_SESSION_BINDING,
        }
    }

    /// First-ever signing for a relationship: helper falls back to AK,
    /// uses it to sign cert; the receipt challenge is answered by the new EK_sk.
    /// Returned cert verifies against AK_pk.
    #[test]
    #[serial_test::serial]
    fn per_step_signing_uses_ak_root_when_chain_head_absent() {
        use crate::storage::client_db::reset_database_for_tests;
        use dsm::crypto::ephemeral_key::{generate_ephemeral_keypair, verify_ek_cert};
        use dsm::crypto::sphincs::sphincs_verify;

        reset_database_for_tests();

        let (ak_pk, ak_sk) = generate_ephemeral_keypair(&[0x01; 32]).unwrap();
        let kyber_kp = dsm::crypto::kyber::generate_kyber_keypair().expect("kyber keygen");
        let kyber_pk = kyber_kp.public_key.clone();
        let commitment = [0xCC; 32];
        let rel_key = [0xDE; 32];
        setup_signing_identity();

        let inputs = signing_inputs(&commitment, &rel_key, &ak_pk, &ak_sk, &kyber_pk);
        let out = sign_receipt_with_per_step_ek(&inputs).unwrap();

        assert!(out.used_root_ak);
        assert!(!out.ek_pk.is_empty());
        assert!(!out.ek_sk.is_empty());
        assert!(!out.ek_cert.is_empty());
        assert!(!out.sig.is_empty());

        // The cert must verify against the AK pubkey.
        let cert_ok = verify_ek_cert(&ak_pk, &out.ek_pk, &inputs.h_n, &out.ek_cert).unwrap();
        assert!(
            cert_ok,
            "cert must verify against AK pubkey when root AK is used"
        );

        // The receipt response must verify against the per-step EK pubkey.
        let response_target =
            compute_receipt_challenge_response_target(&commitment, inputs.session_binding);
        let sig_ok = sphincs_verify(&out.ek_pk, &response_target, &out.sig).unwrap();
        assert!(sig_ok, "sig_a must verify against the per-step EK pubkey");
    }

    /// After advance, the next signing call uses the prior EK_sk (no
    /// root AK). Cert chain step n+1 verifies against EK_pk_n.
    #[test]
    #[serial_test::serial]
    fn per_step_signing_chains_through_advancement() {
        use crate::storage::client_db::reset_database_for_tests;
        use dsm::crypto::ephemeral_key::{generate_ephemeral_keypair, verify_ek_cert};

        reset_database_for_tests();

        let (ak_pk, ak_sk) = generate_ephemeral_keypair(&[0x02; 32]).unwrap();
        let kyber_kp = dsm::crypto::kyber::generate_kyber_keypair().expect("kyber keygen");
        let kyber_pk = kyber_kp.public_key.clone();
        let rel_key = [0xCA; 32];
        let at_rest = setup_signing_identity();

        // Step 0: root AK path. Sign + advance to record EK_1 as chain head.
        let commit0 = [0xC0; 32];
        let inputs0 = signing_inputs(&commit0, &rel_key, &ak_pk, &ak_sk, &kyber_pk);
        let out0 = sign_receipt_with_per_step_ek(&inputs0).unwrap();
        assert!(out0.used_root_ak);
        advance_local_chain_head_after_signing(&rel_key, &out0.ek_pk, &out0.ek_sk, &at_rest, true)
            .unwrap();

        // Step 1: chain head is EK_1 — root NOT used.
        let commit1 = [0xC1; 32];
        let mut inputs1 = signing_inputs(&commit1, &rel_key, &ak_pk, &ak_sk, &kyber_pk);
        inputs1.h_n = [0xBB; 32]; // pretend we advanced the chain
        let out1 = sign_receipt_with_per_step_ek(&inputs1).unwrap();
        assert!(
            !out1.used_root_ak,
            "step 1 must use chain-head SK, not root AK"
        );
        // Cert at step 1 must verify against EK_1 (the prior step's pubkey).
        let cert_ok =
            verify_ek_cert(&out0.ek_pk, &out1.ek_pk, &inputs1.h_n, &out1.ek_cert).unwrap();
        assert!(cert_ok, "step-1 cert must verify against EK_pk_0");

        // Cert at step 1 must NOT verify against AK (proves we actually advanced).
        let cert_against_ak =
            verify_ek_cert(&ak_pk, &out1.ek_pk, &inputs1.h_n, &out1.ek_cert).unwrap();
        assert!(
            !cert_against_ak,
            "step-1 cert must NOT verify against AK after advance"
        );
    }

    /// End-to-end test of the per-step EK signing path: build a receipt,
    /// sign it with `sign_receipt_with_per_step_ek`, stamp the artifacts
    /// onto the receipt, advance the chain head, then re-extract and
    /// verify each component cryptographically. This is the closest thing
    /// to a true integration test for whitepaper §11.1 short of full
    /// bilateral session integration (Phase F).
    #[test]
    #[serial_test::serial]
    fn per_step_signing_end_to_end_two_steps() {
        use crate::storage::client_db::reset_database_for_tests;
        use dsm::crypto::ephemeral_key::{generate_ephemeral_keypair, verify_ek_cert};
        use dsm::crypto::sphincs::sphincs_verify;

        reset_database_for_tests();

        let (ak_pk, ak_sk) = generate_ephemeral_keypair(&[0xA1; 32]).unwrap();
        let kyber_kp = dsm::crypto::kyber::generate_kyber_keypair().expect("kyber keygen");
        let kyber_pk = kyber_kp.public_key.clone();
        let rel_key = [0xE1; 32];
        let at_rest = setup_signing_identity();

        // ────── Step 0 ──────
        let commit0 = [0xF0; 32];
        let inputs0 = signing_inputs(&commit0, &rel_key, &ak_pk, &ak_sk, &kyber_pk);
        let out0 = sign_receipt_with_per_step_ek(&inputs0).unwrap();

        // Cert step 0 chains EK_0 → AK.
        assert!(verify_ek_cert(&ak_pk, &out0.ek_pk, &inputs0.h_n, &out0.ek_cert).unwrap());
        // Receipt response verifies under EK_0.
        let target0 = compute_receipt_challenge_response_target(&commit0, inputs0.session_binding);
        assert!(sphincs_verify(&out0.ek_pk, &target0, &out0.sig).unwrap());

        // Persist EK_0 as new chain head.
        advance_local_chain_head_after_signing(&rel_key, &out0.ek_pk, &out0.ek_sk, &at_rest, true)
            .unwrap();

        // ────── Step 1 ──────
        let commit1 = [0xF1; 32];
        // Simulate chain advancement: new h_n.
        let mut inputs1 = signing_inputs(&commit1, &rel_key, &ak_pk, &ak_sk, &kyber_pk);
        inputs1.h_n = [0xB1; 32];
        let out1 = sign_receipt_with_per_step_ek(&inputs1).unwrap();

        // Step-1 cert chains EK_1 → EK_0 (the prior chain head).
        assert!(!out1.used_root_ak);
        assert!(verify_ek_cert(&out0.ek_pk, &out1.ek_pk, &inputs1.h_n, &out1.ek_cert).unwrap());
        // Step-1 cert MUST NOT verify against AK (proves we walked the chain).
        assert!(!verify_ek_cert(&ak_pk, &out1.ek_pk, &inputs1.h_n, &out1.ek_cert).unwrap());
        // Receipt response at step 1 verifies under EK_1.
        let target1 = compute_receipt_challenge_response_target(&commit1, inputs1.session_binding);
        assert!(sphincs_verify(&out1.ek_pk, &target1, &out1.sig).unwrap());

        // Distinct EK at step 1 vs step 0.
        assert_ne!(out0.ek_pk, out1.ek_pk);

        advance_local_chain_head_after_signing(&rel_key, &out1.ek_pk, &out1.ek_sk, &at_rest, false)
            .unwrap();
    }

    /// Property-style test (loop-based, no proptest dependency).
    ///
    /// For each chain length N in {1, 3, 5, 8}, builds a chain of N
    /// per-step signings and asserts the structural invariants:
    ///
    ///   (P1) Step n's cert verifies against step (n-1)'s pubkey
    ///        (with step 0's cert verifying against AK_pk).
    ///   (P2) For n >= 1, step n's cert does NOT verify against
    ///        AK_pk — the chain has actually walked.
    ///   (P3) For n >= 1, step n's cert does NOT verify against
    ///        step (n-2)'s pubkey (when it exists) — adjacent chain
    ///        only, no skip-level authorization.
    ///   (P4) Each step's receipt response verifies against that
    ///        step's EK_pk (and only that step's EK_pk).
    ///   (P5) All EK_pks across the chain are distinct.
    ///   (P6) Cert chain integrity is preserved across distinct
    ///        h_n values per step (the canonical operating mode).
    ///
    /// This is the closest thing to a proptest formulation of the
    /// DSMCertChain.lean theorem statements without adding a dev-dependency.
    /// It exercises each invariant under multiple chain lengths and
    /// distinct chain contexts.
    #[test]
    #[serial_test::serial]
    fn per_step_signing_chain_property_invariants() {
        use crate::storage::client_db::reset_database_for_tests;
        use dsm::crypto::ephemeral_key::{generate_ephemeral_keypair, verify_ek_cert};
        use dsm::crypto::sphincs::sphincs_verify;

        for &chain_length in &[1usize, 3, 5, 8] {
            reset_database_for_tests();

            let (ak_pk, ak_sk) = generate_ephemeral_keypair(&[0xA0; 32]).unwrap();
            let kyber_kp = dsm::crypto::kyber::generate_kyber_keypair().expect("kyber keygen");
            let kyber_pk = kyber_kp.public_key.clone();
            let rel_key = [0xB0; 32];
            let at_rest = setup_signing_identity();

            let mut chain_pubkeys: Vec<Vec<u8>> = Vec::with_capacity(chain_length);
            let mut chain_certs: Vec<Vec<u8>> = Vec::with_capacity(chain_length);
            let mut chain_h_ns: Vec<[u8; 32]> = Vec::with_capacity(chain_length);
            let mut chain_sigs: Vec<Vec<u8>> = Vec::with_capacity(chain_length);
            let mut chain_commits: Vec<[u8; 32]> = Vec::with_capacity(chain_length);

            for step in 0..chain_length {
                // Distinct h_n + commit per step (structural property: chain
                // walks under varying contexts).
                let mut h_n = [0u8; 32];
                h_n[0] = step as u8;
                h_n[1] = 0xAA;
                let mut commit = [0u8; 32];
                commit[0] = step as u8;
                commit[1] = 0xCC;

                let inputs = PerStepSigningInputs {
                    commitment: &commit,
                    h_n,
                    c_pre: [0xBB; 32],
                    devid_sender: [0x11; 32],
                    relationship_key: rel_key,
                    root_ak_keypair: Some((&ak_pk, &ak_sk)),
                    recipient_kyber_pk: &kyber_pk,
                    session_binding: &TEST_SESSION_BINDING,
                };
                let out = sign_receipt_with_per_step_ek(&inputs).unwrap();

                // Advance chain head so step+1 won't take the root AK.
                advance_local_chain_head_after_signing(
                    &rel_key,
                    &out.ek_pk,
                    &out.ek_sk,
                    &at_rest,
                    /*init=*/ step == 0,
                )
                .unwrap();

                chain_pubkeys.push(out.ek_pk);
                chain_certs.push(out.ek_cert);
                chain_h_ns.push(h_n);
                chain_sigs.push(out.sig);
                chain_commits.push(commit);
            }

            // ── Property checks ──

            // (P1) Each step's cert verifies against the prior pubkey
            //      (AK for step 0, EK_{i-1} for step i>0).
            for i in 0..chain_length {
                let prior_pk: &[u8] = if i == 0 {
                    &ak_pk
                } else {
                    &chain_pubkeys[i - 1]
                };
                assert!(
                    verify_ek_cert(prior_pk, &chain_pubkeys[i], &chain_h_ns[i], &chain_certs[i])
                        .unwrap(),
                    "P1 violated at len={}, step={}",
                    chain_length,
                    i
                );
            }

            // (P2) For step >= 1, cert MUST NOT verify against AK_pk.
            for i in 1..chain_length {
                assert!(
                    !verify_ek_cert(&ak_pk, &chain_pubkeys[i], &chain_h_ns[i], &chain_certs[i])
                        .unwrap(),
                    "P2 violated at len={}, step={}: cert verifies against AK \
                     when it should chain through EK_{}",
                    chain_length,
                    i,
                    i - 1
                );
            }

            // (P3) For step >= 2, cert MUST NOT verify against step (i-2)'s pubkey
            //      (only adjacent step authorizes; no skip-level).
            for i in 2..chain_length {
                assert!(
                    !verify_ek_cert(
                        &chain_pubkeys[i - 2],
                        &chain_pubkeys[i],
                        &chain_h_ns[i],
                        &chain_certs[i]
                    )
                    .unwrap(),
                    "P3 violated at len={}, step={}: cert verifies against \
                     skip-prior pubkey EK_{} instead of EK_{}",
                    chain_length,
                    i,
                    i - 2,
                    i - 1
                );
            }

            // (P4) Each step's receipt response verifies against that
            //      step's EK_pk only.
            for i in 0..chain_length {
                let response_target = compute_receipt_challenge_response_target(
                    &chain_commits[i],
                    &TEST_SESSION_BINDING,
                );
                assert!(
                    sphincs_verify(&chain_pubkeys[i], &response_target, &chain_sigs[i]).unwrap(),
                    "P4 violated at len={}, step={}",
                    chain_length,
                    i
                );
                // And NOT under the previous step's EK_pk.
                if i > 0 {
                    assert!(
                        !sphincs_verify(&chain_pubkeys[i - 1], &response_target, &chain_sigs[i])
                            .unwrap(),
                        "P4 violated at len={}, step={}: sig verifies under \
                         WRONG EK_pk (the prior step's)",
                        chain_length,
                        i
                    );
                }
            }

            // (P5) All EK pubkeys are distinct.
            for i in 0..chain_length {
                for j in (i + 1)..chain_length {
                    assert_ne!(
                        chain_pubkeys[i], chain_pubkeys[j],
                        "P5 violated at len={}: EK_pk[{}] == EK_pk[{}]",
                        chain_length, i, j
                    );
                }
            }
        }
    }

    /// Without a root AK keypair AND without a stored chain head,
    /// signing fails with a clear error.
    #[test]
    #[serial_test::serial]
    fn per_step_signing_errors_without_chain_head_or_root() {
        use crate::storage::client_db::reset_database_for_tests;
        reset_database_for_tests();

        let commit = [0xCC; 32];
        let rel_key = [0xCD; 32];
        setup_signing_identity();
        let inputs = PerStepSigningInputs {
            commitment: &commit,
            h_n: [0xAA; 32],
            c_pre: [0xBB; 32],
            devid_sender: [0x11; 32],
            relationship_key: rel_key,
            root_ak_keypair: None,
            recipient_kyber_pk: &[],
            session_binding: &TEST_SESSION_BINDING,
        };
        let result = sign_receipt_with_per_step_ek(&inputs);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("requires chain-head SK or root AK"));
    }

    // ── verify_per_step_ek_signing ──────────────────────────────────────

    /// Build a stitched receipt for verifier tests.
    ///
    /// Returns a receipt that already has the `side` artifacts stamped (either
    /// A or B), the AK keypair used as the cert chain root, and the h_n that
    /// was used during signing — so the caller can pass `(receipt, side, AK,
    /// h_n)` directly to `verify_per_step_ek_signing`.
    fn build_signed_receipt_for_verifier_test(
        side: BilateralSide,
        seed: &[u8; 32],
    ) -> (StitchedReceiptV2, Vec<u8>, [u8; 32]) {
        use crate::storage::client_db::reset_database_for_tests;
        use dsm::crypto::ephemeral_key::generate_ephemeral_keypair;
        reset_database_for_tests();

        let (ak_pk, ak_sk) = generate_ephemeral_keypair(seed).unwrap();
        let kyber_kp = dsm::crypto::kyber::generate_kyber_keypair().expect("kyber keygen");
        let kyber_pk = kyber_kp.public_key.clone();
        let rel_key = [0xE7; 32];
        setup_signing_identity();

        // Build a minimal receipt with deterministic content so
        // `compute_commitment` is stable.
        let mut receipt = StitchedReceiptV2::new(
            [0x01; 32],     // genesis
            [0x02; 32],     // devid_a
            [0x03; 32],     // devid_b
            [0xAA; 32],     // parent_tip == h_n the verifier will receive
            [0x04; 32],     // child_tip
            [0x05; 32],     // parent_root
            [0x06; 32],     // child_root
            vec![0x07; 16], // rel_proof_parent
            vec![0x09; 16], // dev_proof
        );
        let commitment = receipt.compute_commitment().unwrap();

        let inputs = PerStepSigningInputs {
            commitment: &commitment,
            h_n: [0xAA; 32],
            c_pre: [0xBB; 32],
            devid_sender: [0x11; 32],
            relationship_key: rel_key,
            root_ak_keypair: Some((&ak_pk, &ak_sk)),
            recipient_kyber_pk: &kyber_pk,
            session_binding: &TEST_SESSION_BINDING,
        };
        let out = sign_receipt_with_per_step_ek(&inputs).unwrap();

        match side {
            BilateralSide::A => {
                receipt.set_ek_pk_a(out.ek_pk.clone());
                receipt.set_ek_cert_a(out.ek_cert);
                receipt.set_kyber_ct_a(out.kyber_ct);
                receipt.add_sig_a(out.sig);
            }
            BilateralSide::B => {
                receipt.set_ek_pk_b(out.ek_pk.clone());
                receipt.set_ek_cert_b(out.ek_cert);
                receipt.set_kyber_ct_b(out.kyber_ct);
                receipt.add_sig_b(out.sig);
            }
        }

        (receipt, ak_pk, [0xAA; 32])
    }

    #[test]
    #[serial_test::serial]
    fn verify_per_step_ek_signing_accepts_well_formed_a_side() {
        let (receipt, ak_pk, h_n) =
            build_signed_receipt_for_verifier_test(BilateralSide::A, &[0xA1; 32]);
        verify_per_step_ek_signing(
            &receipt,
            BilateralSide::A,
            &ak_pk,
            &h_n,
            &TEST_SESSION_BINDING,
        )
        .expect("a freshly-signed A-side receipt must verify under AK + h_n");
    }

    #[test]
    #[serial_test::serial]
    fn verify_per_step_ek_signing_accepts_well_formed_b_side() {
        let (receipt, ak_pk, h_n) =
            build_signed_receipt_for_verifier_test(BilateralSide::B, &[0xB1; 32]);
        verify_per_step_ek_signing(
            &receipt,
            BilateralSide::B,
            &ak_pk,
            &h_n,
            &TEST_SESSION_BINDING,
        )
        .expect("a freshly-signed B-side receipt must verify under AK + h_n");
    }

    /// Tampering the receipt commitment after signing must invalidate sig.
    #[test]
    #[serial_test::serial]
    fn verify_per_step_ek_signing_rejects_commitment_tamper() {
        let (mut receipt, ak_pk, h_n) =
            build_signed_receipt_for_verifier_test(BilateralSide::A, &[0xA2; 32]);

        // Mutate a field that participates in commitment computation. The
        // cert-link check still passes (the EK->AK chain is unaffected by
        // the receipt contents), but the receipt response must fail.
        receipt.parent_root = [0xDE; 32];

        let err = verify_per_step_ek_signing(
            &receipt,
            BilateralSide::A,
            &ak_pk,
            &h_n,
            &TEST_SESSION_BINDING,
        )
        .expect_err("tampered commitment must fail signature verification");
        let msg = err.to_string();
        assert!(
            msg.contains("sig_A does NOT verify"),
            "expected sig failure, got: {msg}"
        );
    }

    /// Tampering the cert (or supplying the wrong prev_pk) must fail at the
    /// chain-link step BEFORE the body sig is checked.
    #[test]
    #[serial_test::serial]
    fn verify_per_step_ek_signing_rejects_cert_chain_break() {
        let (receipt, _ak_pk, h_n) =
            build_signed_receipt_for_verifier_test(BilateralSide::A, &[0xA3; 32]);

        // Pass an attacker-controlled pubkey as expected_prev_pk. The cert
        // was signed by the real AK_sk, not by this attacker key, so the
        // cert link check must reject.
        let attacker_pk = vec![0x99u8; 32];
        let err = verify_per_step_ek_signing(
            &receipt,
            BilateralSide::A,
            &attacker_pk,
            &h_n,
            &TEST_SESSION_BINDING,
        )
        .expect_err("cert chained to AK must NOT verify against an attacker pubkey");
        let msg = err.to_string();
        assert!(
            msg.contains("does NOT chain") || msg.contains("cert chain"),
            "expected cert-link failure, got: {msg}"
        );
    }

    /// h_n mismatch (replay) must fail the cert link check.
    #[test]
    #[serial_test::serial]
    fn verify_per_step_ek_signing_rejects_wrong_h_n() {
        let (receipt, ak_pk, _h_n_signed) =
            build_signed_receipt_for_verifier_test(BilateralSide::A, &[0xA4; 32]);

        let wrong_h_n = [0xEE; 32];
        let err = verify_per_step_ek_signing(
            &receipt,
            BilateralSide::A,
            &ak_pk,
            &wrong_h_n,
            &TEST_SESSION_BINDING,
        )
        .expect_err("cert pinned to a different h_n must not verify");
        let msg = err.to_string();
        assert!(
            msg.contains("does NOT chain") || msg.contains("cert chain"),
            "expected cert-link failure, got: {msg}"
        );
    }

    /// Multi-step verifier regression — proves that after a verifier
    /// successfully passes step 0 and the caller advances the
    /// Counterparty chain head, step 1 verification still passes when
    /// expected_prev_pk is loaded from `cert_chain_heads.Counterparty`
    /// (now the fresh EK_pk_0, not the stale AK_pk).
    ///
    /// Without the post-commit `advance_cert_chain_head(Counterparty, ...)`
    /// call, this test fails at step 1 because the cert chains to EK_pk_0
    /// while the verifier still reads AK_pk.
    #[test]
    #[serial_test::serial]
    fn verify_per_step_ek_signing_multi_step_with_counterparty_advance() {
        use crate::storage::client_db::{
            advance_cert_chain_head, init_cert_chain_head, load_cert_chain_head_pubkey,
            reset_database_for_tests, CertChainSide,
        };
        use dsm::crypto::ephemeral_key::generate_ephemeral_keypair;

        reset_database_for_tests();
        // The unit test runs both signer and verifier in the same
        // process / DB, so we let `sign_receipt_with_per_step_ek` use
        // the `Local` row of `cert_chain_heads` for its outbound chain
        // (just like a real signer process would), and we manually seed
        // `Counterparty` with the signer's AK_pk to mirror what the
        // verifier's process would store as its remote-chain mirror.
        let (sender_ak_pk, sender_ak_sk) = generate_ephemeral_keypair(&[0xA1; 32]).unwrap();

        let kyber_kp = dsm::crypto::kyber::generate_kyber_keypair().expect("kyber keygen");
        let kyber_pk = kyber_kp.public_key.clone();

        let sender_rel_key = [0xCA; 32];
        let at_rest = setup_signing_identity();

        // Seed only the Counterparty row (the verifier's mirror of the
        // signer's chain). Leave Local empty so the signer path
        // initializes it fresh on the first sign.
        init_cert_chain_head(&sender_rel_key, CertChainSide::Counterparty, &sender_ak_pk).unwrap();

        // ────── Step 0 (sender signs) ──────
        let mut receipt_step0 = StitchedReceiptV2::new(
            [0x01; 32],
            [0x02; 32],
            [0x03; 32],
            [0xAA; 32],
            [0x04; 32],
            [0x05; 32],
            [0x06; 32],
            vec![0x07; 16],
            vec![0x09; 16],
        );
        let commit0 = receipt_step0.compute_commitment().unwrap();
        let session0 = [0xF0; 32];
        let inputs0 = PerStepSigningInputs {
            commitment: &commit0,
            h_n: [0xAA; 32],
            c_pre: [0xBB; 32],
            devid_sender: [0x11; 32],
            relationship_key: sender_rel_key,
            root_ak_keypair: Some((&sender_ak_pk, &sender_ak_sk)),
            recipient_kyber_pk: &kyber_pk,
            session_binding: &session0,
        };
        let out0 = sign_receipt_with_per_step_ek(&inputs0).unwrap();
        receipt_step0.set_ek_pk_a(out0.ek_pk.clone());
        receipt_step0.set_ek_cert_a(out0.ek_cert);
        receipt_step0.set_kyber_ct_a(out0.kyber_ct);
        receipt_step0.add_sig_a(out0.sig);

        // Sender advances Local during signing (already done by
        // sign_receipt_with_per_step_ek + advance_local_chain_head_after_signing
        // in the BLE handler signer path).
        advance_local_chain_head_after_signing(
            &sender_rel_key,
            &out0.ek_pk,
            &out0.ek_sk,
            &at_rest,
            out0.used_root_ak,
        )
        .unwrap();

        // Step 0 verifier check: the sender's chain head as observed by
        // the receiver (Counterparty side from receiver's POV) is
        // sender_ak_pk. This unit test models the SENDER verifying B-side
        // — but to keep it on one side, we model it from the RECEIVER's
        // verifier perspective: A-side. The Counterparty row was seeded
        // to sender_ak_pk above, which is the correct expected_prev_pk
        // at step 0.
        let prev_pk_loaded =
            load_cert_chain_head_pubkey(&sender_rel_key, CertChainSide::Counterparty)
                .unwrap()
                .expect("Counterparty row should be initialized");
        verify_per_step_ek_signing(
            &receipt_step0,
            BilateralSide::A,
            &prev_pk_loaded,
            &[0xAA; 32],
            &session0,
        )
        .expect("step 0 must verify under freshly-seeded Counterparty AK_pk");

        // ────── Critical post-commit step: advance Counterparty ──────
        // After verifying A-side, the receiver MUST mirror the sender's
        // outbound chain head in their own Counterparty row so step 1+
        // verification finds the fresh prev_pk (EK_pk_0), not the stale
        // genesis AK_pk.
        let new_step =
            advance_cert_chain_head(&sender_rel_key, CertChainSide::Counterparty, &out0.ek_pk)
                .unwrap()
                .expect("Counterparty advance must report new step number");
        assert_eq!(new_step, 1, "Counterparty step counter should advance to 1");

        // ────── Step 1 (sender signs again with advanced Local head) ──────
        let mut receipt_step1 = StitchedReceiptV2::new(
            [0x01; 32],
            [0x02; 32],
            [0x03; 32],
            [0xCC; 32], // new h_n
            [0x44; 32],
            [0x55; 32],
            [0x66; 32],
            vec![0x77; 16],
            vec![0x99; 16],
        );
        let commit1 = receipt_step1.compute_commitment().unwrap();
        let session1 = [0xF1; 32];
        let inputs1 = PerStepSigningInputs {
            commitment: &commit1,
            h_n: [0xCC; 32],
            c_pre: [0xDD; 32],
            devid_sender: [0x11; 32],
            relationship_key: sender_rel_key,
            // The existing chain head must be selected before the root AK.
            root_ak_keypair: Some((&sender_ak_pk, &sender_ak_sk)),
            recipient_kyber_pk: &kyber_pk,
            session_binding: &session1,
        };
        let out1 = sign_receipt_with_per_step_ek(&inputs1).unwrap();
        assert!(
            !out1.used_root_ak,
            "step 1 must sign with chain head EK_sk_0, not root AK"
        );
        receipt_step1.set_ek_pk_a(out1.ek_pk.clone());
        receipt_step1.set_ek_cert_a(out1.ek_cert);
        receipt_step1.set_kyber_ct_a(out1.kyber_ct);
        receipt_step1.add_sig_a(out1.sig);

        // Step 1 verifier MUST resolve expected_prev_pk from the
        // freshly-advanced Counterparty row (= EK_pk_0). With the
        // Counterparty advance from the BLE handler fix, this works.
        // Without it, the loaded pubkey would still be sender_ak_pk
        // and the cert-link check would fail.
        let prev_pk_loaded_step1 =
            load_cert_chain_head_pubkey(&sender_rel_key, CertChainSide::Counterparty)
                .unwrap()
                .expect("Counterparty row should be initialized");
        assert_eq!(
            prev_pk_loaded_step1, out0.ek_pk,
            "Counterparty must now point to EK_pk_0, not AK_pk"
        );
        verify_per_step_ek_signing(
            &receipt_step1,
            BilateralSide::A,
            &prev_pk_loaded_step1,
            &[0xCC; 32],
            &session1,
        )
        .expect("step 1 must verify against the advanced Counterparty chain head");

        // If step 1 is checked against the relationship-genesis AK_pk
        // instead of the advanced chain head, verification must fail.
        let stale_check = verify_per_step_ek_signing(
            &receipt_step1,
            BilateralSide::A,
            &sender_ak_pk,
            &[0xCC; 32],
            &session1,
        );
        assert!(
            stale_check.is_err(),
            "step 1 against the genesis AK_pk must fail"
        );
    }

    /// Item 7 — cross-session receipt substitution must fail under the
    /// receipt challenge-response target.
    ///
    /// Sign a receipt under `session_binding = C1` and verify:
    ///   1. Same session binding verifies.
    ///   2. Different session binding rejects because the signature is
    ///      cryptographically bound to C1, not C2.
    ///
    /// This is the receipt challenge-response invariant: the same receipt
    /// body cannot be replayed into another proposed transition.
    #[test]
    #[serial_test::serial]
    fn item7_session_binding_rejects_cross_session_substitution() {
        use crate::storage::client_db::reset_database_for_tests;
        use dsm::crypto::ephemeral_key::generate_ephemeral_keypair;
        reset_database_for_tests();
        setup_signing_identity();

        let (ak_pk, ak_sk) = generate_ephemeral_keypair(&[0xC4; 32]).unwrap();
        let kyber_kp = dsm::crypto::kyber::generate_kyber_keypair().expect("kyber keygen");
        let kyber_pk = kyber_kp.public_key.clone();

        let mut receipt = StitchedReceiptV2::new(
            [0x01; 32],
            [0x02; 32],
            [0x03; 32],
            [0xAA; 32],
            [0x04; 32],
            [0x05; 32],
            [0x06; 32],
            vec![0x07; 16],
            vec![0x09; 16],
        );
        let commitment = receipt.compute_commitment().unwrap();

        let session_c1: [u8; 32] = [0xC1; 32];
        let session_c2: [u8; 32] = [0xC2; 32];

        // Sign with session_binding = C1.
        let inputs = PerStepSigningInputs {
            commitment: &commitment,
            h_n: [0xAA; 32],
            c_pre: [0xBB; 32],
            devid_sender: [0x11; 32],
            relationship_key: [0xD1; 32],
            root_ak_keypair: Some((&ak_pk, &ak_sk)),
            recipient_kyber_pk: &kyber_pk,
            session_binding: &session_c1,
        };
        let out = sign_receipt_with_per_step_ek(&inputs).unwrap();
        receipt.set_ek_pk_a(out.ek_pk.clone());
        receipt.set_ek_cert_a(out.ek_cert);
        receipt.set_kyber_ct_a(out.kyber_ct);
        receipt.add_sig_a(out.sig);

        // (1) Same session_binding → verifies.
        verify_per_step_ek_signing(&receipt, BilateralSide::A, &ak_pk, &[0xAA; 32], &session_c1)
            .expect("session_binding C1 must verify the C1-bound sig");

        // (2) Different session_binding → rejects.
        let cross = verify_per_step_ek_signing(
            &receipt,
            BilateralSide::A,
            &ak_pk,
            &[0xAA; 32],
            &session_c2,
        );
        assert!(
            cross.is_err(),
            "session_binding C2 must NOT verify a sig bound to C1 — \
             this is the cross-session substitution invariant Item 7 enforces"
        );
    }

    /// Symmetric bilateral co-signing: on a single receipt body, stamp
    /// A-side artifacts with the sender's relationship cert chain and
    /// B-side artifacts with the receiver's (different chain), then assert
    /// that `verify_per_step_ek_signing` accepts both sides INDEPENDENTLY
    /// on the same bytes.
    ///
    /// Mirrors the canonical co-signed receipt that flows back over
    /// `BilateralCommitResponse.counter_signed_receipt` after the receiver
    /// counter-signs the sender's signed bytes.
    /// REPRODUCER (half 1 of 2) for the stranded-proposal defect.
    ///
    /// A signed receipt survives having `kyber_ct_b` DELETED: the B-side
    /// signature still verifies and the strict wire decoder still accepts it.
    /// The field is outside every signature, because `compute_commitment` hashes
    /// the canonical form, which zeroes fields 12-20.
    ///
    /// That is what makes the structural gate in `online_finalize` trippable by
    /// anyone who can touch the bytes -- no key, no forgery. Half 2 is
    /// `online_finalize::tests::a_stripped_kyber_ct_b_is_rejected_by_the_live_gate`;
    /// together they are the causal chain that used to strand a sender forever.
    ///
    /// This test asserts CURRENT, INTENDED behaviour of the crypto layer. The
    /// fix is not to make this test fail -- authenticating fields 12-20 is a
    /// separate protocol-hardening change. The fix is that the resulting
    /// rejection is now RECOVERABLE.
    #[test]
    #[serial_test::serial]
    fn stripping_kyber_ct_b_leaves_sig_b_valid_and_wire_decodable() {
        use crate::storage::client_db::reset_database_for_tests;
        use dsm::crypto::ephemeral_key::generate_ephemeral_keypair;
        reset_database_for_tests();
        setup_signing_identity();

        let (receiver_ak_pk, receiver_ak_sk) = generate_ephemeral_keypair(&[0xB1; 32]).unwrap();
        let kyber_kp = dsm::crypto::kyber::generate_kyber_keypair().expect("kyber keygen");

        let mut receipt = StitchedReceiptV2::new(
            [0x01; 32],
            [0x02; 32],
            [0x03; 32],
            [0xAA; 32],
            [0x04; 32],
            [0x05; 32],
            [0x06; 32],
            vec![0x07; 16],
            vec![0x09; 16],
        );
        let commitment = receipt.compute_commitment().unwrap();
        let b_out = sign_receipt_with_per_step_ek(&PerStepSigningInputs {
            commitment: &commitment,
            h_n: [0xAA; 32],
            c_pre: [0xBB; 32],
            devid_sender: [0x22; 32],
            relationship_key: [0xDA; 32],
            root_ak_keypair: Some((&receiver_ak_pk, &receiver_ak_sk)),
            recipient_kyber_pk: &kyber_kp.public_key,
            session_binding: &TEST_SESSION_BINDING,
        })
        .unwrap();
        receipt.set_ek_pk_b(b_out.ek_pk.clone());
        receipt.set_ek_cert_b(b_out.ek_cert);
        receipt.set_kyber_ct_b(b_out.kyber_ct.clone());
        receipt.add_sig_b(b_out.sig);

        assert!(!b_out.kyber_ct.is_empty(), "fixture must carry a real ct");
        verify_per_step_ek_signing(
            &receipt,
            BilateralSide::B,
            &receiver_ak_pk,
            &[0xAA; 32],
            &TEST_SESSION_BINDING,
        )
        .expect("baseline: intact receipt must verify");

        // THE STRIP: delete field 19 and nothing else.
        let mut stripped = receipt.clone();
        stripped.set_kyber_ct_b(Vec::new());

        assert_eq!(
            stripped.compute_commitment().unwrap(),
            commitment,
            "the commitment is computed over the canonical form, which zeroes 12-20, \
             so deleting kyber_ct_b does not move it"
        );
        verify_per_step_ek_signing(
            &stripped,
            BilateralSide::B,
            &receiver_ak_pk,
            &[0xAA; 32],
            &TEST_SESSION_BINDING,
        )
        .expect("sig_b still verifies with kyber_ct_b deleted -- the field is unsigned");

        // ...and the stripped receipt is still accepted by the strict wire decoder.
        let wire = stripped.to_full_protobuf().expect("encode");
        let round = StitchedReceiptV2::from_canonical_protobuf(&wire)
            .expect("the strict wire decoder still accepts the stripped receipt");
        assert!(round.kyber_ct_b.is_empty());
        assert!(!round.ek_pk_b.is_empty(), "ek_pk_b survives -> gate arms");
    }

    #[test]
    #[serial_test::serial]
    fn verify_per_step_ek_signing_accepts_symmetric_a_and_b_on_same_receipt() {
        use crate::storage::client_db::reset_database_for_tests;
        use dsm::crypto::ephemeral_key::generate_ephemeral_keypair;
        reset_database_for_tests();

        // Two distinct AK keypairs — one per device — and two distinct
        // relationship cert chains so that A-side and B-side derive their
        // EKs from independent contexts.
        let (sender_ak_pk, sender_ak_sk) = generate_ephemeral_keypair(&[0xA1; 32]).unwrap();
        let (receiver_ak_pk, receiver_ak_sk) = generate_ephemeral_keypair(&[0xB1; 32]).unwrap();
        let kyber_kp = dsm::crypto::kyber::generate_kyber_keypair().expect("kyber keygen");
        let kyber_pk = kyber_kp.public_key.clone();

        let sender_rel_key = [0xCA; 32];
        let receiver_rel_key = [0xDA; 32];
        setup_signing_identity();

        let mut receipt = StitchedReceiptV2::new(
            [0x01; 32],
            [0x02; 32],
            [0x03; 32],
            [0xAA; 32],
            [0x04; 32],
            [0x05; 32],
            [0x06; 32],
            vec![0x07; 16],
            vec![0x09; 16],
        );
        let commitment = receipt.compute_commitment().unwrap();

        // A-side stamping (sender's chain).
        let a_inputs = PerStepSigningInputs {
            commitment: &commitment,
            h_n: [0xAA; 32],
            c_pre: [0xBB; 32],
            devid_sender: [0x11; 32],
            relationship_key: sender_rel_key,
            root_ak_keypair: Some((&sender_ak_pk, &sender_ak_sk)),
            recipient_kyber_pk: &kyber_pk,
            session_binding: &TEST_SESSION_BINDING,
        };
        let a_out = sign_receipt_with_per_step_ek(&a_inputs).unwrap();
        receipt.set_ek_pk_a(a_out.ek_pk.clone());
        receipt.set_ek_cert_a(a_out.ek_cert);
        receipt.set_kyber_ct_a(a_out.kyber_ct);
        receipt.add_sig_a(a_out.sig);

        // B-side stamping (receiver's chain). Uses a different relationship
        // key so the chain head lookup hits an empty row and falls back to
        // the receiver's AK_pk.
        let b_inputs = PerStepSigningInputs {
            commitment: &commitment,
            h_n: [0xAA; 32],
            c_pre: [0xBB; 32],
            devid_sender: [0x22; 32],
            relationship_key: receiver_rel_key,
            root_ak_keypair: Some((&receiver_ak_pk, &receiver_ak_sk)),
            recipient_kyber_pk: &kyber_pk,
            session_binding: &TEST_SESSION_BINDING,
        };
        let b_out = sign_receipt_with_per_step_ek(&b_inputs).unwrap();
        receipt.set_ek_pk_b(b_out.ek_pk.clone());
        receipt.set_ek_cert_b(b_out.ek_cert);
        receipt.set_kyber_ct_b(b_out.kyber_ct);
        receipt.add_sig_b(b_out.sig);

        assert!(receipt.is_fully_signed(), "receipt must carry both sigs");

        // Both sides must verify independently against their respective
        // AK pubkeys.
        verify_per_step_ek_signing(
            &receipt,
            BilateralSide::A,
            &sender_ak_pk,
            &[0xAA; 32],
            &TEST_SESSION_BINDING,
        )
        .expect("A-side must verify under sender's AK");
        verify_per_step_ek_signing(
            &receipt,
            BilateralSide::B,
            &receiver_ak_pk,
            &[0xAA; 32],
            &TEST_SESSION_BINDING,
        )
        .expect("B-side must verify under receiver's AK");

        // Cross-check: A-side must NOT verify under receiver's AK, and
        // B-side must NOT verify under sender's AK.
        let cross_a = verify_per_step_ek_signing(
            &receipt,
            BilateralSide::A,
            &receiver_ak_pk,
            &[0xAA; 32],
            &TEST_SESSION_BINDING,
        );
        assert!(
            cross_a.is_err(),
            "A-side must NOT verify under receiver's AK"
        );
        let cross_b = verify_per_step_ek_signing(
            &receipt,
            BilateralSide::B,
            &sender_ak_pk,
            &[0xAA; 32],
            &TEST_SESSION_BINDING,
        );
        assert!(cross_b.is_err(), "B-side must NOT verify under sender's AK");
    }

    /// Two-device 3-step bilateral end-to-end (Item 2 of plan).
    ///
    /// Models a full bilateral relationship across THREE sequential
    /// transitions, exercising both A and B chains advancing in
    /// parallel under strict cert-chain mode. This is the integration
    /// analogue of Lean's `extendChain_preserves_validity` (Theorem 7)
    /// and proves the BLE receipt wiring keeps both chains consistent across
    /// multiple steps.
    ///
    /// Per step n we drive:
    ///   1. Sender (Device A) signs receipt with A-side per-step EK
    ///      derived from sender's chain head (AK_pk_A at step 0,
    ///      EK_pk_a_{n-1} thereafter).
    ///   2. Receiver (Device B) verifies A-side under their mirror of
    ///      sender's chain (Counterparty row from B's POV), then
    ///      counter-signs with B-side per-step EK from receiver's
    ///      chain.
    ///   3. Sender verifies B-side under their mirror of receiver's
    ///      chain (Counterparty row from A's POV).
    ///   4. Both sides advance their respective Counterparty mirrors
    ///      to the just-verified EK_pk.
    ///
    /// Asserts at every step:
    ///   - A-side and B-side verifications both pass (Verified outcome).
    ///   - The cert-link verification at step n+1 uses EK_pk_n (not
    ///     the relationship-genesis AK_pk).
    ///   - Step counter on both Counterparty rows advances monotonically.
    ///   - Cross-substitution: a step-n receipt does NOT verify under
    ///     a step-m chain head (m != n).
    ///
    /// Because the unit test runs both signers in one DB, we use TWO
    /// distinct relationship keys (rel_key_a for sender's outbound chain
    /// + B's mirror of it; rel_key_b for receiver's outbound chain + A's
    /// mirror of it) so each `sign_receipt_with_per_step_ek` call only
    /// touches its own Local row. In production each device has its own
    /// SQLite, so this DB partitioning is implicit.
    #[test]
    #[serial_test::serial]
    fn bilateral_three_step_chain_extension_e2e() {
        use crate::storage::client_db::{
            advance_cert_chain_head, init_cert_chain_head, load_cert_chain_head_pubkey,
            reset_database_for_tests, CertChainSide,
        };
        use dsm::crypto::ephemeral_key::generate_ephemeral_keypair;

        reset_database_for_tests();
        // Two AK keypairs, one per device.
        let (ak_pk_a, ak_sk_a) = generate_ephemeral_keypair(&[0xA1; 32]).unwrap();
        let (ak_pk_b, ak_sk_b) = generate_ephemeral_keypair(&[0xB1; 32]).unwrap();
        let kyber_kp = dsm::crypto::kyber::generate_kyber_keypair().expect("kyber keygen");
        let kyber_pk = kyber_kp.public_key.clone();

        // Two relationship keys (separate DB partitions for the unit
        // test); the Counterparty row of rel_a is B's mirror of A's
        // outbound chain, and vice versa.
        let rel_a: [u8; 32] = [0xCA; 32];
        let rel_b: [u8; 32] = [0xCB; 32];
        let at_rest = setup_signing_identity();

        // Seed Counterparty rows on both partitions:
        //   rel_a.Counterparty = ak_pk_a (B's mirror of A's chain).
        //   rel_b.Counterparty = ak_pk_b (A's mirror of B's chain).
        init_cert_chain_head(&rel_a, CertChainSide::Counterparty, &ak_pk_a).unwrap();
        init_cert_chain_head(&rel_b, CertChainSide::Counterparty, &ak_pk_b).unwrap();

        // Track every step's EK_pk on both sides for negative
        // cross-substitution checks at the end.
        let mut ek_pks_a: Vec<Vec<u8>> = Vec::with_capacity(3);
        let mut ek_pks_b: Vec<Vec<u8>> = Vec::with_capacity(3);

        for step in 0..3u8 {
            // Per-step h_n (asymmetric per side; same value here for
            // simplicity since only the cert-link check uses it and
            // both sides drive it independently).
            let h_n_a: [u8; 32] = [0xA0 | step; 32];
            let h_n_b: [u8; 32] = [0xB0 | step; 32];
            let c_pre: [u8; 32] = [0xC0 | step; 32];

            // ─── Receipt body (canonical, identical fields aside ───
            // from per-step h_n). The per-step EK signing only depends
            // on the commit hash + h_n + cert-chain context.
            let mut receipt = StitchedReceiptV2::new(
                [0x01; 32],
                [0x02; 32],
                [0x03; 32],
                h_n_a, // parent_tip on A-side view
                [0x04 | step; 32],
                [0x05 | step; 32],
                [0x06 | step; 32],
                vec![0x07; 16],
                vec![0x09; 16],
            );
            let commitment = receipt.compute_commitment().unwrap();
            let session_binding = [0x90 | step; 32];

            // ─── A-side signing (Device A) ───
            let a_inputs = PerStepSigningInputs {
                commitment: &commitment,
                h_n: h_n_a,
                c_pre,
                devid_sender: [0x11; 32],
                relationship_key: rel_a,
                root_ak_keypair: Some((&ak_pk_a, &ak_sk_a)),
                recipient_kyber_pk: &kyber_pk,
                session_binding: &session_binding,
            };
            let a_out = sign_receipt_with_per_step_ek(&a_inputs).unwrap();
            // Step 0 must use root AK; step 1+ must use chain head.
            if step == 0 {
                assert!(
                    a_out.used_root_ak,
                    "step 0 A-side must use root AK (chain head not yet established)"
                );
            } else {
                assert!(
                    !a_out.used_root_ak,
                    "step {step} A-side must use prior chain head EK_sk, not root AK"
                );
            }
            receipt.set_ek_pk_a(a_out.ek_pk.clone());
            receipt.set_ek_cert_a(a_out.ek_cert.clone());
            receipt.set_kyber_ct_a(a_out.kyber_ct.clone());
            receipt.add_sig_a(a_out.sig.clone());
            advance_local_chain_head_after_signing(
                &rel_a,
                &a_out.ek_pk,
                &a_out.ek_sk,
                &at_rest,
                a_out.used_root_ak,
            )
            .unwrap();

            // ─── B-side verification of A (Device B verifies A) ───
            let prev_pk_a_loaded = load_cert_chain_head_pubkey(&rel_a, CertChainSide::Counterparty)
                .unwrap()
                .expect("rel_a.Counterparty must be initialized");
            // At step n, prev_pk_a_loaded should be:
            //   step 0 → ak_pk_a (genesis seed)
            //   step n>0 → ek_pks_a[n-1] (advanced after step n-1)
            if step == 0 {
                assert_eq!(
                    prev_pk_a_loaded, ak_pk_a,
                    "step 0: B's mirror of A's chain should be A's AK"
                );
            } else {
                assert_eq!(
                    prev_pk_a_loaded,
                    ek_pks_a[(step - 1) as usize],
                    "step {step}: B's mirror of A's chain should be EK_pk_a_{}",
                    step - 1
                );
            }
            verify_per_step_ek_signing(
                &receipt,
                BilateralSide::A,
                &prev_pk_a_loaded,
                &h_n_a,
                &session_binding,
            )
            .unwrap_or_else(|e| panic!("step {step} A-side verify failed: {e}"));

            // ─── B-side counter-signing (Device B) ───
            // Receipt's parent_tip remains h_n_a (A-side view) but
            // B's per-step EK derivation uses h_n_b. The verifier on
            // sender side will use receipt.parent_tip = h_n_a, so we
            // need to either (a) keep parent_tip aligned with B's
            // h_n_b or (b) drive verifier with h_n_b explicitly. We
            // model (b) — sender knows the receiver's h_n_b out-of-
            // band (in production, via the SMT proofs). The receipt's
            // parent_tip is A-side asymmetric and irrelevant to B's
            // cert-link verification.
            let b_inputs = PerStepSigningInputs {
                commitment: &commitment,
                h_n: h_n_b,
                c_pre,
                devid_sender: [0x22; 32],
                relationship_key: rel_b,
                root_ak_keypair: Some((&ak_pk_b, &ak_sk_b)),
                recipient_kyber_pk: &kyber_pk,
                session_binding: &session_binding,
            };
            let b_out = sign_receipt_with_per_step_ek(&b_inputs).unwrap();
            if step == 0 {
                assert!(b_out.used_root_ak, "step 0 B-side must use root AK");
            } else {
                assert!(
                    !b_out.used_root_ak,
                    "step {step} B-side must use prior chain head"
                );
            }
            receipt.set_ek_pk_b(b_out.ek_pk.clone());
            receipt.set_ek_cert_b(b_out.ek_cert.clone());
            receipt.set_kyber_ct_b(b_out.kyber_ct.clone());
            receipt.add_sig_b(b_out.sig.clone());
            advance_local_chain_head_after_signing(
                &rel_b,
                &b_out.ek_pk,
                &b_out.ek_sk,
                &at_rest,
                b_out.used_root_ak,
            )
            .unwrap();

            assert!(
                receipt.is_fully_signed(),
                "step {step} receipt must carry both A and B sigs"
            );

            // ─── A-side verification of B (Device A verifies B) ───
            let prev_pk_b_loaded = load_cert_chain_head_pubkey(&rel_b, CertChainSide::Counterparty)
                .unwrap()
                .expect("rel_b.Counterparty must be initialized");
            if step == 0 {
                assert_eq!(prev_pk_b_loaded, ak_pk_b);
            } else {
                assert_eq!(prev_pk_b_loaded, ek_pks_b[(step - 1) as usize]);
            }
            verify_per_step_ek_signing(
                &receipt,
                BilateralSide::B,
                &prev_pk_b_loaded,
                &h_n_b,
                &session_binding,
            )
            .unwrap_or_else(|e| panic!("step {step} B-side verify failed: {e}"));

            // ─── Post-commit Counterparty advances ───
            // Both devices advance their mirrors of the other's chain.
            let new_step_a =
                advance_cert_chain_head(&rel_a, CertChainSide::Counterparty, &a_out.ek_pk)
                    .unwrap()
                    .expect("rel_a.Counterparty advance must succeed");
            let new_step_b =
                advance_cert_chain_head(&rel_b, CertChainSide::Counterparty, &b_out.ek_pk)
                    .unwrap()
                    .expect("rel_b.Counterparty advance must succeed");
            assert_eq!(
                new_step_a,
                step as u64 + 1,
                "rel_a.Counterparty step counter monotonicity"
            );
            assert_eq!(
                new_step_b,
                step as u64 + 1,
                "rel_b.Counterparty step counter monotonicity"
            );

            ek_pks_a.push(a_out.ek_pk);
            ek_pks_b.push(b_out.ek_pk);
        }

        // ─── Cross-substitution negative regression ───
        // Build a fresh step-2 receipt, sign A-side with rel_a's
        // current chain head (which after the loop is EK_pk_a_2),
        // then assert it does NOT verify under any earlier step's
        // chain head. This cryptographically pins the chain freshness
        // invariant.
        let mut substitution_check_receipt = StitchedReceiptV2::new(
            [0x01; 32],
            [0x02; 32],
            [0x03; 32],
            [0xAF; 32],
            [0x04; 32],
            [0x05; 32],
            [0x06; 32],
            vec![0x07; 16],
            vec![0x09; 16],
        );
        let sub_commitment = substitution_check_receipt.compute_commitment().unwrap();
        let sub_inputs = PerStepSigningInputs {
            commitment: &sub_commitment,
            h_n: [0xAF; 32],
            c_pre: [0xCF; 32],
            devid_sender: [0x11; 32],
            relationship_key: rel_a,
            root_ak_keypair: Some((&ak_pk_a, &ak_sk_a)),
            recipient_kyber_pk: &kyber_pk,
            session_binding: &TEST_SESSION_BINDING,
        };
        let sub_out = sign_receipt_with_per_step_ek(&sub_inputs).unwrap();
        substitution_check_receipt.set_ek_pk_a(sub_out.ek_pk.clone());
        substitution_check_receipt.set_ek_cert_a(sub_out.ek_cert);
        substitution_check_receipt.set_kyber_ct_a(sub_out.kyber_ct);
        substitution_check_receipt.add_sig_a(sub_out.sig);

        // The freshly-signed receipt's cert chains to ek_pks_a[2]
        // (the head right before this signing). Any earlier head
        // (ak_pk_a, ek_pks_a[0], ek_pks_a[1]) MUST fail the cert link.
        for (idx, stale_pk) in [&ak_pk_a, &ek_pks_a[0], &ek_pks_a[1]].iter().enumerate() {
            let result = verify_per_step_ek_signing(
                &substitution_check_receipt,
                BilateralSide::A,
                stale_pk,
                &[0xAF; 32],
                &TEST_SESSION_BINDING,
            );
            assert!(
                result.is_err(),
                "substitution check {idx}: stale chain head MUST reject"
            );
        }
    }

    // ── verify_per_step_ek_signing ─────────────────────────────────────

    /// Session-bound verification accepts a correctly signed receipt.
    #[test]
    #[serial_test::serial]
    fn required_verifier_accepts_session_bound_receipt() {
        use crate::storage::client_db::reset_database_for_tests;
        use dsm::crypto::ephemeral_key::generate_ephemeral_keypair;
        reset_database_for_tests();
        // Install identity (`G` + DevID) and the cached wallet seed so the per-step
        // EK signer can re-derive `Smaster` internally. Without this the test only
        // passed when an earlier test happened to leave `G` set in the process-global
        // AppState — an implicit ordering dependency that flakes under parallel runs.
        setup_signing_identity();

        let (ak_pk, ak_sk) = generate_ephemeral_keypair(&[0xC2; 32]).unwrap();
        let kyber_kp = dsm::crypto::kyber::generate_kyber_keypair().expect("kyber keygen");
        let mut receipt = StitchedReceiptV2::new(
            [0x01; 32],
            [0x02; 32],
            [0x03; 32],
            [0xAA; 32],
            [0x04; 32],
            [0x05; 32],
            [0x06; 32],
            vec![0x07; 16],
            vec![0x09; 16],
        );
        let commitment = receipt.compute_commitment().unwrap();
        let session_binding = [0xD2; 32];
        let inputs = PerStepSigningInputs {
            commitment: &commitment,
            h_n: [0xAA; 32],
            c_pre: [0xBB; 32],
            devid_sender: [0x11; 32],
            relationship_key: [0xE7; 32],
            root_ak_keypair: Some((&ak_pk, &ak_sk)),
            recipient_kyber_pk: &kyber_kp.public_key,
            session_binding: &session_binding,
        };
        let out = sign_receipt_with_per_step_ek(&inputs).unwrap();
        receipt.set_ek_pk_a(out.ek_pk);
        receipt.set_ek_cert_a(out.ek_cert);
        receipt.set_kyber_ct_a(out.kyber_ct);
        receipt.add_sig_a(out.sig);

        verify_per_step_ek_signing(
            &receipt,
            BilateralSide::A,
            &ak_pk,
            &[0xAA; 32],
            &session_binding,
        )
        .expect("session-bound A-side must verify");
    }

    /// A receipt without per-step EK artifacts always fails closed.
    #[test]
    #[serial_test::serial]
    fn required_verifier_rejects_missing_artifacts() {
        use crate::storage::client_db::reset_database_for_tests;
        reset_database_for_tests();

        let receipt = StitchedReceiptV2::new(
            [0x01; 32],
            [0x02; 32],
            [0x03; 32],
            [0xAA; 32],
            [0x04; 32],
            [0x05; 32],
            [0x06; 32],
            vec![0x07; 16],
            vec![0x09; 16],
        );

        let err = verify_per_step_ek_signing(
            &receipt,
            BilateralSide::A,
            &[0x99u8; 32],
            &[0xAA; 32],
            &[0xFE; 32],
        )
        .expect_err("missing artifacts must reject");
        let msg = err.to_string();
        assert!(
            msg.contains("per-step EK"),
            "error must reference missing per-step EK artifacts, got: {msg}"
        );
    }

    /// A receipt with artifacts present but cryptographically invalid
    /// propagates the underlying verification error.
    #[test]
    #[serial_test::serial]
    fn required_verifier_propagates_crypto_failure() {
        let (mut receipt, ak_pk, h_n) =
            build_signed_receipt_for_verifier_test(BilateralSide::A, &[0xC3; 32]);
        receipt.parent_root = [0xDE; 32];

        let err = verify_per_step_ek_signing(
            &receipt,
            BilateralSide::A,
            &ak_pk,
            &h_n,
            &TEST_SESSION_BINDING,
        )
        .expect_err("tampered receipt must fail receipt response verification");
        let msg = err.to_string();
        assert!(
            msg.contains("sig_A does NOT verify"),
            "error must surface the signature failure, got: {msg}"
        );
    }

    // ── verify_per_step_ek_signing (low-level) ─────────────────────────

    /// An empty cert/sig/ek_pk surface must reject with a descriptive error
    /// instead of panicking inside the SPHINCS+ verifier.
    #[test]
    #[serial_test::serial]
    fn verify_per_step_ek_signing_rejects_missing_artifacts() {
        let (mut receipt, ak_pk, h_n) =
            build_signed_receipt_for_verifier_test(BilateralSide::A, &[0xA5; 32]);

        // Drop sig_a — receipt now has cert + ek_pk but no signature.
        receipt.sig_a = vec![];
        let err = verify_per_step_ek_signing(
            &receipt,
            BilateralSide::A,
            &ak_pk,
            &h_n,
            &TEST_SESSION_BINDING,
        )
        .expect_err("empty sig_a must fail-closed");
        assert!(err.to_string().contains("per-step EK A-side artifacts"));

        // B-side never signed for this receipt, so all B fields are empty.
        let err_b = verify_per_step_ek_signing(
            &receipt,
            BilateralSide::B,
            &ak_pk,
            &h_n,
            &TEST_SESSION_BINDING,
        )
        .expect_err("requesting B-side verification on an A-only receipt must fail-closed");
        assert!(err_b.to_string().contains("per-step EK B-side artifacts"));
    }

    // ── encode_protocol_transition_payload ──

    #[test]
    fn encode_protocol_transition_basic() {
        let encoded = encode_protocol_transition_payload(b"FAUCET", &[b"part1", b"part2"]);
        // label len (4) + label (6) + part1 len (4) + part1 (5) + part2 len (4) + part2 (5) = 28
        assert_eq!(encoded.len(), 4 + 6 + 4 + 5 + 4 + 5);
    }

    #[test]
    fn encode_protocol_transition_deterministic() {
        let a = encode_protocol_transition_payload(b"LABEL", &[b"data"]);
        let b = encode_protocol_transition_payload(b"LABEL", &[b"data"]);
        assert_eq!(a, b);
    }

    #[test]
    fn encode_protocol_transition_empty_parts() {
        let encoded = encode_protocol_transition_payload(b"LABEL", &[]);
        // just label length-prefix + label = 4 + 5
        assert_eq!(encoded.len(), 4 + 5);
    }

    #[test]
    fn encode_protocol_transition_empty_label() {
        let encoded = encode_protocol_transition_payload(b"", &[b"data"]);
        // label_len(4) + label(0) + data_len(4) + data(4) = 12
        assert_eq!(encoded.len(), 4 + 4 + 4);
    }

    #[test]
    fn encode_protocol_transition_label_at_offset_zero() {
        let encoded = encode_protocol_transition_payload(b"LBL", &[b"X"]);
        // First 4 bytes = label length (3)
        let label_len = u32::from_le_bytes(encoded[0..4].try_into().unwrap());
        assert_eq!(label_len, 3);
        assert_eq!(&encoded[4..7], b"LBL");
    }

    #[test]
    fn encode_protocol_transition_parts_are_length_prefixed() {
        let encoded = encode_protocol_transition_payload(b"L", &[b"AB", b"CDE"]);
        // After label: offset = 4+1=5
        // Part0: len(4)=2, data(2)="AB" → offset 5..11
        let p0_len = u32::from_le_bytes(encoded[5..9].try_into().unwrap());
        assert_eq!(p0_len, 2);
        assert_eq!(&encoded[9..11], b"AB");
        // Part1: len(4)=3, data(3)="CDE" → offset 11..18
        let p1_len = u32::from_le_bytes(encoded[11..15].try_into().unwrap());
        assert_eq!(p1_len, 3);
        assert_eq!(&encoded[15..18], b"CDE");
    }

    // ── compute_protocol_transition_commitment ──

    #[test]
    fn protocol_commitment_deterministic() {
        let a = compute_protocol_transition_commitment(b"payload");
        let b = compute_protocol_transition_commitment(b"payload");
        assert_eq!(a, b);
    }

    #[test]
    fn protocol_commitment_varies() {
        let a = compute_protocol_transition_commitment(b"payload_a");
        let b = compute_protocol_transition_commitment(b"payload_b");
        assert_ne!(a, b);
    }

    #[test]
    fn protocol_commitment_nonzero() {
        let c = compute_protocol_transition_commitment(b"data");
        assert_ne!(c, [0u8; 32]);
    }

    #[test]
    fn protocol_commitment_empty_input() {
        let c = compute_protocol_transition_commitment(b"");
        assert_ne!(c, [0u8; 32]);
    }

    // ── encode_protocol_transition_payload: additional ──

    #[test]
    fn encode_protocol_transition_order_matters() {
        let a = encode_protocol_transition_payload(b"L", &[b"X", b"Y"]);
        let b = encode_protocol_transition_payload(b"L", &[b"Y", b"X"]);
        assert_ne!(a, b);
    }

    #[test]
    fn encode_protocol_transition_different_labels_differ() {
        let a = encode_protocol_transition_payload(b"FAUCET", &[b"data"]);
        let b = encode_protocol_transition_payload(b"DLV", &[b"data"]);
        assert_ne!(a, b);
    }

    // ── compute_protocol_transition_commitment ──

    // ── encode + commit roundtrip ──

    #[test]
    fn encode_then_commit_deterministic() {
        let payload = encode_protocol_transition_payload(b"TEST", &[b"a", b"b"]);
        let c1 = compute_protocol_transition_commitment(&payload);
        let c2 = compute_protocol_transition_commitment(&payload);
        assert_eq!(c1, c2);
    }

    #[test]
    fn encode_different_payloads_produce_different_commitments() {
        let p1 = encode_protocol_transition_payload(b"A", &[b"x"]);
        let p2 = encode_protocol_transition_payload(b"B", &[b"x"]);
        let c1 = compute_protocol_transition_commitment(&p1);
        let c2 = compute_protocol_transition_commitment(&p2);
        assert_ne!(c1, c2);
    }

    // #[serial] required: this test mutates the process-global `AppState`
    // (via `set_identity_info`). Running
    // concurrently with other identity/AppState-touching tests (e.g.
    // `dlv_sdk::tests::*` and `bilateral_ble_handler::tests::test_register_
    // sender_session_persists_canonical_sender_session`) produces intermittent
    // CI failures where one test sees the other's identity.
    #[test]
    #[serial_test::serial]
    fn a_first_step_receipt_starts_from_the_root_the_device_committed() {
        use crate::test_support::two_device::TestDevice;
        let peer = TestDevice::create("B", 0x42);
        let local = TestDevice::create("A", 0x41);
        let (devid_a, devid_b) = (local.device_id, peer.device_id);
        let h0 = dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &devid_a, &devid_b,
        );
        let device_tree_commitment = DeviceTreeAcceptanceCommitment::from_root(
            dsm::common::device_tree::DeviceTree::single(devid_a).root(),
        );

        let head = crate::storage::client_db::load_bcr_device_head(&devid_a)
            .expect("load the head")
            .expect("genesis installed the head");
        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(&devid_a, &devid_b);
        assert!(
            head.advance(rel_key, devid_b, Operation::Noop, &[], None, None)
                .is_err(),
            "a step on a relationship the device never established is refused"
        );

        let established = head.establish_relationship(devid_b).expect("establish");
        let outcome = established
            .advance(rel_key, devid_b, Operation::Noop, &[], None, None)
            .expect("the first step");
        assert_eq!(outcome.parent_r_a, established.root());
        assert_eq!(
            outcome.smt_proofs.pre_root,
            established.root(),
            "the first step's pre-state root is the root the device committed"
        );
        let parent_tip = outcome
            .smt_proofs
            .parent_proof
            .value
            .expect("the parent path authenticates the established leaf");
        assert_eq!(parent_tip, h0);

        let child_tip = outcome.new_chain_state.compute_chain_tip();
        let receipt = build_bilateral_receipt_with_smt(
            devid_a,
            devid_b,
            parent_tip,
            child_tip,
            outcome.smt_proofs.pre_root,
            outcome.child_r_a,
            &outcome.smt_proofs.parent_proof,
            &device_tree_commitment,
            outcome.transition_entropy(),
        )
        .expect("the first step's receipt");
        let decoded = StitchedReceiptV2::from_canonical_protobuf(&receipt)
            .expect("the built receipt decodes");
        dsm::verification::receipt_verification::verify_receipt_state(
            &decoded,
            &device_tree_commitment,
        )
        .expect("the first step's receipt holds its state rules");

        assert!(
            build_bilateral_receipt_with_smt(
                devid_a,
                devid_b,
                parent_tip,
                child_tip,
                head.root(),
                outcome.child_r_a,
                &outcome.smt_proofs.parent_proof,
                &device_tree_commitment,
                outcome.transition_entropy(),
            )
            .is_err(),
            "a root from before the relationship was established is not the step's parent: no receipt"
        );
    }
}
