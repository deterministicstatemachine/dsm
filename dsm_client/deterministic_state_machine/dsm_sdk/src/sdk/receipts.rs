//! # Receipt Primitives for Offline Bilateral Flows
//!
//! Re-exports canonical receipt types and verification from `dsm::core`,
//! adding SDK-level helpers for relationship key derivation and monotonic
//! counter checking on stitched receipts.

use dsm::types::error::DsmError;

// Re-export canonical types from dsm core
pub use dsm::types::receipt_types::{
    DeviceTreeAcceptanceCommitment, ParentConsumptionTracker as ReceiptGuard, ReceiptAcceptance,
    ReceiptVerificationContext, StitchedReceiptV2,
};

/// Derive relationship key from counterparty public key.
/// Domain-separated to prevent collision with other hash contexts.
pub fn derive_relationship_key(counterparty_pk: &[u8]) -> [u8; 32] {
    dsm::crypto::blake3::domain_hash_bytes("DSM/relationship-key", counterparty_pk)
}

/// Inputs for per-step ephemeral SPHINCS+ key derivation (whitepaper §11.1).
///
/// The signer's per-step EK is derived as:
///   `E_{n+1} = HKDF-BLAKE3("DSM/ek\0", h_n || C_pre || k_step || K_DBRW)`
///   `(EK_pk_{n+1}, EK_sk_{n+1}) = SPHINCS+.KeyGen(E_{n+1})`
///
/// All three inputs MUST be 32 bytes. `k_step` comes from a Kyber exchange
/// between the parties; for relationships that don't yet run per-step
/// Kyber, callers may pass a deterministic stub derived from chain context
#[derive(Debug, Clone, Copy)]
pub struct PerStepEkContext {
    /// Current bilateral chain tip h_n (parent_tip of the receipt being built).
    pub h_n: [u8; 32],
    /// Pre-commitment hash C_pre for this step (whitepaper §4.1).
    pub c_pre: [u8; 32],
    /// Kyber-derived step key: `BLAKE3("DSM/kyber-ss\0" || ss)` where ss
    /// is the Kyber shared secret for this step.
    pub k_step: [u8; 32],
}

/// Derive the per-step ephemeral SPHINCS+ keypair (whitepaper §11.1).
///
/// Wraps the underlying primitives `derive_ephemeral_seed` +
/// `generate_ephemeral_keypair` from `dsm::crypto::ephemeral_key`. Returns
/// `(EK_pk, EK_sk)`. The result is fully deterministic in `(h_n, c_pre,
/// k_step, k_dbrw)` — same inputs always produce the same keypair.
pub fn derive_per_step_ek(
    ctx: &PerStepEkContext,
    k_dbrw: &[u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), DsmError> {
    let seed =
        dsm::crypto::ephemeral_key::derive_ephemeral_seed(&ctx.h_n, &ctx.c_pre, &ctx.k_step, k_dbrw);
    dsm::crypto::ephemeral_key::generate_ephemeral_keypair(&seed)
}

/// Result of the sender-side per-step Kyber encapsulation.
#[derive(Debug)]
pub struct KyberStepEncap {
    /// The 32-byte `k_step = BLAKE3("DSM/kyber-ss\0" || ss)` mixed into
    /// the per-step EK derivation alongside K_DBRW.
    pub k_step: [u8; 32],
    /// Kyber ciphertext that travels in the receipt envelope; recipient
    /// decapsulates with their Kyber secret key to recover the same `ss`
    /// and derive identical `k_step`.
    pub ciphertext: Vec<u8>,
}

/// Sender-side: derive `k_step` for the per-step EK by deterministically
/// encapsulating against the recipient's Kyber public key (whitepaper §11).
///
/// The encapsulation coins are derived from public chain context plus the
/// device-bound `K_DBRW`:
///   coins = BLAKE3-256("DSM/kyber-coins\0" || h_n || C_pre
///                       || DevID_sender || K_DBRW)
///
/// Returns the `k_step` to use as input to `derive_per_step_ek` AND the
/// ciphertext to embed in `receipt.kyber_ct_a` (or `_b` for B's side) so
/// the recipient can recover the same `k_step`.
pub fn derive_kyber_k_step_for_send(
    h_n: &[u8; 32],
    c_pre: &[u8; 32],
    devid_sender: &[u8; 32],
    k_dbrw: &[u8; 32],
    recipient_kyber_pk: &[u8],
) -> Result<KyberStepEncap, DsmError> {
    if recipient_kyber_pk.is_empty() {
        return Err(DsmError::invalid_operation(
            "derive_kyber_k_step_for_send: recipient Kyber public key is empty; \
             contact must be re-established with a Kyber pubkey to upgrade for \
             per-step EK signing",
        ));
    }
    // coins = BLAKE3("DSM/kyber-coins\0" || h_n || C_pre || DevID_sender || K_DBRW)
    let coins = dsm::crypto::ephemeral_key::derive_kyber_coins(h_n, c_pre, devid_sender, k_dbrw);
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
/// loading the prior chain head SK (or falling back to AK), deriving a
/// fresh `EK_{n+1}` keypair, signing the cert, signing the receipt body,
/// and returning all artifacts. Callers do post-acceptance advancement
/// separately via `advance_local_chain_head_after_signing`.
pub struct PerStepSigningInputs<'a> {
    /// The receipt commitment hash (output of
    /// `StitchedReceiptV2::compute_commitment`) — what gets signed by EK_sk.
    pub commitment: &'a [u8; 32],
    /// Parent tip h_n — the bilateral chain tip before this transition.
    pub h_n: [u8; 32],
    /// Pre-commitment hash C_pre for this step (whitepaper §4.1).
    pub c_pre: [u8; 32],
    /// Local device ID — used in the deterministic Kyber `coins` derivation
    /// per whitepaper §11 (DevID_sender input to coins).
    pub devid_sender: [u8; 32],
    /// Per-Device SMT relationship key (used to look up chain head).
    pub relationship_key: [u8; 32],
    /// K_DBRW binding key for SK encryption + EK derivation.
    pub k_dbrw: &'a [u8; 32],
    /// Fallback AK keypair, used when the relationship has no chain head
    /// recorded yet (relationship genesis / step 0 / pre-feature path).
    /// `(ak_pk, ak_sk)`. Pass `None` to require chain-head presence.
    pub fallback_ak_keypair: Option<(&'a [u8], &'a [u8])>,
    /// Recipient's Kyber/ML-KEM public key. Required: the helper
    /// encapsulates against this to derive `k_step` deterministically per
    /// whitepaper §11. Caller pulls this from the recipient contact's
    /// `kyber_public_key` field. An empty value causes the helper to
    /// fail-closed — there is no fallback path; relationships must be
    /// established with peer Kyber pubkey before per-step EK signing
    /// can run.
    pub recipient_kyber_pk: &'a [u8],
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
    /// SPHINCS+ signature over the receipt commitment using `EK_sk` —
    /// caller passes this to `receipt.add_sig_a` (or `add_sig_b`).
    pub sig: Vec<u8>,
    /// Per-step Kyber ciphertext that travels in `receipt.kyber_ct_a`
    /// (or `_b`). The recipient decapsulates this with their Kyber
    /// secret key to derive the same `k_step` and reconstruct the per-step
    /// EK derivation inputs at verify time.
    pub kyber_ct: Vec<u8>,
    /// True if the helper used the AK fallback (relationship not yet
    /// initialized in cert_chain_heads). Caller should initialize the
    /// chain head with the new EK after acceptance via
    /// `init_local_cert_chain_head_with_sk` rather than `advance`.
    pub used_ak_fallback: bool,
}

/// Sign a receipt body with a per-step ephemeral SPHINCS+ key, building
/// the cert chain back to the device's AK in the process (whitepaper §11.1).
///
/// Flow:
/// 1. Load prior chain head SK (encrypted, decrypted in-memory). If absent,
///    fall back to `inputs.fallback_ak_keypair` — required if the chain
///    head doesn't yet exist (relationship genesis).
/// 2. Run deterministic Kyber encapsulation against
///    `inputs.recipient_kyber_pk` to derive `k_step` per whitepaper §11
///    (no stubs, no fallbacks — the recipient's Kyber pubkey is mandatory).
///    The resulting Kyber ciphertext travels in `receipt.kyber_ct_a` so
///    the recipient can reconstruct the same `k_step`.
/// 3. Derive `EK_{n+1}` from `(h_n, C_pre, k_step, K_DBRW)`.
/// 4. Sign `cert_{n+1} = Sign_{prior_SK}(BLAKE3("DSM/ek-cert\0" ||
///    EK_pk_{n+1} || h_n))`.
/// 5. Sign `inputs.commitment` with the new `EK_sk_{n+1}` to produce sig.
/// 6. Return all artifacts; caller stamps them onto the receipt and calls
///    `advance_local_chain_head_after_signing` post-acceptance.
pub fn sign_receipt_with_per_step_ek(
    inputs: &PerStepSigningInputs,
) -> Result<PerStepSigningOutput, DsmError> {
    use crate::storage::client_db::load_local_chain_head_sk;
    use dsm::crypto::ephemeral_key::sign_ek_cert;
    use dsm::crypto::sphincs::sphincs_sign;

    // 1. Resolve prior signer's SK.
    let (prior_sk, used_ak_fallback) = match load_local_chain_head_sk(
        &inputs.relationship_key,
        inputs.k_dbrw,
    )
    .map_err(|e| DsmError::invalid_operation(format!("chain-head SK load: {e}")))?
    {
        Some(sk) => (sk, false),
        None => match inputs.fallback_ak_keypair {
            Some((_pk, sk)) => (sk.to_vec(), true),
            None => {
                return Err(DsmError::invalid_operation(
                    "per-step signing requires chain-head SK or fallback AK keypair; \
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
        inputs.k_dbrw,
        inputs.recipient_kyber_pk,
    )?;

    // 3. Derive new EK keypair using the Kyber-derived k_step.
    let ek_ctx = PerStepEkContext {
        h_n: inputs.h_n,
        c_pre: inputs.c_pre,
        k_step: kyber_step.k_step,
    };
    let (ek_pk, ek_sk) = derive_per_step_ek(&ek_ctx, inputs.k_dbrw)?;

    // 4. Sign cert.
    let cert = sign_ek_cert(&prior_sk, &ek_pk, &inputs.h_n)?;

    // 5. Sign receipt commitment with the new EK_sk.
    let sig = sphincs_sign(&ek_sk, inputs.commitment).map_err(|e| {
        DsmError::crypto(format!("per-step receipt body sign failed: {e}"), None::<String>)
    })?;

    Ok(PerStepSigningOutput {
        ek_pk,
        ek_sk,
        ek_cert: cert,
        sig,
        kyber_ct: kyber_step.ciphertext,
        used_ak_fallback,
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
    k_dbrw: &[u8; 32],
    init: bool,
) -> Result<(), DsmError> {
    use crate::storage::client_db::{
        advance_local_cert_chain_head_with_sk, init_cert_chain_head,
        init_local_cert_chain_head_with_sk, CertChainSide,
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
            k_dbrw,
        )
        .map_err(|e| DsmError::invalid_operation(format!("chain-head SK init: {e}")))?;
    } else {
        advance_local_cert_chain_head_with_sk(
            relationship_key,
            new_ek_pk,
            new_ek_sk_in_memory,
            k_dbrw,
        )
        .map_err(|e| DsmError::invalid_operation(format!("chain-head SK advance: {e}")))?;
    }
    // Suppress unused-import in the init=false branch.
    let _ = (init_cert_chain_head, CertChainSide::Local);
    Ok(())
}

/// Which side of a bilateral receipt is being inspected for per-step EK
/// signing verification.
///
/// Used by [`verify_per_step_ek_signing`] to select between the A-side
/// (`ek_pk_a`/`ek_cert_a`/`sig_a`) and B-side fields on a stitched receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BilateralSide {
    /// Sender / initiating party.
    A,
    /// Receiver / counter-signing party.
    B,
}

/// Verify the per-step EK signing artifacts on one side of a stitched
/// receipt (whitepaper §11.1).
///
/// Checks two cryptographic invariants for the requested `side`:
///
/// 1. **Cert chain link**: `ek_cert_{side}` is a valid SPHINCS+ signature by
///    `expected_prev_pk` over `BLAKE3("DSM/ek-cert\0" || ek_pk_{side} || h_n)`.
///    `expected_prev_pk` is the signer of the cert — AK_pk at relationship
///    genesis (step 0) or `EK_pk_{n-1}` for steady-state transitions, loaded
///    from `cert_chain_heads`.
///
/// 2. **Receipt signature**: `sig_{side}` is a valid SPHINCS+ signature by
///    `ek_pk_{side}` over the receipt's canonical commitment hash
///    (`receipt.compute_commitment()`).
///
/// Returns `Ok(())` on success and a structured `DsmError` on the first
/// failed check (cert link error vs. signature error are distinguished in the
/// error message). The Kyber ciphertext (`kyber_ct_{side}`) is NOT checked
/// here — it is consumed by recipient-side k_step recovery, not by the
/// sender's signature verification.
///
/// Use this from the receiver's bilateral confirm handler to verify the
/// sender's A-side signing before applying the advance, and symmetrically
/// from the sender's commit-response handler when the protocol carries the
/// counter-signed receipt back.
pub fn verify_per_step_ek_signing(
    receipt: &StitchedReceiptV2,
    side: BilateralSide,
    expected_prev_pk: &[u8],
    h_n: &[u8; 32],
) -> Result<(), DsmError> {
    use dsm::crypto::ephemeral_key::verify_ek_cert;
    use dsm::crypto::sphincs::sphincs_verify;

    let (ek_pk, ek_cert, sig, label) = match side {
        BilateralSide::A => (
            &receipt.ek_pk_a,
            &receipt.ek_cert_a,
            &receipt.sig_a,
            "A",
        ),
        BilateralSide::B => (
            &receipt.ek_pk_b,
            &receipt.ek_cert_b,
            &receipt.sig_b,
            "B",
        ),
    };

    if ek_pk.is_empty() {
        return Err(DsmError::invalid_operation(format!(
            "verify_per_step_ek_signing: receipt missing ek_pk_{label}"
        )));
    }
    if ek_cert.is_empty() {
        return Err(DsmError::invalid_operation(format!(
            "verify_per_step_ek_signing: receipt missing ek_cert_{label}"
        )));
    }
    if sig.is_empty() {
        return Err(DsmError::invalid_operation(format!(
            "verify_per_step_ek_signing: receipt missing sig_{label}"
        )));
    }
    if expected_prev_pk.is_empty() {
        return Err(DsmError::invalid_operation(format!(
            "verify_per_step_ek_signing: expected_prev_pk for {label}-side is empty — \
             caller must supply AK_pk at step 0 or the prior chain head EK_pk for steady state"
        )));
    }

    // Step 1: cert chain link (prev_sk over hash(ek_pk_next || h_n)).
    let cert_ok = verify_ek_cert(expected_prev_pk, ek_pk, h_n, ek_cert).map_err(|e| {
        DsmError::crypto(
            format!("verify_per_step_ek_signing: cert chain verify error ({label}-side): {e}"),
            None::<std::io::Error>,
        )
    })?;
    if !cert_ok {
        return Err(DsmError::invalid_operation(format!(
            "verify_per_step_ek_signing: ek_cert_{label} does NOT chain ek_pk_{label} \
             back to expected_prev_pk over h_n — sig_{label} cannot be trusted"
        )));
    }

    // Step 2: receipt signature using ek_pk over commitment.
    let commitment = receipt.compute_commitment()?;
    let sig_ok = sphincs_verify(ek_pk, &commitment, sig).map_err(|e| {
        DsmError::crypto(
            format!("verify_per_step_ek_signing: sig verify error ({label}-side): {e}"),
            None::<std::io::Error>,
        )
    })?;
    if !sig_ok {
        return Err(DsmError::invalid_operation(format!(
            "verify_per_step_ek_signing: sig_{label} does NOT verify under ek_pk_{label} \
             over receipt commitment — receipt is unauthenticated"
        )));
    }

    Ok(())
}

/// Verify a stitched receipt with signatures.
///
/// Delegates to the canonical core verifier. Replay protection is enforced
/// by the `ParentConsumptionTracker` (one-time parent-tip lock per relationship),
/// NOT by sequence numbers — the protocol is clockless (§4.3).
///
/// Cert chain verification (whitepaper §11.1): if the
/// `cert_chain_heads` table has chain heads recorded for this relationship,
/// they are loaded automatically and threaded into the verification context.
/// The receipt's `ek_cert_a` / `ek_cert_b` MUST then verify against those
/// heads. If no chain head is recorded (relationship not yet established
/// or pre-feature legacy data), cert verification is skipped — the
/// transitional behavior. To make cert verification mandatory for a
/// relationship, call `init_cert_chain_head_for_relationship` first.
#[allow(clippy::too_many_arguments)]
pub fn verify_stitched_receipt(
    receipt: &StitchedReceiptV2,
    sig_a: &[u8],
    sig_b: &[u8],
    pk_a: &[u8],
    pk_b: &[u8],
    device_tree_commitment: DeviceTreeAcceptanceCommitment,
    guard: Option<&mut ReceiptGuard>,
) -> Result<(), DsmError> {
    use crate::sdk::app_state::AppState;
    use crate::storage::client_db::{
        is_strict_cert_chain_mode, load_cert_chain_head_pubkey, CertChainSide,
    };
    use dsm::verification::smt_replace_witness::compute_smt_key;

    let smt_key = compute_smt_key(&receipt.devid_a, &receipt.devid_b);
    let strict_mode = is_strict_cert_chain_mode().unwrap_or(false);
    // Per-relationship chain heads are optional during the transitional
    // period. When set, they make cert verification MANDATORY for this
    // relationship's receipts.
    //
    // Match receipt party (A vs B) to local-vs-counterparty roles by
    // looking up the local device id. If we can't determine which side
    // is local (genesis not initialized, etc.), skip auto-loading rather
    // than risk threading the wrong head into verification.
    let local_id = AppState::get_device_id();
    let (head_for_a, head_for_b): (Option<Vec<u8>>, Option<Vec<u8>>) =
        match local_id.as_deref() {
            Some(id) if id.len() == 32 && id == receipt.devid_a.as_slice() => {
                // We are party A. Our chain head verifies our own cert (sig_a),
                // counterparty's chain head verifies their cert (sig_b).
                (
                    load_cert_chain_head_pubkey(&smt_key, CertChainSide::Local)
                        .ok()
                        .flatten(),
                    load_cert_chain_head_pubkey(&smt_key, CertChainSide::Counterparty)
                        .ok()
                        .flatten(),
                )
            }
            Some(id) if id.len() == 32 && id == receipt.devid_b.as_slice() => {
                // We are party B (counter-signer). Local side maps to B; A is
                // the remote sender whose chain we track as Counterparty.
                (
                    load_cert_chain_head_pubkey(&smt_key, CertChainSide::Counterparty)
                        .ok()
                        .flatten(),
                    load_cert_chain_head_pubkey(&smt_key, CertChainSide::Local)
                        .ok()
                        .flatten(),
                )
            }
            _ => (None, None),
        };

    // Strict mode (whitepaper §11.1, mainnet-required): reject receipts for
    // relationships that have no recorded chain heads. Without this, a
    // relationship that "forgot" to call init_cert_chain_for_relationship
    // would silently skip cert verification — fail-open security regression.
    // Default off pre-mainnet to keep the transitional development path
    // workable; mainnet MUST call set_strict_cert_chain_mode(true).
    if strict_mode && head_for_a.is_none() && head_for_b.is_none() {
        return Err(DsmError::invalid_operation(
            "Receipt verification failed: strict cert-chain mode is on and no chain heads \
             are recorded for this relationship (init_cert_chain_for_relationship not called)",
        ));
    }

    // Per-step Kyber consistency (whitepaper §11): if the receipt carries
    // a per-step EK_pk_a, it MUST also carry the corresponding kyber_ct_a
    // — they're the two halves of the per-step EK derivation context. A
    // receipt with ek_pk_a but no kyber_ct_a is structurally malformed:
    // either the sender skipped the Kyber encapsulation (spec violation)
    // or the ct was stripped in transit. Same enforcement on the B side
    // when sig_b is present.
    if !receipt.ek_pk_a.is_empty() && receipt.kyber_ct_a.is_empty() {
        return Err(DsmError::invalid_operation(
            "Receipt verification failed: ek_pk_a is set but kyber_ct_a is missing — \
             per-step EK derivation requires both halves of the Kyber context",
        ));
    }
    if !sig_b.is_empty()
        && !receipt.ek_pk_b.is_empty()
        && receipt.kyber_ct_b.is_empty()
    {
        return Err(DsmError::invalid_operation(
            "Receipt verification failed: ek_pk_b is set but kyber_ct_b is missing — \
             per-step EK derivation requires both halves of the Kyber context",
        ));
    }

    // Per-step EK pubkey (whitepaper §11.1): when the receipt carries
    // `ek_pk_a`/`ek_pk_b`, those override the externally-passed `pk_a`/`pk_b`.
    // This is what makes `sig_a`/`sig_b` verifiable without out-of-band
    // distribution of per-step keys: each receipt carries its own freshly-
    // derived EK_pk, and the cert chain (already verified above via
    // ek_cert_a/b) chains it back to AK_pk.
    //
    // Legacy receipts (signed by the wallet's long-term identity key)
    // leave `ek_pk_a`/`ek_pk_b` empty; we fall back to the externally-
    // passed `pk_a`/`pk_b` so old receipts still verify.
    let pk_a_effective: Vec<u8> = if !receipt.ek_pk_a.is_empty() {
        receipt.ek_pk_a.clone()
    } else {
        pk_a.to_vec()
    };
    let pk_b_effective: Vec<u8> = if !receipt.ek_pk_b.is_empty() {
        receipt.ek_pk_b.clone()
    } else {
        pk_b.to_vec()
    };

    let mut ctx = ReceiptVerificationContext::new(
        device_tree_commitment,
        receipt.parent_root,
        pk_a_effective,
        pk_b_effective,
    );
    if let Some(head) = head_for_a {
        ctx = ctx.with_chain_head_a(head);
    }
    if let Some(head) = head_for_b {
        ctx = ctx.with_chain_head_b(head);
    }

    // Prepare signatures on the receipt
    let mut receipt_with_sigs = receipt.clone();
    receipt_with_sigs.add_sig_a(sig_a.to_vec());
    receipt_with_sigs.add_sig_b(sig_b.to_vec());

    // Use canonical verification
    let mut local_tracker;
    let tracker = if let Some(g) = guard {
        g
    } else {
        local_tracker = ReceiptGuard::new();
        &mut local_tracker
    };

    let result = dsm::verification::receipt_verification::verify_stitched_receipt(
        &receipt_with_sigs,
        &ctx,
        tracker,
    )?;

    if result.valid {
        Ok(())
    } else {
        Err(DsmError::invalid_operation(format!(
            "Receipt verification failed: {}",
            result.reason.unwrap_or_else(|| "unknown".to_string())
        )))
    }
}

/// Build a complete `StitchedReceiptV2` struct with real cryptographic material.
///
/// **This is the SINGLE authoritative receipt constructor for the entire SDK.**
/// All receipt construction — bilateral, unilateral, faucet, BLE, online —
/// MUST go through this function. It computes:
/// - Real genesis hash from `AppState`
/// - Stub parent/child SMT roots via `hash_smt_leaf()` (zero-depth, leaf=root)
/// - Parseable `SerializableMerkleProof` envelopes for relation proofs
/// - Canonical `DevTreeProof` for device binding
/// - Zero-depth SMT replace witness (verified against tripwire)
///
/// Returns `None` only if strict verification of the computed artifacts fails.
pub fn build_receipt_struct(
    devid_a: [u8; 32],
    devid_b: [u8; 32],
    parent_tip: [u8; 32],
    child_tip: [u8; 32],
    device_tree_commitment: Option<DeviceTreeAcceptanceCommitment>,
) -> Option<StitchedReceiptV2> {
    use dsm::common::device_tree;
    use dsm::verification::smt_replace_witness::{
        compute_smt_key, hash_smt_leaf, verify_tripwire_smt_replace,
    };

    // 1. Real genesis hash from AppState.
    let genesis = {
        let mut g = [0u8; 32];
        if let Some(gh) = crate::sdk::app_state::AppState::get_genesis_hash() {
            if gh.len() >= 32 {
                g.copy_from_slice(&gh[..32]);
            }
        }
        if g == [0u8; 32] {
            log::warn!(
                "[receipts] genesis hash unavailable from AppState — receipt will be unverifiable"
            );
            return None;
        }
        g
    };

    // 2. STUB: Compute degenerate single-leaf SMT roots (leaf hash = root).
    //    This creates a zero-depth tree where the leaf IS the root, with no
    //    siblings. The BLE offline path uses `build_bilateral_receipt_with_smt()`
    //    with real SparseMerkleTree roots instead. This stub path is for online receipts
    //    that don't yet track the full Per-Device SMT.
    let smt_key = compute_smt_key(&devid_a, &devid_b);
    let parent_root = hash_smt_leaf(&parent_tip);
    let child_root = hash_smt_leaf(&child_tip);

    // 3. Build parseable relation proofs in SmtInclusionProof format
    //    (zero-depth SMT: rel_key is the key, tip is the value, no siblings).
    let rel_proof_parent =
        serialize_inclusion_proof(&dsm::merkle::sparse_merkle_tree::SmtInclusionProof {
            key: smt_key,
            value: Some(parent_tip),
            siblings: Vec::new(),
        });
    let rel_proof_child =
        serialize_inclusion_proof(&dsm::merkle::sparse_merkle_tree::SmtInclusionProof {
            key: smt_key,
            value: Some(child_tip),
            siblings: Vec::new(),
        });

    // 4. Build device tree proof via DeviceTree builder (§2.3).
    //    The authenticated commitment used for `π_dev` MUST be supplied explicitly
    //    by the caller. Today that commitment is the concrete root `R_G`.
    let device_tree_commitment = match device_tree_commitment {
        Some(commitment) => commitment,
        None => {
            log::error!(
                "[receipts] build_receipt_struct: authenticated device-tree commitment is required; refusing to derive a synthetic R_G"
            );
            return None;
        }
    };
    let r_g = device_tree_commitment.root();
    let dev_tree = device_tree::DeviceTree::single(devid_a);
    let dev_proof_obj = dev_tree
        .proof(&devid_a)
        .unwrap_or(device_tree::DevTreeProof {
            siblings: Vec::new(),
            path_bits: Vec::new(),
            leaf_to_root: true,
        });
    let dev_proof = dev_proof_obj.to_bytes();

    // 5. Zero-depth replace witness.
    let witness: Vec<u8> = 0u32.to_le_bytes().to_vec();

    // 6. Strict verification: proofs must parse and tripwire must pass.
    if deserialize_inclusion_proof(&rel_proof_parent).is_err()
        || deserialize_inclusion_proof(&rel_proof_child).is_err()
    {
        log::warn!("[receipts] Failed to build parseable relation proofs");
        return None;
    }

    let parsed_dev = device_tree::DevTreeProof::from_bytes(&dev_proof)?;
    if !parsed_dev.verify(&devid_a, &r_g) {
        log::warn!("[receipts] Device proof verification failed against R_G");
        return None;
    }

    if !verify_tripwire_smt_replace(&parent_root, &child_root, &parent_tip, &child_tip, &witness)
        .ok()?
    {
        log::warn!("[receipts] Tripwire SMT replace witness verification failed");
        return None;
    }

    // 7. Assemble receipt.
    let mut receipt = StitchedReceiptV2::new(
        genesis,
        devid_a,
        devid_b,
        parent_tip,
        child_tip,
        parent_root,
        child_root,
        rel_proof_parent,
        rel_proof_child,
        dev_proof,
    );
    receipt.set_rel_replace_witness(witness);
    Some(receipt)
}

/// Convenience wrapper: build receipt and serialize to canonical protobuf bytes.
///
/// Delegates entirely to `build_receipt_struct()` for all crypto, then serializes.
pub fn build_bilateral_receipt(
    devid_a: [u8; 32],
    devid_b: [u8; 32],
    parent_tip: [u8; 32],
    child_tip: [u8; 32],
    device_tree_commitment: Option<DeviceTreeAcceptanceCommitment>,
) -> Option<Vec<u8>> {
    build_receipt_struct(
        devid_a,
        devid_b,
        parent_tip,
        child_tip,
        device_tree_commitment,
    )?
    .to_canonical_protobuf()
    .ok()
}

/// Build receipt with **real** Per-Device SMT roots and inclusion proofs (§4.2).
///
/// Unlike `build_bilateral_receipt()` which computes single-leaf stub proofs,
/// this function accepts the actual SMT roots and serialized inclusion proofs
/// produced by `SparseMerkleTree` after an `update_leaf()` call. Use this when the
/// caller has already performed the SMT-Replace and collected the proofs.
#[allow(clippy::too_many_arguments)]
pub fn build_bilateral_receipt_with_smt(
    devid_a: [u8; 32],
    devid_b: [u8; 32],
    parent_tip: [u8; 32],
    child_tip: [u8; 32],
    parent_root: [u8; 32],
    child_root: [u8; 32],
    rel_proof_parent: Vec<u8>,
    rel_proof_child: Vec<u8>,
    device_tree_commitment: Option<DeviceTreeAcceptanceCommitment>,
) -> Option<Vec<u8>> {
    use dsm::common::device_tree;

    // 1. Real genesis hash from AppState.
    let genesis = {
        let mut g = [0u8; 32];
        if let Some(gh) = crate::sdk::app_state::AppState::get_genesis_hash() {
            if gh.len() >= 32 {
                g.copy_from_slice(&gh[..32]);
            }
        }
        if g == [0u8; 32] {
            log::warn!(
                "[receipts] genesis hash unavailable from AppState — receipt will be unverifiable"
            );
            return None;
        }
        g
    };

    // 2. Build device tree proof via DeviceTree builder (§2.3).
    //    The authenticated commitment used for `π_dev` MUST be supplied explicitly
    //    by the caller. Today that commitment is the concrete root `R_G`.
    let device_tree_commitment = match device_tree_commitment {
        Some(commitment) => commitment,
        None => {
            log::error!(
                "[receipts] build_bilateral_receipt_with_smt: authenticated device-tree commitment is required; refusing to derive a synthetic R_G"
            );
            return None;
        }
    };
    let r_g = device_tree_commitment.root();
    let dev_tree = device_tree::DeviceTree::single(devid_a);
    let dev_proof_obj = dev_tree
        .proof(&devid_a)
        .unwrap_or(device_tree::DevTreeProof {
            siblings: Vec::new(),
            path_bits: Vec::new(),
            leaf_to_root: true,
        });
    let dev_proof = dev_proof_obj.to_bytes();

    // 3. Zero-depth replace witness (tripwire).
    let witness: Vec<u8> = 0u32.to_le_bytes().to_vec();

    // 4. Verify device proof against R_G before assembly.
    let parsed_dev = device_tree::DevTreeProof::from_bytes(&dev_proof)?;
    if !parsed_dev.verify(&devid_a, &r_g) {
        log::warn!("[receipts] Device proof verification failed against R_G");
        return None;
    }

    // 5. Assemble receipt with real SMT roots and proofs.
    let mut receipt = StitchedReceiptV2::new(
        genesis,
        devid_a,
        devid_b,
        parent_tip,
        child_tip,
        parent_root,
        child_root,
        rel_proof_parent,
        rel_proof_child,
        dev_proof,
    );
    receipt.set_rel_replace_witness(witness);
    receipt.to_canonical_protobuf().ok()
}

/// Verify a stitched receipt from its canonical protobuf bytes (§4.3).
///
/// Both counterparties share an **identical chain tip** h_n for C_{A↔B}.
/// Implements the normative verification rules from §4.3:
///
/// 1. Protobuf decodes the receipt
/// 2. All 32-byte fixed fields (genesis, devids, tips, roots) must be non-zero
/// 3. §4.3#2: π_rel proves h_n ∈ r_A and π'_rel proves h_{n+1} ∈ r'_A
///    (SmtInclusionProof deserialization + root reconstruction)
/// 4. §4.3#4: Leaf-replace recomputation — replacing h_n with h_{n+1} using
///    the same sibling path must yield r'_A byte-exactly
/// 5. §4.3#3: π_dev proves DevID_A ∈ R_G (Device Tree inclusion)
///
/// `device_tree_commitment`: explicit authenticated commitment for the sender's
/// Device Tree path. `None` is rejected.
/// Returns `true` only if all checks pass.
pub fn verify_receipt_bytes(
    receipt_bytes: &[u8],
    device_tree_commitment: Option<DeviceTreeAcceptanceCommitment>,
) -> bool {
    use dsm::merkle::sparse_merkle_tree::{SmtInclusionProof, SparseMerkleTree};
    use dsm::common::device_tree;
    use dsm::verification::smt_replace_witness::compute_smt_key;

    // 1. Decode the canonical protobuf into a StitchedReceiptV2.
    let receipt = match StitchedReceiptV2::from_canonical_protobuf(receipt_bytes) {
        Ok(r) => r,
        Err(_) => return false,
    };

    // 2. Non-zero fixed fields.
    let is_zero = |b: &[u8; 32]| b.iter().all(|&v| v == 0);
    if is_zero(&receipt.genesis)
        || is_zero(&receipt.devid_a)
        || is_zero(&receipt.devid_b)
        || is_zero(&receipt.parent_tip)
        || is_zero(&receipt.child_tip)
        || is_zero(&receipt.parent_root)
        || is_zero(&receipt.child_root)
    {
        return false;
    }

    // 3–4. §4.3#2+#4: Both counterparties share an IDENTICAL chain tip.
    //   π_rel proves h_n ∈ r_A, π'_rel proves h_{n+1} ∈ r'_A.
    //   Leaf-replace recomputation (same siblings, swap h_n→h_{n+1}) must yield r'_A.
    let smt_key = compute_smt_key(&receipt.devid_a, &receipt.devid_b);

    let parent_proof = deserialize_inclusion_proof(&receipt.rel_proof_parent).ok();
    let child_proof = match deserialize_inclusion_proof(&receipt.rel_proof_child) {
        Ok(p) => p,
        Err(_) => return false, // child proof must always exist (post-update)
    };

    // §4.3#2: π'_rel proves h_{n+1} ∈ r'_A
    if child_proof.key != smt_key {
        return false;
    }
    if child_proof.value != Some(receipt.child_tip) {
        return false;
    }
    if !SparseMerkleTree::verify_proof_against_root(&child_proof, &receipt.child_root) {
        return false;
    }

    if let Some(pp) = parent_proof {
        // Full verification: parent proof exists.
        if pp.key != smt_key {
            return false;
        }
        // §4.3#2: π_rel MUST prove inclusion of h_n in r_A.
        // Fail closed: the proof value must be present and must equal parent_tip.
        // A non-inclusion proof (value=None) or value mismatch both reject.
        match pp.value {
            Some(v) if v == receipt.parent_tip => { /* inclusion of correct tip */ }
            _ => return false,
        }

        // §4.3#2: π_rel proves h_n ∈ r_A
        if !SparseMerkleTree::verify_proof_against_root(&pp, &receipt.parent_root) {
            return false;
        }

        // §4.3#4: Leaf-replace recomputation.
        // Single leaf change ⇒ sibling path is identical.
        // Replace h_n with h_{n+1} using parent's siblings → must yield r'_A.
        let replace_proof = SmtInclusionProof {
            key: smt_key,
            value: Some(receipt.child_tip),
            siblings: pp.siblings,
        };
        if !SparseMerkleTree::verify_proof_against_root(&replace_proof, &receipt.child_root) {
            return false;
        }
    }
    // If parent proof absent: first tx for this relationship (leaf was ZERO_LEAF).
    // Child proof already verified above.

    // 5. §4.3#3: Device proof must parse and verify against the authenticated
    //    local commitment used for `π_dev`.
    //    Today this is the raw root `R_G`, supplied by the caller from a trusted
    //    external source (§2.3 commit path). If None, reject: acceptance predicates
    //    must never derive `R_G` from the receipt itself.
    let r_g = match device_tree_commitment {
        Some(commitment) => commitment.root(),
        None => {
            log::error!(
                "[receipts] §4.3#3 FATAL: authenticated device-tree commitment not provided — \
                 R_G or an equivalent authenticated persisted commitment must be externally supplied, never derived from the receipt itself."
            );
            return false;
        }
    };
    match device_tree::DevTreeProof::from_bytes(&receipt.dev_proof) {
        Some(parsed) => {
            if !parsed.verify(&receipt.devid_a, &r_g) {
                return false;
            }
        }
        None => return false,
    }

    true
}

/// Serialize a `SmtInclusionProof` to bytes for wire transport.
///
/// Format: [32-byte key][1-byte has_value][optional 32-byte value][4-byte LE sibling count][32-byte siblings...]
pub fn serialize_inclusion_proof(
    proof: &dsm::merkle::sparse_merkle_tree::SmtInclusionProof,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + 1 + 32 + 4 + proof.siblings.len() * 32);
    buf.extend_from_slice(&proof.key);
    buf.push(proof.value.is_some() as u8);
    if let Some(v) = &proof.value {
        buf.extend_from_slice(v);
    }
    buf.extend_from_slice(&(proof.siblings.len() as u32).to_le_bytes());
    for s in &proof.siblings {
        buf.extend_from_slice(s);
    }
    buf
}

/// Deserialize a `SmtInclusionProof` from bytes.
pub fn deserialize_inclusion_proof(
    data: &[u8],
) -> Result<dsm::merkle::sparse_merkle_tree::SmtInclusionProof, DsmError> {
    if data.len() < 33 {
        return Err(DsmError::invalid_operation(
            "inclusion proof too short: need at least 33 bytes",
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&data[..32]);
    let has_value = data[32] != 0;
    let mut offset = 33;
    let value = if has_value {
        if data.len() < offset + 32 {
            return Err(DsmError::invalid_operation(
                "inclusion proof truncated at value",
            ));
        }
        let mut v = [0u8; 32];
        v.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;
        Some(v)
    } else {
        None
    };
    if data.len() < offset + 4 {
        return Err(DsmError::invalid_operation(
            "inclusion proof truncated at sibling count",
        ));
    }
    let count =
        u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or_default()) as usize;
    offset += 4;
    if data.len() < offset + count * 32 {
        return Err(DsmError::invalid_operation(
            "inclusion proof truncated at siblings",
        ));
    }
    let mut siblings = Vec::with_capacity(count);
    for i in 0..count {
        let mut s = [0u8; 32];
        s.copy_from_slice(&data[offset + i * 32..offset + (i + 1) * 32]);
        siblings.push(s);
    }
    Ok(dsm::merkle::sparse_merkle_tree::SmtInclusionProof {
        key,
        value,
        siblings,
    })
}

/// Deterministically derive a stitched receipt sigma from canonical input parts.
///
/// This uses the DSM receipt commitment domain tag and length-prefixes each input
/// part to prevent ambiguity:
/// `BLAKE3("DSM/receipt-commit\0" || len(part_0)||part_0 || ... )`.
///
/// Callers should prefer a true `StitchedReceiptV2::compute_commitment()` when
/// available. This helper mirrors the same domain and deterministic framing.
pub fn derive_stitched_receipt_sigma(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = dsm::crypto::blake3::dsm_domain_hasher("DSM/receipt-commit");
    for part in parts {
        hasher.update(&(part.len() as u32).to_le_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
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
    dsm::crypto::blake3::domain_hash_bytes("DSM/protocol-transition", payload_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsm::merkle::sparse_merkle_tree::SmtInclusionProof;
    use dsm::types::device_state::DeviceState;
    use dsm::types::operations::Operation;

    // ── derive_per_step_ek (whitepaper §11.1) ──

    fn ek_ctx() -> PerStepEkContext {
        PerStepEkContext {
            h_n: [0x11; 32],
            c_pre: [0x22; 32],
            k_step: [0x33; 32],
        }
    }

    /// Derivation is deterministic in (h_n, c_pre, k_step, k_dbrw).
    #[test]
    fn derive_per_step_ek_deterministic() {
        let ctx = ek_ctx();
        let k_dbrw = [0x44; 32];
        let (pk1, sk1) = derive_per_step_ek(&ctx, &k_dbrw).unwrap();
        let (pk2, sk2) = derive_per_step_ek(&ctx, &k_dbrw).unwrap();
        assert_eq!(pk1, pk2);
        assert_eq!(sk1, sk2);
    }

    /// Distinct h_n produces distinct keypairs.
    #[test]
    fn derive_per_step_ek_diverges_on_h_n() {
        let mut ctx_a = ek_ctx();
        let mut ctx_b = ek_ctx();
        ctx_b.h_n = [0xAA; 32];
        let k_dbrw = [0x44; 32];
        let (pk_a, _) = derive_per_step_ek(&ctx_a, &k_dbrw).unwrap();
        let (pk_b, _) = derive_per_step_ek(&ctx_b, &k_dbrw).unwrap();
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
        let k_dbrw = [0x44; 32];
        let (pk_a, _) = derive_per_step_ek(&ctx_a, &k_dbrw).unwrap();
        let (pk_b, _) = derive_per_step_ek(&ctx_b, &k_dbrw).unwrap();
        assert_ne!(pk_a, pk_b);
    }

    /// Distinct K_DBRW produces distinct keypairs (DBRW binding works).
    #[test]
    fn derive_per_step_ek_diverges_on_k_dbrw() {
        let ctx = ek_ctx();
        let (pk_a, _) = derive_per_step_ek(&ctx, &[0x44; 32]).unwrap();
        let (pk_b, _) = derive_per_step_ek(&ctx, &[0x55; 32]).unwrap();
        assert_ne!(pk_a, pk_b);
    }

    /// Resulting keypair signs and verifies correctly under SPHINCS+.
    #[test]
    fn derive_per_step_ek_keypair_signs_and_verifies() {
        let ctx = ek_ctx();
        let k_dbrw = [0x44; 32];
        let (pk, sk) = derive_per_step_ek(&ctx, &k_dbrw).unwrap();
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
        let k_dbrw = [0x44u8; 32];

        let encap = derive_kyber_k_step_for_send(
            &h_n, &c_pre, &devid_sender, &k_dbrw, &recipient_kp.public_key,
        )
        .expect("encap");

        let decap = derive_kyber_k_step_for_verify(&encap.ciphertext, &recipient_kp.secret_key)
            .expect("decap");

        assert_eq!(encap.k_step, decap, "sender and recipient must derive identical k_step");
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
        let k_dbrw = [0x44u8; 32];

        let encap_1 = derive_kyber_k_step_for_send(
            &[0xAA; 32], &c_pre, &devid_sender, &k_dbrw, &recipient_kp.public_key,
        )
        .expect("encap step 1");
        let encap_2 = derive_kyber_k_step_for_send(
            &[0xBB; 32], &c_pre, &devid_sender, &k_dbrw, &recipient_kp.public_key,
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
        let k_dbrw = [0x44u8; 32];

        let to_1 = derive_kyber_k_step_for_send(
            &h_n, &c_pre, &devid_sender, &k_dbrw, &kp1.public_key,
        )
        .expect("encap to kp1");
        let to_2 = derive_kyber_k_step_for_send(
            &h_n, &c_pre, &devid_sender, &k_dbrw, &kp2.public_key,
        )
        .expect("encap to kp2");
        assert_ne!(to_1.k_step, to_2.k_step);
    }

    /// Sender helper rejects an empty recipient Kyber pubkey (no fallback).
    #[test]
    fn kyber_k_step_rejects_empty_recipient_pubkey() {
        let result = derive_kyber_k_step_for_send(
            &[0x11; 32], &[0x22; 32], &[0x33; 32], &[0x44; 32], &[],
        );
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

    /// Helper: build minimal valid signing inputs for tests.
    fn signing_inputs<'a>(
        commitment: &'a [u8; 32],
        rel_key: &[u8; 32],
        ak_pk: &'a [u8],
        ak_sk: &'a [u8],
        k_dbrw: &'a [u8; 32],
        recipient_kyber_pk: &'a [u8],
    ) -> PerStepSigningInputs<'a> {
        PerStepSigningInputs {
            commitment,
            h_n: [0xAA; 32],
            c_pre: [0xBB; 32],
            devid_sender: [0x11; 32],
            relationship_key: *rel_key,
            k_dbrw,
            fallback_ak_keypair: Some((ak_pk, ak_sk)),
            recipient_kyber_pk,
        }
    }

    /// First-ever signing for a relationship: helper falls back to AK,
    /// uses it to sign cert; receipt body is signed by the new EK_sk.
    /// Returned cert verifies against AK_pk.
    #[test]
    #[serial_test::serial]
    fn per_step_signing_uses_ak_fallback_when_chain_head_absent() {
        use crate::storage::client_db::reset_database_for_tests;
        use dsm::crypto::ephemeral_key::{generate_ephemeral_keypair, verify_ek_cert};
        use dsm::crypto::sphincs::sphincs_verify;

        reset_database_for_tests();

        let (ak_pk, ak_sk) = generate_ephemeral_keypair(&[0x01; 32]).unwrap();
        let kyber_kp = dsm::crypto::kyber::generate_kyber_keypair()
            .expect("kyber keygen");
        let kyber_pk = kyber_kp.public_key.clone();
        let commitment = [0xCC; 32];
        let rel_key = [0xDE; 32];
        let k_dbrw = [0xFF; 32];

        let inputs = signing_inputs(&commitment, &rel_key, &ak_pk, &ak_sk, &k_dbrw, &kyber_pk);
        let out = sign_receipt_with_per_step_ek(&inputs).unwrap();

        assert!(out.used_ak_fallback);
        assert!(!out.ek_pk.is_empty());
        assert!(!out.ek_sk.is_empty());
        assert!(!out.ek_cert.is_empty());
        assert!(!out.sig.is_empty());

        // The cert must verify against the AK pubkey.
        let cert_ok = verify_ek_cert(&ak_pk, &out.ek_pk, &inputs.h_n, &out.ek_cert).unwrap();
        assert!(cert_ok, "cert must verify against AK pubkey when AK fallback is used");

        // The receipt-body signature must verify against the per-step EK pubkey.
        let sig_ok = sphincs_verify(&out.ek_pk, &commitment, &out.sig).unwrap();
        assert!(sig_ok, "sig_a must verify against the per-step EK pubkey");
    }

    /// After advance, the next signing call uses the prior EK_sk (no
    /// AK fallback). Cert chain step n+1 verifies against EK_pk_n.
    #[test]
    #[serial_test::serial]
    fn per_step_signing_chains_through_advancement() {
        use crate::storage::client_db::reset_database_for_tests;
        use dsm::crypto::ephemeral_key::{generate_ephemeral_keypair, verify_ek_cert};

        reset_database_for_tests();

        let (ak_pk, ak_sk) = generate_ephemeral_keypair(&[0x02; 32]).unwrap();
        let kyber_kp = dsm::crypto::kyber::generate_kyber_keypair()
            .expect("kyber keygen");
        let kyber_pk = kyber_kp.public_key.clone();
        let rel_key = [0xCA; 32];
        let k_dbrw = [0xFE; 32];

        // Step 0: AK fallback path. Sign + advance to record EK_1 as chain head.
        let commit0 = [0xC0; 32];
        let inputs0 = signing_inputs(&commit0, &rel_key, &ak_pk, &ak_sk, &k_dbrw, &kyber_pk);
        let out0 = sign_receipt_with_per_step_ek(&inputs0).unwrap();
        assert!(out0.used_ak_fallback);
        advance_local_chain_head_after_signing(&rel_key, &out0.ek_pk, &out0.ek_sk, &k_dbrw, true)
            .unwrap();

        // Step 1: chain head is EK_1 — fallback NOT used.
        let commit1 = [0xC1; 32];
        let mut inputs1 = signing_inputs(&commit1, &rel_key, &ak_pk, &ak_sk, &k_dbrw, &kyber_pk);
        inputs1.h_n = [0xBB; 32]; // pretend we advanced the chain
        let out1 = sign_receipt_with_per_step_ek(&inputs1).unwrap();
        assert!(!out1.used_ak_fallback, "step 1 must use chain-head SK, not AK fallback");
        // Cert at step 1 must verify against EK_1 (the prior step's pubkey).
        let cert_ok = verify_ek_cert(&out0.ek_pk, &out1.ek_pk, &inputs1.h_n, &out1.ek_cert)
            .unwrap();
        assert!(cert_ok, "step-1 cert must verify against EK_pk_0");

        // Cert at step 1 must NOT verify against AK (proves we actually advanced).
        let cert_against_ak =
            verify_ek_cert(&ak_pk, &out1.ek_pk, &inputs1.h_n, &out1.ek_cert).unwrap();
        assert!(!cert_against_ak, "step-1 cert must NOT verify against AK after advance");
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
        let kyber_kp = dsm::crypto::kyber::generate_kyber_keypair()
            .expect("kyber keygen");
        let kyber_pk = kyber_kp.public_key.clone();
        let rel_key = [0xE1; 32];
        let k_dbrw = [0xE2; 32];

        // ────── Step 0 ──────
        let commit0 = [0xF0; 32];
        let inputs0 = signing_inputs(&commit0, &rel_key, &ak_pk, &ak_sk, &k_dbrw, &kyber_pk);
        let out0 = sign_receipt_with_per_step_ek(&inputs0).unwrap();

        // Cert step 0 chains EK_0 → AK.
        assert!(verify_ek_cert(&ak_pk, &out0.ek_pk, &inputs0.h_n, &out0.ek_cert).unwrap());
        // Receipt body verifies under EK_0.
        assert!(sphincs_verify(&out0.ek_pk, &commit0, &out0.sig).unwrap());

        // Persist EK_0 as new chain head.
        advance_local_chain_head_after_signing(&rel_key, &out0.ek_pk, &out0.ek_sk, &k_dbrw, true)
            .unwrap();

        // ────── Step 1 ──────
        let commit1 = [0xF1; 32];
        // Simulate chain advancement: new h_n.
        let mut inputs1 = signing_inputs(&commit1, &rel_key, &ak_pk, &ak_sk, &k_dbrw, &kyber_pk);
        inputs1.h_n = [0xB1; 32];
        let out1 = sign_receipt_with_per_step_ek(&inputs1).unwrap();

        // Step-1 cert chains EK_1 → EK_0 (the prior chain head).
        assert!(!out1.used_ak_fallback);
        assert!(verify_ek_cert(&out0.ek_pk, &out1.ek_pk, &inputs1.h_n, &out1.ek_cert).unwrap());
        // Step-1 cert MUST NOT verify against AK (proves we walked the chain).
        assert!(!verify_ek_cert(&ak_pk, &out1.ek_pk, &inputs1.h_n, &out1.ek_cert).unwrap());
        // Receipt body at step 1 verifies under EK_1.
        assert!(sphincs_verify(&out1.ek_pk, &commit1, &out1.sig).unwrap());

        // Distinct EK at step 1 vs step 0.
        assert_ne!(out0.ek_pk, out1.ek_pk);

        advance_local_chain_head_after_signing(
            &rel_key,
            &out1.ek_pk,
            &out1.ek_sk,
            &k_dbrw,
            false,
        )
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
    ///   (P4) Each step's receipt-body sig verifies against that
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
        let kyber_kp = dsm::crypto::kyber::generate_kyber_keypair()
            .expect("kyber keygen");
        let kyber_pk = kyber_kp.public_key.clone();
            let rel_key = [0xB0; 32];
            let k_dbrw = [0xC0; 32];

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
                    k_dbrw: &k_dbrw,
                    fallback_ak_keypair: Some((&ak_pk, &ak_sk)),
                    recipient_kyber_pk: &kyber_pk,
                };
                let out = sign_receipt_with_per_step_ek(&inputs).unwrap();

                // Advance chain head so step+1 won't take the AK fallback.
                advance_local_chain_head_after_signing(
                    &rel_key,
                    &out.ek_pk,
                    &out.ek_sk,
                    &k_dbrw,
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

            // (P4) Each step's receipt-body sig verifies against that
            //      step's EK_pk only.
            for i in 0..chain_length {
                assert!(
                    sphincs_verify(&chain_pubkeys[i], &chain_commits[i], &chain_sigs[i]).unwrap(),
                    "P4 violated at len={}, step={}",
                    chain_length,
                    i
                );
                // And NOT under the previous step's EK_pk.
                if i > 0 {
                    assert!(
                        !sphincs_verify(
                            &chain_pubkeys[i - 1],
                            &chain_commits[i],
                            &chain_sigs[i]
                        )
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

    /// Without a fallback AK keypair AND without a stored chain head,
    /// signing fails with a clear error.
    #[test]
    #[serial_test::serial]
    fn per_step_signing_errors_without_chain_head_or_fallback() {
        use crate::storage::client_db::reset_database_for_tests;
        reset_database_for_tests();

        let commit = [0xCC; 32];
        let rel_key = [0xCD; 32];
        let k_dbrw = [0xCE; 32];
        let inputs = PerStepSigningInputs {
            commitment: &commit,
            h_n: [0xAA; 32],
            c_pre: [0xBB; 32],
            devid_sender: [0x11; 32],
            relationship_key: rel_key,
            k_dbrw: &k_dbrw,
            fallback_ak_keypair: None,
            recipient_kyber_pk: &[],
        };
        let result = sign_receipt_with_per_step_ek(&inputs);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("requires chain-head SK or fallback AK"));
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
        let k_dbrw = [0xE8; 32];

        // Build a minimal receipt with deterministic content so
        // `compute_commitment` is stable.
        let mut receipt = StitchedReceiptV2::new(
            [0x01; 32], // genesis
            [0x02; 32], // devid_a
            [0x03; 32], // devid_b
            [0xAA; 32], // parent_tip == h_n the verifier will receive
            [0x04; 32], // child_tip
            [0x05; 32], // parent_root
            [0x06; 32], // child_root
            vec![0x07; 16], // rel_proof_parent
            vec![0x08; 16], // rel_proof_child
            vec![0x09; 16], // dev_proof
        );
        let commitment = receipt.compute_commitment().unwrap();

        let inputs = PerStepSigningInputs {
            commitment: &commitment,
            h_n: [0xAA; 32],
            c_pre: [0xBB; 32],
            devid_sender: [0x11; 32],
            relationship_key: rel_key,
            k_dbrw: &k_dbrw,
            fallback_ak_keypair: Some((&ak_pk, &ak_sk)),
            recipient_kyber_pk: &kyber_pk,
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
        verify_per_step_ek_signing(&receipt, BilateralSide::A, &ak_pk, &h_n)
            .expect("a freshly-signed A-side receipt must verify under AK + h_n");
    }

    #[test]
    #[serial_test::serial]
    fn verify_per_step_ek_signing_accepts_well_formed_b_side() {
        let (receipt, ak_pk, h_n) =
            build_signed_receipt_for_verifier_test(BilateralSide::B, &[0xB1; 32]);
        verify_per_step_ek_signing(&receipt, BilateralSide::B, &ak_pk, &h_n)
            .expect("a freshly-signed B-side receipt must verify under AK + h_n");
    }

    /// Tampering the receipt commitment after signing must invalidate sig.
    #[test]
    #[serial_test::serial]
    fn verify_per_step_ek_signing_rejects_commitment_tamper() {
        let (mut receipt, ak_pk, h_n) =
            build_signed_receipt_for_verifier_test(BilateralSide::A, &[0xA2; 32]);

        // Mutate a field that participates in commitment computation. The
        // cert-link check still passes (the EK→AK chain is unaffected by
        // the receipt body), but the receipt-body signature must fail.
        receipt.parent_root = [0xDE; 32];

        let err = verify_per_step_ek_signing(&receipt, BilateralSide::A, &ak_pk, &h_n)
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
        let err = verify_per_step_ek_signing(&receipt, BilateralSide::A, &attacker_pk, &h_n)
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
        let err =
            verify_per_step_ek_signing(&receipt, BilateralSide::A, &ak_pk, &wrong_h_n)
                .expect_err("cert pinned to a different h_n must not verify");
        let msg = err.to_string();
        assert!(
            msg.contains("does NOT chain") || msg.contains("cert chain"),
            "expected cert-link failure, got: {msg}"
        );
    }

    /// An empty cert/sig/ek_pk surface must reject with a descriptive error
    /// instead of panicking inside the SPHINCS+ verifier.
    #[test]
    #[serial_test::serial]
    fn verify_per_step_ek_signing_rejects_missing_artifacts() {
        let (mut receipt, ak_pk, h_n) =
            build_signed_receipt_for_verifier_test(BilateralSide::A, &[0xA5; 32]);

        // Drop sig_a — receipt now has cert + ek_pk but no signature.
        receipt.sig_a = vec![];
        let err = verify_per_step_ek_signing(&receipt, BilateralSide::A, &ak_pk, &h_n)
            .expect_err("empty sig_a must fail-closed");
        assert!(err.to_string().contains("missing sig_A"));

        // B-side never signed for this receipt, so all B fields are empty.
        let err_b = verify_per_step_ek_signing(&receipt, BilateralSide::B, &ak_pk, &h_n)
            .expect_err("requesting B-side verification on an A-only receipt must fail-closed");
        assert!(err_b.to_string().contains("missing ek_pk_B"));
    }

    // ── derive_relationship_key ──

    #[test]
    fn derive_relationship_key_deterministic() {
        let pk = [0xABu8; 32];
        let a = derive_relationship_key(&pk);
        let b = derive_relationship_key(&pk);
        assert_eq!(a, b, "same input must yield identical key");
    }

    #[test]
    fn derive_relationship_key_varies_with_input() {
        let k1 = derive_relationship_key(&[1u8; 32]);
        let k2 = derive_relationship_key(&[2u8; 32]);
        assert_ne!(k1, k2);
    }

    #[test]
    fn derive_relationship_key_nonzero() {
        let k = derive_relationship_key(b"any-counterparty-pk");
        assert_ne!(k, [0u8; 32]);
    }

    // ── serialize / deserialize inclusion proof round-trip ──

    fn sample_proof(with_value: bool, siblings: usize) -> SmtInclusionProof {
        SmtInclusionProof {
            key: [0x11u8; 32],
            value: if with_value { Some([0x22u8; 32]) } else { None },
            siblings: (0..siblings)
                .map(|i| [(i as u8).wrapping_add(0x30); 32])
                .collect(),
        }
    }

    #[test]
    fn roundtrip_proof_with_value_no_siblings() {
        let proof = sample_proof(true, 0);
        let bytes = serialize_inclusion_proof(&proof);
        let decoded = deserialize_inclusion_proof(&bytes).unwrap();
        assert_eq!(decoded.key, proof.key);
        assert_eq!(decoded.value, proof.value);
        assert!(decoded.siblings.is_empty());
    }

    #[test]
    fn roundtrip_proof_without_value_no_siblings() {
        let proof = sample_proof(false, 0);
        let bytes = serialize_inclusion_proof(&proof);
        let decoded = deserialize_inclusion_proof(&bytes).unwrap();
        assert_eq!(decoded.key, proof.key);
        assert_eq!(decoded.value, None);
        assert!(decoded.siblings.is_empty());
    }

    #[test]
    fn roundtrip_proof_with_value_and_siblings() {
        let proof = sample_proof(true, 4);
        let bytes = serialize_inclusion_proof(&proof);
        let decoded = deserialize_inclusion_proof(&bytes).unwrap();
        assert_eq!(decoded.key, proof.key);
        assert_eq!(decoded.value, proof.value);
        assert_eq!(decoded.siblings.len(), 4);
        assert_eq!(decoded.siblings, proof.siblings);
    }

    #[test]
    fn roundtrip_proof_without_value_with_siblings() {
        let proof = sample_proof(false, 3);
        let bytes = serialize_inclusion_proof(&proof);
        let decoded = deserialize_inclusion_proof(&bytes).unwrap();
        assert_eq!(decoded.value, None);
        assert_eq!(decoded.siblings.len(), 3);
    }

    #[test]
    fn serialize_proof_expected_length_with_value() {
        let proof = sample_proof(true, 2);
        let bytes = serialize_inclusion_proof(&proof);
        // 32 (key) + 1 (has_value) + 32 (value) + 4 (count) + 2*32 (siblings)
        assert_eq!(bytes.len(), 32 + 1 + 32 + 4 + 64);
    }

    #[test]
    fn serialize_proof_expected_length_without_value() {
        let proof = sample_proof(false, 2);
        let bytes = serialize_inclusion_proof(&proof);
        // 32 (key) + 1 (has_value) + 4 (count) + 2*32 (siblings)
        assert_eq!(bytes.len(), 32 + 1 + 4 + 64);
    }

    // ── deserialize error cases ──

    #[test]
    fn deserialize_too_short() {
        let short = vec![0u8; 10];
        assert!(deserialize_inclusion_proof(&short).is_err());
    }

    #[test]
    fn deserialize_truncated_at_value() {
        // 32 key + has_value=1, but no value bytes
        let mut data = vec![0u8; 33];
        data[32] = 1; // has_value = true
        assert!(deserialize_inclusion_proof(&data).is_err());
    }

    #[test]
    fn deserialize_truncated_at_sibling_count() {
        // 32 key + has_value=0, missing sibling count bytes
        let data = vec![0u8; 33]; // has_value=0, no count
        assert!(deserialize_inclusion_proof(&data).is_err());
    }

    #[test]
    fn deserialize_truncated_siblings() {
        // valid header + count=2, but only 1 sibling worth of bytes
        let proof = sample_proof(false, 2);
        let bytes = serialize_inclusion_proof(&proof);
        let truncated = &bytes[..bytes.len() - 16]; // remove half of second sibling
        assert!(deserialize_inclusion_proof(truncated).is_err());
    }

    #[test]
    fn deserialize_empty_is_err() {
        assert!(deserialize_inclusion_proof(&[]).is_err());
    }

    // ── derive_stitched_receipt_sigma ──

    #[test]
    fn sigma_deterministic() {
        let parts: Vec<&[u8]> = vec![b"hello", b"world"];
        let a = derive_stitched_receipt_sigma(&parts);
        let b = derive_stitched_receipt_sigma(&parts);
        assert_eq!(a, b);
    }

    #[test]
    fn sigma_varies_with_different_parts() {
        let s1 = derive_stitched_receipt_sigma(&[b"a", b"b"]);
        let s2 = derive_stitched_receipt_sigma(&[b"a", b"c"]);
        assert_ne!(s1, s2);
    }

    #[test]
    fn sigma_order_matters() {
        let s1 = derive_stitched_receipt_sigma(&[b"first", b"second"]);
        let s2 = derive_stitched_receipt_sigma(&[b"second", b"first"]);
        assert_ne!(s1, s2);
    }

    #[test]
    fn sigma_empty_parts() {
        let s = derive_stitched_receipt_sigma(&[]);
        assert_ne!(s, [0u8; 32]);
    }

    #[test]
    fn sigma_nonzero() {
        let s = derive_stitched_receipt_sigma(&[b"test"]);
        assert_ne!(s, [0u8; 32]);
    }

    #[test]
    fn sigma_length_prefixing_prevents_ambiguity() {
        // "ab" + "cd" vs "abc" + "d" should differ due to length prefixes
        let s1 = derive_stitched_receipt_sigma(&[b"ab", b"cd"]);
        let s2 = derive_stitched_receipt_sigma(&[b"abc", b"d"]);
        assert_ne!(s1, s2);
    }

    // #[serial] required: this test mutates the process-global `AppState`
    // (via `set_identity_info`) and the `DSM_SDK_TEST_MODE` env var. Running
    // concurrently with other identity/AppState-touching tests (e.g.
    // `dlv_sdk::tests::*` and `bilateral_ble_handler::tests::test_register_
    // sender_session_persists_canonical_sender_session`) produces intermittent
    // CI failures where one test sees the other's identity.
    #[test]
    #[serial_test::serial]
    fn first_ever_receipt_requires_merkle_pre_root_not_cas_parent_root() {
        unsafe {
            std::env::set_var("DSM_SDK_TEST_MODE", "1");
        }

        let devid_a = [0x41u8; 32];
        let devid_b = [0x42u8; 32];
        let genesis = [0x43u8; 32];
        let public_key = vec![0x44u8; 64];
        let initial_tip = [0x45u8; 32];

        let storage_dir =
            std::env::temp_dir().join(format!("dsm_receipts_test_{}", std::process::id()));
        let _ = crate::storage_utils::set_storage_base_dir(storage_dir);

        crate::sdk::app_state::AppState::set_identity_info(
            devid_a.to_vec(),
            public_key.clone(),
            genesis.to_vec(),
            [0u8; 32].to_vec(),
        );

        let device_tree_commitment = Some(DeviceTreeAcceptanceCommitment::from_root(
            dsm::common::device_tree::DeviceTree::single(devid_a).root(),
        ));

        let state = DeviceState::new(genesis, devid_a, public_key, 64);
        let rel_key = dsm::verification::smt_replace_witness::compute_smt_key(&devid_a, &devid_b);
        let outcome = state
            .advance(
                rel_key,
                devid_b,
                Operation::Noop,
                vec![0x46; 32],
                None,
                &[],
                Some(initial_tip),
                None,
            )
            .expect("first-ever advance should succeed");

        assert_ne!(
            outcome.parent_r_a, outcome.smt_proofs.pre_root,
            "first-ever advance must distinguish CAS parent root from Merkle proof pre_root"
        );

        let parent_tip = outcome
            .smt_proofs
            .parent_proof
            .value
            .expect("first-ever parent proof should carry seeded initial tip");
        let child_tip = outcome.new_chain_state.compute_chain_tip();
        let parent_proof = outcome.smt_proofs.parent_proof.to_bytes();
        let child_proof = outcome.smt_proofs.child_proof.to_bytes();

        let receipt_with_proof_root = build_bilateral_receipt_with_smt(
            devid_a,
            devid_b,
            parent_tip,
            child_tip,
            outcome.smt_proofs.pre_root,
            outcome.child_r_a,
            parent_proof.clone(),
            child_proof.clone(),
            device_tree_commitment,
        )
        .expect("receipt with Merkle pre_root");
        assert!(verify_receipt_bytes(
            &receipt_with_proof_root,
            device_tree_commitment,
        ));

        let receipt_with_cas_root = build_bilateral_receipt_with_smt(
            devid_a,
            devid_b,
            parent_tip,
            child_tip,
            outcome.parent_r_a,
            outcome.child_r_a,
            parent_proof,
            child_proof,
            device_tree_commitment,
        )
        .expect("receipt with CAS parent root");
        assert!(
            !verify_receipt_bytes(&receipt_with_cas_root, device_tree_commitment),
            "using parent_r_a should fail receipt verification on first-ever advances"
        );
    }

    /// Strict cert-chain mode (whitepaper §11.1, mainnet-required) rejects
    /// receipts for relationships that have no recorded chain heads. This
    /// is the fail-closed behavior that closes the security gap Gemini
    /// flagged in adversarial review of the chain-head threading commit
    /// — without strict mode, a relationship whose `init_cert_chain_for_relationship`
    /// was never called would silently skip cert verification.
    #[test]
    #[serial_test::serial]
    fn strict_mode_rejects_receipt_without_chain_heads() {
        use crate::storage::client_db::{
            reset_database_for_tests, set_strict_cert_chain_mode,
        };

        unsafe {
            std::env::set_var("DSM_SDK_TEST_MODE", "1");
        }

        let devid_a = [0x71u8; 32];
        let devid_b = [0x72u8; 32];
        let genesis = [0x73u8; 32];
        let public_key = vec![0x74u8; 64];

        let storage_dir = std::env::temp_dir()
            .join(format!("dsm_strict_mode_test_{}", std::process::id()));
        let _ = crate::storage_utils::set_storage_base_dir(storage_dir);
        reset_database_for_tests();

        crate::sdk::app_state::AppState::set_identity_info(
            devid_a.to_vec(),
            public_key.clone(),
            genesis.to_vec(),
            [0u8; 32].to_vec(),
        );

        // Enable strict mode, but DO NOT initialize chain heads for this
        // relationship — exactly the scenario Gemini flagged.
        set_strict_cert_chain_mode(true).unwrap();

        // Build a minimal receipt; we don't need it to verify
        // cryptographically — strict-mode rejection fires BEFORE the
        // canonical core verifier runs.
        let receipt = StitchedReceiptV2::new(
            genesis, devid_a, devid_b,
            [0x01; 32], [0x02; 32],
            [0x03; 32], [0x04; 32],
            vec![], vec![], vec![],
        );
        let device_tree_commitment = DeviceTreeAcceptanceCommitment::from_root(
            dsm::common::device_tree::DeviceTree::single(devid_a).root(),
        );

        let result = verify_stitched_receipt(
            &receipt,
            &[0xAA; 64],
            &[0xBB; 64],
            &public_key,
            &public_key,
            device_tree_commitment,
            None,
        );

        assert!(result.is_err(), "strict mode without chain heads must reject");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("strict cert-chain mode") || err.contains("init_cert_chain_for_relationship"),
            "wrong rejection reason: {}",
            err
        );

        // Reset strict mode for any subsequent tests.
        set_strict_cert_chain_mode(false).unwrap();
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

    // ── serialize/deserialize: additional edge cases ──

    #[test]
    fn roundtrip_proof_many_siblings() {
        let proof = SmtInclusionProof {
            key: [0xFF; 32],
            value: Some([0xEE; 32]),
            siblings: (0..256).map(|i| [(i as u8); 32]).collect(),
        };
        let bytes = serialize_inclusion_proof(&proof);
        let decoded = deserialize_inclusion_proof(&bytes).unwrap();
        assert_eq!(decoded.siblings.len(), 256);
        assert_eq!(decoded.key, [0xFF; 32]);
        assert_eq!(decoded.value, Some([0xEE; 32]));
        for (i, sib) in decoded.siblings.iter().enumerate() {
            assert_eq!(*sib, [(i as u8); 32]);
        }
    }

    #[test]
    fn serialize_proof_key_is_first_32_bytes() {
        let proof = SmtInclusionProof {
            key: [0xAB; 32],
            value: None,
            siblings: vec![],
        };
        let bytes = serialize_inclusion_proof(&proof);
        assert_eq!(&bytes[..32], &[0xAB; 32]);
    }

    #[test]
    fn serialize_has_value_byte_zero_when_none() {
        let proof = SmtInclusionProof {
            key: [0; 32],
            value: None,
            siblings: vec![],
        };
        let bytes = serialize_inclusion_proof(&proof);
        assert_eq!(bytes[32], 0);
    }

    #[test]
    fn serialize_has_value_byte_one_when_some() {
        let proof = SmtInclusionProof {
            key: [0; 32],
            value: Some([0; 32]),
            siblings: vec![],
        };
        let bytes = serialize_inclusion_proof(&proof);
        assert_eq!(bytes[32], 1);
    }

    #[test]
    fn deserialize_exact_minimum_no_value() {
        // 32 key + 1 has_value(0) + 4 count(0) = 37 bytes
        let mut data = vec![0u8; 37];
        data[32] = 0; // has_value = false
                      // count bytes already zero (0 siblings)
        let proof = deserialize_inclusion_proof(&data).unwrap();
        assert_eq!(proof.key, [0u8; 32]);
        assert_eq!(proof.value, None);
        assert!(proof.siblings.is_empty());
    }

    #[test]
    fn deserialize_exact_minimum_with_value() {
        // 32 key + 1 has_value(1) + 32 value + 4 count(0) = 69 bytes
        let mut data = vec![0u8; 69];
        data[32] = 1; // has_value = true
        data[33..65].copy_from_slice(&[0xCC; 32]); // value
                                                   // count bytes at 65..69 already zero
        let proof = deserialize_inclusion_proof(&data).unwrap();
        assert_eq!(proof.value, Some([0xCC; 32]));
        assert!(proof.siblings.is_empty());
    }

    #[test]
    fn deserialize_sibling_count_as_le_u32() {
        let proof = sample_proof(false, 1);
        let bytes = serialize_inclusion_proof(&proof);
        // After key(32) + has_value(1) byte, count is at offset 33..37
        let count = u32::from_le_bytes(bytes[33..37].try_into().unwrap());
        assert_eq!(count, 1);
    }

    // ── sigma: additional edge cases ──

    #[test]
    fn sigma_single_empty_part_differs_from_no_parts() {
        let s_empty = derive_stitched_receipt_sigma(&[]);
        let s_one_empty = derive_stitched_receipt_sigma(&[b""]);
        assert_ne!(s_empty, s_one_empty);
    }

    #[test]
    fn sigma_large_input() {
        let big = vec![0x42u8; 10_000];
        let s = derive_stitched_receipt_sigma(&[&big]);
        assert_ne!(s, [0u8; 32]);
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

    // ── derive_relationship_key: additional ──

    #[test]
    fn derive_relationship_key_empty_input() {
        let k = derive_relationship_key(&[]);
        assert_ne!(k, [0u8; 32]);
    }

    #[test]
    fn derive_relationship_key_large_input() {
        let big = vec![0xCC; 1024];
        let k = derive_relationship_key(&big);
        assert_ne!(k, [0u8; 32]);
    }

    // ── compute_protocol_transition_commitment ──

    #[test]
    fn protocol_commitment_uses_different_domain_from_sigma() {
        let data = b"same-payload";
        let sigma = derive_stitched_receipt_sigma(&[data.as_slice()]);
        let proto = compute_protocol_transition_commitment(data);
        assert_ne!(sigma, proto);
    }

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
}
