// SPDX-License-Identifier: MIT OR Apache-2.0
//! Offline-bearer secure-element attestation (anti-clone island binding).
//!
//! Implements the verifier side of the attested-device-identity anti-clone
//! mechanism (`.github/instructions/dsm_anticlone.instructions.md`). An offline
//! bearer transition is bound to a hardware secure element ("island") the owner
//! cannot rewrite: the island signs the transition's canonical intent challenge,
//! and the verifier checks that signature against a pinned device identity and a
//! pinned vendor production root. A perfect bit copy on different silicon holds the
//! seed and keys but not the island's non-extractable key, so it cannot produce the
//! signature and cannot continue an offline-bearer lineage.
//!
//! The island uses classical signatures (the device's own keys); see
//! [`crate::crypto::classical_verify`] for the scoped classical exception. DSM's own
//! protocol crypto remains post-quantum (BLAKE3 / SPHINCS+ / ML-KEM).
//!
//! [`verify_island_attestation`] is the Rust port of the vendor's
//! `verify_authentication_response`, restricted to the Trezor Safe 7 production
//! roots so a development device is rejected by construction.

use crate::crypto::blake3::dsm_domain_hasher;
use crate::crypto::classical_verify::{
    ed25519_pubkey_from_spki, verify_ecdsa_p256_sha256, verify_ecdsa_p256_sha256_sec1,
    verify_ed25519,
};
use crate::types::error::DsmError;
use sha2::{Digest, Sha256};
use x509_parser::certificate::X509Certificate;
use x509_parser::oid_registry::{
    OID_KEY_TYPE_EC_PUBLIC_KEY, OID_SIG_ECDSA_WITH_SHA256, OID_SIG_ED25519,
};
use x509_parser::prelude::FromDer;

/// The AuthenticateDevice framing header used by the device host protocol. The island
/// signs `len(header) || header || len(challenge) || challenge`.
pub const AUTHENTICATE_DEVICE_HEADER: &[u8] = b"AuthenticateDevice:";

/// Pinned Trezor Safe 7 (T3W1) production root public keys (from the vendor verifier's
/// ROOT_PUBLIC_KEYS). P-256 keys are SEC1 uncompressed points (65 bytes); Ed25519 keys
/// are raw (32 bytes). Only production roots are pinned, so a development or staging
/// device is rejected by construction.
const SAFE7_P256_ROOTS: [&[u8]; 2] = [
    include_bytes!("roots/safe7_p256_prod.bin"),
    include_bytes!("roots/safe7_p256_prod_backup.bin"),
];
const SAFE7_ED25519_ROOTS: [&[u8]; 2] = [
    include_bytes!("roots/safe7_ed25519_prod.bin"),
    include_bytes!("roots/safe7_ed25519_prod_backup.bin"),
];

/// Build the framed message the island signs for a given challenge. `challenge` is the
/// DSM canonical intent hash; the island wraps it with the fixed AuthenticateDevice
/// framing. Strict-fail if either part cannot be single-byte length-prefixed.
pub fn frame_authenticate_device(challenge: &[u8]) -> Result<Vec<u8>, DsmError> {
    if AUTHENTICATE_DEVICE_HEADER.len() > u8::MAX as usize || challenge.len() > u8::MAX as usize {
        return Err(DsmError::verification(
            "attestation: challenge or header too long to length-prefix",
        ));
    }
    let mut framed = Vec::with_capacity(2 + AUTHENTICATE_DEVICE_HEADER.len() + challenge.len());
    framed.push(AUTHENTICATE_DEVICE_HEADER.len() as u8);
    framed.extend_from_slice(AUTHENTICATE_DEVICE_HEADER);
    framed.push(challenge.len() as u8);
    framed.extend_from_slice(challenge);
    Ok(framed)
}

/// The stable per-device island identity: SHA-256 of the leaf SubjectPublicKeyInfo
/// DER. This matches the external vendor verifier and is the value DSM pins and folds
/// into the offline-bearer chain tip. (SHA-256 here is for external identity
/// compatibility; DSM's own canonical hashing uses domain-separated BLAKE3.)
pub fn id_island_from_spki(spki_der: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(spki_der);
    let digest = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&digest);
    id
}

/// Domain tag for the offline-bearer island attestation intent challenge.
pub const ISLAND_ATTESTATION_DOMAIN: &str = "DSM/offline-bearer/island-attestation/v1";

/// Domain tag for the on-device UI transcript hash (the consent-oracle binding).
pub const UI_TRANSCRIPT_DOMAIN: &str = "DSM/ui/v1";

/// Build the on-device UI transcript hash: a commitment to exactly what the Safe 7 screen
/// rendered and the human confirmed before the island signed. This is the consent-oracle
/// layer — a different security job from the anti-clone island authority. The element signs a
/// challenge that folds this transcript ([`dsm_island_challenge`]), so a hostile host cannot
/// get the device to sign a transition different from the one the human approved on the device
/// screen ("no matching UI transcript, verifier rejects").
///
/// `firmware_id` is the DSM custom-firmware identity: Track B intentionally discards the Trezor
/// factory attestation (bootloader unlock destroys the factory key), and the firmware identity
/// replaces it. `screen_template_id` pins the exact screen layout version that rendered the
/// fields. Variable-length fields are length-prefixed to forbid concatenation ambiguity. The
/// verifier recomputes this from the canonical transition fields and rejects on mismatch.
#[allow(clippy::too_many_arguments)]
pub fn dsm_ui_transcript(
    amount: u64,
    asset: &[u8],
    counterparty_id: &[u8; 32],
    h_n: &[u8; 32],
    payload_hash: &[u8; 32],
    policy_id: &[u8; 32],
    firmware_id: &[u8; 32],
    screen_template_id: u32,
) -> [u8; 32] {
    let mut hasher = dsm_domain_hasher(UI_TRANSCRIPT_DOMAIN);
    hasher.update(&amount.to_le_bytes());
    hasher.update(&(asset.len() as u32).to_le_bytes());
    hasher.update(asset);
    hasher.update(counterparty_id);
    hasher.update(h_n);
    hasher.update(payload_hash);
    hasher.update(policy_id);
    hasher.update(firmware_id);
    hasher.update(&screen_template_id.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Build the canonical intent challenge the island signs for an offline-bearer transition.
///
/// Binding the full intent (not just `h_n`) is what prevents a hostile host reusing one
/// island approval across a different payload. The result is the 32-byte value handed to the
/// device's AuthenticateDevice operation as the challenge (the device then wraps it with
/// [`frame_authenticate_device`]). `expiry_tick` is a DETERMINISTIC tick / state-index bound,
/// never wall-clock: DSM is clockless and this value folds into a signed commitment.
///
/// `ui_transcript` binds the on-device consent ceremony ([`dsm_ui_transcript`]): the element
/// signs only what the human approved on the Safe 7 screen, not merely what the host
/// requested. It is APPENDED to the existing intent binding (rather than replacing it), so the
/// consent-oracle layer is gained without losing the relay/replay protection that `nonce` and
/// `expiry_tick` provide.
#[allow(clippy::too_many_arguments)]
pub fn dsm_island_challenge(
    h_n: &[u8; 32],
    payload_hash: &[u8; 32],
    relationship_id: &[u8; 32],
    device_id: &[u8; 32],
    value_capability: u8,
    offline_bearer_mode: u8,
    nonce: &[u8],
    expiry_tick: u64,
    ui_transcript: &[u8; 32],
    receipt_commit: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = dsm_domain_hasher(ISLAND_ATTESTATION_DOMAIN);
    hasher.update(h_n);
    hasher.update(payload_hash);
    hasher.update(relationship_id);
    hasher.update(device_id);
    hasher.update(&[value_capability, offline_bearer_mode]);
    hasher.update(&(nonce.len() as u32).to_le_bytes());
    hasher.update(nonce);
    hasher.update(&expiry_tick.to_le_bytes());
    hasher.update(ui_transcript);
    hasher.update(receipt_commit);
    *hasher.finalize().as_bytes()
}

/// Domain tag for the offline-bearer anchor-proof digest folded into the chain tip.
pub const ANCHOR_PROOF_DOMAIN: &str = "DSM/offline-bearer/anchor-proof/v1";

/// Canonical signature bundle for an attested transition: `count || (len-prefixed signature)*`,
/// signatures sorted so the bundle is independent of the order the caller supplies them in. For a
/// single-island anchor this is the one signature; dual-island carries both. Folded as a whole into
/// [`compute_anchor_proof_hash`], and carried on the receipt so the digest is reconstructable.
pub fn canonical_signature_bundle(signatures: &[Vec<u8>]) -> Vec<u8> {
    let mut sigs: Vec<&[u8]> = signatures.iter().map(|s| s.as_slice()).collect();
    sigs.sort_unstable();
    let mut out = Vec::new();
    out.extend_from_slice(&(sigs.len() as u32).to_le_bytes());
    for s in sigs {
        out.extend_from_slice(&(s.len() as u32).to_le_bytes());
        out.extend_from_slice(s);
    }
    out
}

/// Canonical anchor-proof digest folded into the attested successor tip:
/// `BLAKE3("DSM/offline-bearer/anchor-proof/v1" || policy_id || id_anchor_set || ui_transcript_hash
/// || canonical_signature_bundle)`.
///
/// Only this 32-byte digest is folded into the tip — never a brittle `id_anchor || s_n || policy_id`
/// concatenation — giving stable tip bytes and room for dual-island sets, UI transcripts, policy
/// versions, and future anchor formats without changing the tip formula again. Crucially ALL four
/// inputs are carried on the receipt's `IslandAttestation` (`policy_id`, `id_anchor_set`,
/// `ui_transcript_hash`, and the signature(s) → `canonical_signature_bundle`), so a re-verifier can
/// reconstruct this digest from the receipt and match it to the folded tip.
///
/// `id_anchor_set` is the canonical set-id digest from [`compute_anchor_set_id`], NOT the raw ids.
pub fn compute_anchor_proof_hash(
    policy_id: &[u8; 32],
    id_anchor_set: &[u8; 32],
    ui_transcript_hash: &[u8; 32],
    canonical_signature_bundle: &[u8],
) -> [u8; 32] {
    let mut hasher = dsm_domain_hasher(ANCHOR_PROOF_DOMAIN);
    hasher.update(policy_id);
    hasher.update(id_anchor_set);
    hasher.update(ui_transcript_hash);
    hasher.update(canonical_signature_bundle);
    *hasher.finalize().as_bytes()
}

/// Domain tag for the anchor's own monotonic root frontier (separate from the Per-Device SMT root,
/// which folds `anchor_proof_hash` and would be circular to sign over).
pub const ANCHOR_FRONTIER_DOMAIN: &str = "DSM/anchor-frontier/v1";

/// Deterministically advance the anchor's monotonic frontier:
/// `successor_root = BLAKE3("DSM/anchor-frontier/v1" || parent_root || operation_hash || state_number)`.
/// No signature dependency, so the receipt can both bind and advance it without circularity. The
/// device requires `parent_root == stored_root`, recomputes this, and atomically advances.
pub fn dsm_anchor_frontier_successor(
    parent_root: &[u8; 32],
    operation_hash: &[u8; 32],
    state_number: u64,
) -> [u8; 32] {
    let mut hasher = dsm_domain_hasher(ANCHOR_FRONTIER_DOMAIN);
    hasher.update(parent_root);
    hasher.update(operation_hash);
    hasher.update(&state_number.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Domain-separated hash of the anchor's SubjectPublicKeyInfo, carried on the receipt so a verifier
/// pins exactly which key signed (length-prefixed to forbid concatenation ambiguity).
pub const ANCHOR_PUBKEY_HASH_DOMAIN: &str = "DSM/anchor-pubkey/v1";

/// `BLAKE3("DSM/anchor-pubkey/v1" || len(spki) || spki)`.
pub fn dsm_anchor_pubkey_hash(leaf_spki: &[u8]) -> [u8; 32] {
    let mut hasher = dsm_domain_hasher(ANCHOR_PUBKEY_HASH_DOMAIN);
    hasher.update(&(leaf_spki.len() as u32).to_le_bytes());
    hasher.update(leaf_spki);
    *hasher.finalize().as_bytes()
}

/// Domain tag for the policy-content hash the receipt binds (distinct from the policy id).
pub const POLICY_HASH_DOMAIN: &str = "DSM/policy-hash/v1";

/// `BLAKE3("DSM/policy-hash/v1" || policy_id || anchor_set_id)` — a hash of the pinning policy's
/// canonical contents the verifier checks against the enrolled value.
pub fn dsm_policy_hash(policy_id: &[u8; 32], anchor_set_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = dsm_domain_hasher(POLICY_HASH_DOMAIN);
    hasher.update(policy_id);
    hasher.update(anchor_set_id);
    *hasher.finalize().as_bytes()
}

/// Canonical policy id for the default offline-bearer authority policy. A device that holds an anchor
/// stamps this id on its OFFLINE_BEARER_REQUIRED transfers; the sender and receiver agree on it by
/// construction (it travels in the operation and is folded, via `dsm_policy_hash`, into the signed
/// receipt). A richer policy registry can replace this single default later.
pub fn dsm_offline_bearer_policy_id() -> [u8; 32] {
    *dsm_domain_hasher("DSM/offline-bearer/policy-id/v1")
        .finalize()
        .as_bytes()
}

/// Domain tag for the stateful-receipt commitment appended to the island intent challenge.
pub const OFFLINE_BEARER_RECEIPT_DOMAIN: &str = "DSM/offline-bearer/receipt/v1";

/// Stateful-receipt commitment folded into the island challenge:
/// `BLAKE3("DSM/offline-bearer/receipt/v1" || anchor_pubkey_hash || firmware_hash || policy_hash ||
/// parent_root || successor_root || state_number)`. Binds the fields not already in
/// [`dsm_island_challenge`] (operation_hash==payload_hash and device_id are already folded there;
/// `h_n` there is the relationship chain tip, SEPARATE from the anchor `parent_root` bound here — the
/// device's single monotonic frontier root). Host and device compute this identically; the verifier
/// reconstructs it from the receipt.
pub fn dsm_offline_bearer_receipt_commit(
    anchor_pubkey_hash: &[u8; 32],
    firmware_hash: &[u8; 32],
    policy_hash: &[u8; 32],
    parent_root: &[u8; 32],
    successor_root: &[u8; 32],
    state_number: u64,
) -> [u8; 32] {
    let mut hasher = dsm_domain_hasher(OFFLINE_BEARER_RECEIPT_DOMAIN);
    hasher.update(anchor_pubkey_hash);
    hasher.update(firmware_hash);
    hasher.update(policy_hash);
    hasher.update(parent_root);
    hasher.update(successor_root);
    hasher.update(&state_number.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Canonical offline-bearer mode tag bound into the island intent challenge. Explicit enum — no
/// magic naked constant at call sites.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OfflineBearerMode {
    /// Offline-bearer authority is required for this transition.
    Required,
}

impl OfflineBearerMode {
    /// Canonical 1-byte tag for the `offline_bearer_mode` intent field.
    pub fn tag(self) -> u8 {
        match self {
            OfflineBearerMode::Required => 1,
        }
    }
}

/// Domain for the offline-bearer transition payload hash bound into the intent challenge.
pub const OFFLINE_BEARER_PAYLOAD_DOMAIN: &str = "DSM/offline-bearer/payload/v1";

/// Hash of the transition's operation payload, bound into the island intent challenge as
/// `payload_hash`. Deterministic over the canonical operation bytes.
pub fn dsm_offline_bearer_payload_hash(op_bytes: &[u8]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(OFFLINE_BEARER_PAYLOAD_DOMAIN);
    h.update(op_bytes);
    *h.finalize().as_bytes()
}

/// Domain for the canonical anchor-set identifier.
pub const ANCHOR_SET_DOMAIN: &str = "DSM/anchor-set/v1";

/// Canonical encoding of an anchor set: `count || sorted ids`. Order-independent (set semantics),
/// length-prefixed.
pub fn canonical_anchor_set(anchor_ids: &[[u8; 32]]) -> Vec<u8> {
    let mut ids: Vec<&[u8; 32]> = anchor_ids.iter().collect();
    ids.sort();
    let mut out = Vec::with_capacity(4 + ids.len() * 32);
    out.extend_from_slice(&(ids.len() as u32).to_le_bytes());
    for id in ids {
        out.extend_from_slice(id);
    }
    out
}

/// The canonical anchor-set identifier: `H("DSM/anchor-set/v1\0" || CanonicalAnchorSet(ids))`.
///
/// The gate recomputes this from the transport's ACTUAL anchor identities and requires it to equal
/// the operation's declared `authority_policy.anchor_set_id` — so a policy cannot name one anchor
/// set while the device signs with a different concrete identity set.
pub fn compute_anchor_set_id(anchor_ids: &[[u8; 32]]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(ANCHOR_SET_DOMAIN);
    h.update(&canonical_anchor_set(anchor_ids));
    *h.finalize().as_bytes()
}

fn parse_cert(der: &[u8]) -> Result<X509Certificate<'_>, DsmError> {
    X509Certificate::from_der(der)
        .map(|(_, cert)| cert)
        .map_err(|_| DsmError::verification("attestation: malformed certificate"))
}

fn ed25519_sig_array(sig: &[u8]) -> Result<[u8; 64], DsmError> {
    sig.try_into()
        .map_err(|_| DsmError::verification("attestation: Ed25519 signature is not 64 bytes"))
}

/// Verify a signature over `message` using a SubjectPublicKeyInfo and a signature
/// algorithm OID to select the scheme (Ed25519 raw, or ECDSA P-256 / SHA-256 DER).
fn verify_by_spki(
    spki_der: &[u8],
    sig_alg: &x509_parser::der_parser::Oid,
    message: &[u8],
    signature: &[u8],
) -> Result<(), DsmError> {
    if *sig_alg == OID_SIG_ED25519 {
        let pubkey = ed25519_pubkey_from_spki(spki_der)?;
        verify_ed25519(&pubkey, message, &ed25519_sig_array(signature)?)
    } else if *sig_alg == OID_SIG_ECDSA_WITH_SHA256 {
        verify_ecdsa_p256_sha256(spki_der, message, signature)
    } else {
        Err(DsmError::verification(
            "attestation: unsupported certificate signature algorithm",
        ))
    }
}

/// Check that `issuer` is a valid CA permitted to sign at the current path length:
/// keyUsage.keyCertSign set, basicConstraints.cA set, and pathLenConstraint present
/// and not exceeded.
fn check_ca(issuer: &X509Certificate, path_len: usize) -> Result<(), DsmError> {
    let key_cert_sign = issuer
        .key_usage()
        .ok()
        .flatten()
        .map(|ku| ku.value.key_cert_sign())
        .unwrap_or(false);
    if !key_cert_sign {
        return Err(DsmError::verification(
            "attestation: issuer certificate lacks keyCertSign",
        ));
    }
    let bc =
        issuer.basic_constraints().ok().flatten().ok_or_else(|| {
            DsmError::verification("attestation: issuer missing BasicConstraints")
        })?;
    if !bc.value.ca {
        return Err(DsmError::verification(
            "attestation: issuer is not a CA (cA flag unset)",
        ));
    }
    let plc = bc
        .value
        .path_len_constraint
        .ok_or_else(|| DsmError::verification("attestation: issuer missing pathLenConstraint"))?;
    if (plc as usize) < path_len {
        return Err(DsmError::verification(
            "attestation: issuer pathLenConstraint exceeded",
        ));
    }
    Ok(())
}

/// Verify the top certificate is signed by a pinned Safe 7 production root.
fn verify_signed_by_pinned_root(top: &X509Certificate) -> Result<(), DsmError> {
    let tbs = top.tbs_certificate.as_ref();
    let sig = top.signature_value.as_ref();
    let alg = &top.signature_algorithm.algorithm;
    if *alg == OID_SIG_ED25519 {
        let sig_arr = ed25519_sig_array(sig)?;
        for root in SAFE7_ED25519_ROOTS {
            if let Ok(root_arr) = <[u8; 32]>::try_from(root) {
                if verify_ed25519(&root_arr, tbs, &sig_arr).is_ok() {
                    return Ok(());
                }
            }
        }
        Err(DsmError::verification(
            "attestation: top certificate not signed by a pinned Safe 7 Ed25519 production root",
        ))
    } else if *alg == OID_SIG_ECDSA_WITH_SHA256 {
        for root in SAFE7_P256_ROOTS {
            if verify_ecdsa_p256_sha256_sec1(root, tbs, sig).is_ok() {
                return Ok(());
            }
        }
        Err(DsmError::verification(
            "attestation: top certificate not signed by a pinned Safe 7 P-256 production root",
        ))
    } else {
        Err(DsmError::verification(
            "attestation: unsupported top certificate signature algorithm",
        ))
    }
}

/// Verify an offline-bearer island attestation. The leaf signs the framed challenge, the
/// certificate chain links leaf to issuer(s), and the top certificate is signed by a
/// pinned Trezor Safe 7 production root. Returns the pinned device identity
/// (`id_island`) on success. Development devices are rejected because only production
/// roots are pinned.
pub fn verify_island_attestation(
    challenge: &[u8],
    signature: &[u8],
    cert_chain: &[&[u8]],
) -> Result<[u8; 32], DsmError> {
    if cert_chain.is_empty() {
        return Err(DsmError::verification(
            "attestation: empty certificate chain",
        ));
    }
    let framed = frame_authenticate_device(challenge)?;

    let leaf = parse_cert(cert_chain[0])?;
    let leaf_spki = leaf.public_key().raw;
    let leaf_key_alg = &leaf.public_key().algorithm.algorithm;

    // 1) Challenge binding: the leaf's own key signs the framed challenge.
    if *leaf_key_alg == OID_SIG_ED25519 {
        let pubkey = ed25519_pubkey_from_spki(leaf_spki)?;
        verify_ed25519(&pubkey, &framed, &ed25519_sig_array(signature)?)?;
    } else if *leaf_key_alg == OID_KEY_TYPE_EC_PUBLIC_KEY {
        verify_ecdsa_p256_sha256(leaf_spki, &framed, signature)?;
    } else {
        return Err(DsmError::verification(
            "attestation: unsupported leaf key type",
        ));
    }

    let id_island = id_island_from_spki(leaf_spki);

    // 2) Walk the chain: each issuer must name the child, be a valid CA, and sign it.
    let mut child = leaf;
    for (path_len, issuer_der) in cert_chain[1..].iter().enumerate() {
        let issuer = parse_cert(issuer_der)?;
        if issuer.subject() != child.issuer() {
            return Err(DsmError::verification(
                "attestation: certificate issuer name mismatch",
            ));
        }
        check_ca(&issuer, path_len)?;
        verify_by_spki(
            issuer.public_key().raw,
            &child.signature_algorithm.algorithm,
            child.tbs_certificate.as_ref(),
            child.signature_value.as_ref(),
        )?;
        child = issuer;
    }

    // 3) The top certificate must be signed by a pinned Safe 7 production root.
    verify_signed_by_pinned_root(&child)?;

    Ok(id_island)
}

/// The full offline-bearer intent an island signs for one transition. These are exactly
/// the fields folded into [`dsm_island_challenge`]; bundling them keeps the per-transition
/// gate call honest (a hostile host cannot swap one approved field for another after the
/// island has signed).
#[derive(Clone, Copy, Debug)]
pub struct IslandIntent<'a> {
    /// Prior chain tip `h_n` the transition extends.
    pub h_n: &'a [u8; 32],
    /// Hash of the transition payload.
    pub payload_hash: &'a [u8; 32],
    /// Relationship identifier.
    pub relationship_id: &'a [u8; 32],
    /// Acting device identifier.
    pub device_id: &'a [u8; 32],
    /// Value-capability commit tag at this transition.
    pub value_capability: u8,
    /// Offline-bearer mode tag.
    pub offline_bearer_mode: u8,
    /// Per-transition nonce.
    pub nonce: &'a [u8],
    /// Deterministic expiry tick (clockless), never wall-clock.
    pub expiry_tick: u64,
    /// On-device UI transcript hash ([`dsm_ui_transcript`]): the consent-oracle binding to
    /// exactly what the Safe 7 screen displayed and the human confirmed.
    pub ui_transcript: &'a [u8; 32],
    /// Stateful-receipt commitment ([`dsm_offline_bearer_receipt_commit`]): binds the anchor pubkey
    /// hash, measured firmware hash, policy hash, frontier successor root, and state number into the
    /// signed challenge so the island authority cannot be replayed across firmware, policy, or
    /// frontier position.
    pub receipt_commit: &'a [u8; 32],
}

impl IslandIntent<'_> {
    /// The 32-byte canonical challenge for this intent (see [`dsm_island_challenge`]).
    pub fn challenge(&self) -> [u8; 32] {
        dsm_island_challenge(
            self.h_n,
            self.payload_hash,
            self.relationship_id,
            self.device_id,
            self.value_capability,
            self.offline_bearer_mode,
            self.nonce,
            self.expiry_tick,
            self.ui_transcript,
            self.receipt_commit,
        )
    }
}

/// Verify an island's Ed25519 signature over one transition intent, given the island's
/// leaf SubjectPublicKeyInfo. Recomputes the canonical challenge from the bound intent,
/// frames it exactly as the device firmware does, and checks the signature. On success
/// returns the pinned island identity `id_island = SHA-256(leaf SPKI)` so the caller can
/// confirm it matches the admitted island. The binding element is TROPIC01 (Ed25519,
/// spec §10); the heavier certificate-chain-to-root proof is the admission-time
/// [`verify_island_attestation`], not repeated per transition.
pub fn verify_island_intent_signature(
    leaf_spki_der: &[u8],
    intent: &IslandIntent,
    signature: &[u8],
) -> Result<[u8; 32], DsmError> {
    let challenge = intent.challenge();
    let framed = frame_authenticate_device(&challenge)?;
    let pubkey = ed25519_pubkey_from_spki(leaf_spki_der)?;
    verify_ed25519(&pubkey, &framed, &ed25519_sig_array(signature)?)?;
    Ok(id_island_from_spki(leaf_spki_der))
}

/// Which settlement path an offline-bearer-eligible transition takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettlementPath {
    /// The optional offline-bearer authority path: a genuine admitted island signed this
    /// exact intent. Usable offline with no online check.
    OfflineBearer,
    /// The existing online-checked settlement path. Used whenever offline-bearer authority
    /// is not requested, not admitted, or its proof is absent or invalid. Fail-closed but
    /// never a hard reject: a failed attestation forecloses the offline path only — the
    /// transaction still settles online.
    OnlineFallback,
}

/// Decide the settlement path for a transition. Offline-bearer authority is granted ONLY
/// when it is requested, the device's island is PROVEN `Attested`, and the island's
/// signature over this exact intent verifies. Every other case falls back to the
/// online-checked path — deny-unless-proven, never a hard reject of the transaction.
pub fn decide_settlement_path(
    requesting_offline_bearer: bool,
    capability: crate::types::device_state::OfflineBearerAttestation,
    island_signature_ok: bool,
) -> SettlementPath {
    if requesting_offline_bearer && capability.permits_offline_bearer() && island_signature_ok {
        SettlementPath::OfflineBearer
    } else {
        SettlementPath::OnlineFallback
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real captured AuthenticateDevice vectors from a genuine Trezor Safe 7 (T3W1),
    // independently verified AUTHENTIC by trezorlib's own verifier against the Trezor
    // production root (devel = false, both legs, challenge bound).
    const CHALLENGE: &[u8] = include_bytes!("test_vectors/challenge.bin");
    const TROPIC_SIG: &[u8] = include_bytes!("test_vectors/tropic_sig.bin");
    const TROPIC_SPKI: &[u8] = include_bytes!("test_vectors/tropic_leaf_spki.der");
    const TROPIC_ID: &[u8] = include_bytes!("test_vectors/tropic_id.bin");
    const TROPIC_CERT0: &[u8] = include_bytes!("test_vectors/tropic_cert0.der");
    const TROPIC_CERT1: &[u8] = include_bytes!("test_vectors/tropic_cert1.der");
    const OPTIGA_SIG: &[u8] = include_bytes!("test_vectors/optiga_sig.bin");
    const OPTIGA_SPKI: &[u8] = include_bytes!("test_vectors/optiga_leaf_spki.der");
    const OPTIGA_ID: &[u8] = include_bytes!("test_vectors/optiga_id.bin");
    const OPTIGA_CERT0: &[u8] = include_bytes!("test_vectors/optiga_cert0.der");
    const OPTIGA_CERT1: &[u8] = include_bytes!("test_vectors/optiga_cert1.der");

    #[test]
    fn tropic_ed25519_challenge_binds_over_frame() {
        let framed = frame_authenticate_device(CHALLENGE).expect("frame");
        let pubkey = ed25519_pubkey_from_spki(TROPIC_SPKI).expect("ed25519 spki");
        let mut sig = [0u8; 64];
        sig.copy_from_slice(TROPIC_SIG);
        verify_ed25519(&pubkey, &framed, &sig).expect("TROPIC01 challenge signature must verify");
        assert_eq!(&id_island_from_spki(TROPIC_SPKI)[..], TROPIC_ID);
    }

    #[test]
    fn optiga_ecdsa_challenge_binds_over_frame() {
        let framed = frame_authenticate_device(CHALLENGE).expect("frame");
        verify_ecdsa_p256_sha256(OPTIGA_SPKI, &framed, OPTIGA_SIG)
            .expect("OPTIGA challenge signature must verify");
        assert_eq!(&id_island_from_spki(OPTIGA_SPKI)[..], OPTIGA_ID);
    }

    #[test]
    fn wrong_payload_challenge_is_rejected() {
        let mut tampered = CHALLENGE.to_vec();
        tampered[0] ^= 0xff;
        let framed = frame_authenticate_device(&tampered).expect("frame");
        let pubkey = ed25519_pubkey_from_spki(TROPIC_SPKI).expect("ed25519 spki");
        let mut sig = [0u8; 64];
        sig.copy_from_slice(TROPIC_SIG);
        assert!(verify_ed25519(&pubkey, &framed, &sig).is_err());
    }

    #[test]
    fn unframed_challenge_is_rejected() {
        let pubkey = ed25519_pubkey_from_spki(TROPIC_SPKI).expect("ed25519 spki");
        let mut sig = [0u8; 64];
        sig.copy_from_slice(TROPIC_SIG);
        assert!(verify_ed25519(&pubkey, CHALLENGE, &sig).is_err());
    }

    #[test]
    fn tropic_full_chain_verifies_to_pinned_root() {
        let id = verify_island_attestation(CHALLENGE, TROPIC_SIG, &[TROPIC_CERT0, TROPIC_CERT1])
            .expect("TROPIC01 chain must verify to pinned Safe 7 root");
        assert_eq!(&id[..], TROPIC_ID);
    }

    #[test]
    fn optiga_full_chain_verifies_to_pinned_root() {
        let id = verify_island_attestation(CHALLENGE, OPTIGA_SIG, &[OPTIGA_CERT0, OPTIGA_CERT1])
            .expect("OPTIGA chain must verify to pinned Safe 7 root");
        assert_eq!(&id[..], OPTIGA_ID);
    }

    #[test]
    fn tampered_challenge_fails_full_chain() {
        let mut bad = CHALLENGE.to_vec();
        bad[0] ^= 0xff;
        assert!(
            verify_island_attestation(&bad, TROPIC_SIG, &[TROPIC_CERT0, TROPIC_CERT1]).is_err()
        );
    }

    #[test]
    fn wrong_leaf_signature_fails_full_chain() {
        // OPTIGA's signature with TROPIC01's chain: leaf challenge check must fail.
        assert!(
            verify_island_attestation(CHALLENGE, OPTIGA_SIG, &[TROPIC_CERT0, TROPIC_CERT1])
                .is_err()
        );
    }

    #[test]
    fn island_challenge_is_deterministic_and_binds_every_intent_field() {
        let h_n = [1u8; 32];
        let payload = [2u8; 32];
        let rel = [3u8; 32];
        let dev = [4u8; 32];
        let ui = [5u8; 32];
        let rc = [0xABu8; 32];
        let base = dsm_island_challenge(&h_n, &payload, &rel, &dev, 1, 1, b"nonce", 7, &ui, &rc);
        // Deterministic: identical inputs -> identical challenge.
        assert_eq!(
            base,
            dsm_island_challenge(&h_n, &payload, &rel, &dev, 1, 1, b"nonce", 7, &ui, &rc)
        );
        // Every intent field is bound: flipping any one changes the challenge.
        assert_ne!(
            base,
            dsm_island_challenge(&[9u8; 32], &payload, &rel, &dev, 1, 1, b"nonce", 7, &ui, &rc)
        );
        assert_ne!(
            base,
            dsm_island_challenge(&h_n, &[9u8; 32], &rel, &dev, 1, 1, b"nonce", 7, &ui, &rc)
        );
        assert_ne!(
            base,
            dsm_island_challenge(&h_n, &payload, &[9u8; 32], &dev, 1, 1, b"nonce", 7, &ui, &rc)
        );
        assert_ne!(
            base,
            dsm_island_challenge(&h_n, &payload, &rel, &[9u8; 32], 1, 1, b"nonce", 7, &ui, &rc)
        );
        assert_ne!(
            base,
            dsm_island_challenge(&h_n, &payload, &rel, &dev, 2, 1, b"nonce", 7, &ui, &rc)
        );
        assert_ne!(
            base,
            dsm_island_challenge(&h_n, &payload, &rel, &dev, 1, 2, b"nonce", 7, &ui, &rc)
        );
        assert_ne!(
            base,
            dsm_island_challenge(&h_n, &payload, &rel, &dev, 1, 1, b"other", 7, &ui, &rc)
        );
        assert_ne!(
            base,
            dsm_island_challenge(&h_n, &payload, &rel, &dev, 1, 1, b"nonce", 8, &ui, &rc)
        );
        // The UI transcript is bound: a different on-device consent transcript (the human saw a
        // different action) changes the challenge, so the same signature cannot carry over.
        assert_ne!(
            base,
            dsm_island_challenge(&h_n, &payload, &rel, &dev, 1, 1, b"nonce", 7, &[6u8; 32], &rc)
        );
        // The stateful-receipt commitment is bound: a different receipt_commit changes the challenge.
        assert_ne!(
            base,
            dsm_island_challenge(
                &h_n,
                &payload,
                &rel,
                &dev,
                1,
                1,
                b"nonce",
                7,
                &ui,
                &[0xCDu8; 32]
            )
        );
    }

    #[test]
    fn ui_transcript_binds_every_displayed_field() {
        let cp = [1u8; 32];
        let h_n = [2u8; 32];
        let payload = [3u8; 32];
        let policy = [4u8; 32];
        let fw = [5u8; 32];
        let base = dsm_ui_transcript(10, b"ERA", &cp, &h_n, &payload, &policy, &fw, 1);
        // Deterministic.
        assert_eq!(
            base,
            dsm_ui_transcript(10, b"ERA", &cp, &h_n, &payload, &policy, &fw, 1)
        );
        // Every displayed field is bound: flipping any one changes the transcript.
        assert_ne!(
            base,
            dsm_ui_transcript(11, b"ERA", &cp, &h_n, &payload, &policy, &fw, 1)
        ); // amount
        assert_ne!(
            base,
            dsm_ui_transcript(10, b"DBTC", &cp, &h_n, &payload, &policy, &fw, 1)
        ); // asset
        assert_ne!(
            base,
            dsm_ui_transcript(10, b"ERA", &[9u8; 32], &h_n, &payload, &policy, &fw, 1)
        ); // counterparty
        assert_ne!(
            base,
            dsm_ui_transcript(10, b"ERA", &cp, &[9u8; 32], &payload, &policy, &fw, 1)
        ); // h_n
        assert_ne!(
            base,
            dsm_ui_transcript(10, b"ERA", &cp, &h_n, &[9u8; 32], &policy, &fw, 1)
        ); // payload
        assert_ne!(
            base,
            dsm_ui_transcript(10, b"ERA", &cp, &h_n, &payload, &[9u8; 32], &fw, 1)
        ); // policy
        assert_ne!(
            base,
            dsm_ui_transcript(10, b"ERA", &cp, &h_n, &payload, &policy, &[9u8; 32], 1)
        ); // firmware_id
        assert_ne!(
            base,
            dsm_ui_transcript(10, b"ERA", &cp, &h_n, &payload, &policy, &fw, 2)
        ); // screen_template
    }

    #[test]
    fn anchor_proof_hash_is_canonical_and_binds_each_component() {
        let policy = [1u8; 32];
        let ui = [2u8; 32];
        let id_a = [3u8; 32];
        let id_b = [4u8; 32];
        let sig_a = vec![10u8; 64];
        let sig_b = vec![11u8; 64];

        let set = compute_anchor_set_id(&[id_a, id_b]);
        let bundle = canonical_signature_bundle(&[sig_a.clone(), sig_b.clone()]);
        let base = compute_anchor_proof_hash(&policy, &set, &ui, &bundle);
        // Deterministic.
        assert_eq!(base, compute_anchor_proof_hash(&policy, &set, &ui, &bundle));
        // Set semantics: supplying the set / signatures in the other order yields the same set-id
        // digest and the same bundle, hence the same proof hash.
        let set2 = compute_anchor_set_id(&[id_b, id_a]);
        let bundle2 = canonical_signature_bundle(&[sig_b.clone(), sig_a.clone()]);
        assert_eq!(
            base,
            compute_anchor_proof_hash(&policy, &set2, &ui, &bundle2)
        );
        // Every component is bound.
        assert_ne!(
            base,
            compute_anchor_proof_hash(&[9u8; 32], &set, &ui, &bundle)
        ); // policy_id
        assert_ne!(
            base,
            compute_anchor_proof_hash(&policy, &[9u8; 32], &ui, &bundle)
        ); // anchor-set id
        assert_ne!(
            base,
            compute_anchor_proof_hash(&policy, &set, &[9u8; 32], &bundle)
        ); // ui transcript
        let bundle_diff = canonical_signature_bundle(&[sig_a.clone(), vec![12u8; 64]]);
        assert_ne!(
            base,
            compute_anchor_proof_hash(&policy, &set, &ui, &bundle_diff)
        ); // a signature
           // Single-island vs dual-island differ (set-id digest + bundle both change).
        let set_one = compute_anchor_set_id(&[id_a]);
        let bundle_one = canonical_signature_bundle(std::slice::from_ref(&sig_a));
        assert_ne!(
            base,
            compute_anchor_proof_hash(&policy, &set_one, &ui, &bundle_one)
        );
    }

    #[test]
    fn anchor_set_id_is_order_independent_and_binds_membership() {
        let a = [3u8; 32];
        let b = [4u8; 32];
        let base = compute_anchor_set_id(&[a, b]);
        assert_eq!(base, compute_anchor_set_id(&[a, b]));
        // Set semantics: order-independent.
        assert_eq!(base, compute_anchor_set_id(&[b, a]));
        // Membership / cardinality bound: a different member or a smaller set => different id.
        assert_ne!(base, compute_anchor_set_id(&[a, [9u8; 32]]));
        assert_ne!(base, compute_anchor_set_id(&[a]));
    }

    #[test]
    fn offline_bearer_payload_hash_and_mode_tag() {
        let p1 = dsm_offline_bearer_payload_hash(b"op-1");
        assert_eq!(p1, dsm_offline_bearer_payload_hash(b"op-1"));
        assert_ne!(p1, dsm_offline_bearer_payload_hash(b"op-2"));
        assert_eq!(OfflineBearerMode::Required.tag(), 1);
    }

    /// Minimal Ed25519 SubjectPublicKeyInfo DER wrapping a raw 32-byte public key.
    fn ed25519_spki(raw_pubkey: &[u8; 32]) -> Vec<u8> {
        let mut spki = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        spki.extend_from_slice(raw_pubkey);
        spki
    }

    #[test]
    fn island_intent_signature_round_trips_and_rejects_tampering() {
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let spki = ed25519_spki(sk.verifying_key().as_bytes());

        let h_n = [1u8; 32];
        let payload = [2u8; 32];
        let rel = [3u8; 32];
        let dev = [4u8; 32];
        let ui = [5u8; 32];
        let rc = [6u8; 32];
        let intent = IslandIntent {
            h_n: &h_n,
            payload_hash: &payload,
            relationship_id: &rel,
            device_id: &dev,
            value_capability: 1,
            offline_bearer_mode: 1,
            nonce: b"n0",
            expiry_tick: 9,
            ui_transcript: &ui,
            receipt_commit: &rc,
        };
        let framed = frame_authenticate_device(&intent.challenge()).expect("frame");
        let sig = sk.sign(&framed).to_bytes();

        // Honest path: the island signed THIS exact intent; id pins to the leaf SPKI.
        let id = verify_island_intent_signature(&spki, &intent, &sig).expect("intent sig verifies");
        assert_eq!(id, id_island_from_spki(&spki));

        // Tampered intent (different nonce) -> recomputed challenge differs -> fails.
        let tampered = IslandIntent {
            nonce: b"n1",
            ..intent
        };
        assert!(verify_island_intent_signature(&spki, &tampered, &sig).is_err());

        // Tampered UI transcript: the host displayed/relayed a different action than the one
        // the island signed over. The consent-oracle binding makes the recomputed challenge
        // differ, so the signature is rejected ("no matching UI transcript, verifier rejects").
        let other_ui = [6u8; 32];
        let tampered_ui = IslandIntent {
            ui_transcript: &other_ui,
            ..intent
        };
        assert!(verify_island_intent_signature(&spki, &tampered_ui, &sig).is_err());

        // Wrong island key -> fails (a clone with a different key cannot reuse the sig).
        let other = SigningKey::from_bytes(&[8u8; 32]);
        let other_spki = ed25519_spki(other.verifying_key().as_bytes());
        assert!(verify_island_intent_signature(&other_spki, &intent, &sig).is_err());
    }

    #[test]
    fn settlement_path_grants_offline_only_when_attested_and_signed() {
        use crate::types::device_state::OfflineBearerAttestation::*;
        // The sole grant case: requested + Attested + valid island signature.
        assert_eq!(
            decide_settlement_path(true, Attested, true),
            SettlementPath::OfflineBearer
        );
        // Every other case falls back to the online-checked path (never a hard reject).
        assert_eq!(
            decide_settlement_path(false, Attested, true),
            SettlementPath::OnlineFallback
        );
        assert_eq!(
            decide_settlement_path(true, NotAttested, true),
            SettlementPath::OnlineFallback
        );
        assert_eq!(
            decide_settlement_path(true, Unknown, true),
            SettlementPath::OnlineFallback
        );
        assert_eq!(
            decide_settlement_path(true, Attested, false),
            SettlementPath::OnlineFallback
        );
    }
}
