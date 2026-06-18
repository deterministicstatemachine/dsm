// SPDX-License-Identifier: MIT OR Apache-2.0
//! Host-side abstraction over the offline-bearer signing anchor (the DeviceAnchor).
//!
//! The anchor lives in a secure element behind a transport: BLE to a forked Trezor Safe 7
//! (Track B), UDP to the T3W1 emulator, or an in-process mock for tests. This module defines the
//! transport-agnostic trait the DSM gate calls, plus the host/verifier helper that recomputes the
//! on-device consent ceremony and checks the island's signature.
//!
//! # The two security jobs, kept separate
//!
//! - The **secure element** signs with a non-extractable key — "this device authority exists"
//!   (the anti-clone primitive; a copy on other silicon holds a different key).
//! - The **device screen** is a consent oracle — "the human approved this exact action". The
//!   firmware RENDERS the request fields, waits for hold-to-confirm, and computes the UI
//!   transcript + challenge ITSELF, so the host can relay bytes but never gets the element to sign
//!   a transition different from the one the human saw. See [`crate::attestation::dsm_ui_transcript`].
//!
//! # Track B identity is self-provisioned
//!
//! After bootloader unlock the Trezor factory attestation key is destroyed (intended), so the
//! anchor identity is the firmware's OWN non-extractable key — [`AnchorIdentityRecord::leaf_spki`]
//! is that self-provisioned key, never a vendor leaf cert. The verifier pins it directly via
//! [`crate::attestation::verify_island_intent_signature`] (raw Ed25519, no vendor-root check) and
//! never walks the Track A production-root chain.

use crate::attestation::{dsm_ui_transcript, verify_island_intent_signature, IslandIntent};
use crate::types::error::DsmError;
use async_trait::async_trait;

/// The published, pinnable identity of an anchor. Everything here is shareable; none of it lets a
/// holder sign. `firmware_id` + `screen_template_id` are the device constants the verifier must use
/// to recompute the UI transcript, pinned at admission alongside `leaf_spki`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorIdentityRecord {
    /// Anchor identifier, derived from the birth commitment `C` and the signing key.
    pub id_anchor: [u8; 32],
    /// Birth commitment `C` (hiding+binding over the in-element walk output).
    pub commitment_c: [u8; 32],
    /// SubjectPublicKeyInfo DER of the anchor's signing key (self-provisioned; Ed25519 in cut-1,
    /// SPHINCS+ after the PQ swap — the verifier branches on the scheme then).
    pub leaf_spki: Vec<u8>,
    /// DSM custom-firmware identity that replaces the discarded Trezor factory attestation. Folded
    /// into every UI transcript so a signature is bound to the firmware that displayed it.
    pub firmware_id: [u8; 32],
    /// Screen-layout template version that rendered the consent fields.
    pub screen_template_id: u32,
    /// Device-measured firmware hash bound at enrollment — the value the secmon gate enforces and
    /// the receipt commits to (distinct from the display-only `firmware_id`).
    pub firmware_hash: [u8; 32],
}

/// One offline-bearer transition to be displayed on the device and signed by the anchor.
///
/// These are the fields the firmware RENDERS on the Safe 7 screen and from which it computes the
/// UI transcript and challenge ITSELF — the host never hands the device a pre-baked challenge
/// (that would let a hostile host display one action and sign another).
#[derive(Clone, Copy, Debug)]
pub struct AnchorSignRequest<'a> {
    /// Prior chain tip `h_n` the transition extends.
    pub h_n: &'a [u8; 32],
    /// Hash of the transition payload.
    pub payload_hash: &'a [u8; 32],
    /// Relationship identifier.
    pub relationship_id: &'a [u8; 32],
    /// Acting device identifier.
    pub device_id: &'a [u8; 32],
    /// Value-capability commit tag.
    pub value_capability: u8,
    /// Offline-bearer mode tag.
    pub offline_bearer_mode: u8,
    /// Per-transition nonce.
    pub nonce: &'a [u8],
    /// Deterministic expiry tick (clockless), never wall-clock.
    pub expiry_tick: u64,
    /// Human-displayed amount, in base units.
    pub amount: u64,
    /// Human-displayed asset identifier.
    pub asset: &'a [u8],
    /// Human-displayed counterparty identifier.
    pub counterparty_id: &'a [u8; 32],
    /// Pinning-policy identifier (e.g. a "dual island required" policy).
    pub policy_id: &'a [u8; 32],
    /// Hash of the pinning policy's canonical contents (stateful-receipt binding).
    pub policy_hash: &'a [u8; 32],
    /// The device's CURRENT single anchor frontier root this advance consumes (== device
    /// `stored_root`; ONE per device keyed by anchor identity, NOT per relationship). Distinct from
    /// `h_n`, the relationship chain tip.
    pub parent_root: &'a [u8; 32],
    /// Anchor monotonic-frontier successor root this advance produces
    /// (`dsm_anchor_frontier_successor(parent_root, operation_hash, state_number)`).
    pub successor_root: &'a [u8; 32],
    /// Monotonic anchor-frontier counter for this advance.
    pub state_number: u64,
}

/// Transport-agnostic handle to an offline-bearer signing anchor. Implemented by the BLE transport
/// (real Safe 7), the UDP transport (emulator), and the in-process mock (tests / host wiring).
#[async_trait]
pub trait AnchorTransport: Send + Sync + std::fmt::Debug {
    /// Provision a fresh anchor inside the element and return its published identity.
    /// `device_context` is folded into the in-element state derivation. Idempotent transports may
    /// return the existing identity if already born.
    async fn birth(&self, device_context: &[u8]) -> Result<AnchorIdentityRecord, DsmError>;

    /// Return the anchor's published identity without (re)provisioning.
    async fn get_identity(&self) -> Result<AnchorIdentityRecord, DsmError>;

    /// Display `req` on the device, await human hold-to-confirm, and return the island's signature
    /// over the framed canonical challenge. Errors if the human rejects, the device is unreachable,
    /// or no anchor is born — the gate treats every such error as "no offline-bearer authority" and
    /// falls back to the online-checked path (fail-closed, never a hard reject).
    async fn sign(&self, req: &AnchorSignRequest<'_>) -> Result<Vec<u8>, DsmError>;
}

/// Recompute the consent ceremony and verify the island's signature over a sign request, against a
/// pinned identity record. This is the host/verifier mirror of the device's in-firmware
/// computation: it rebuilds `ui_transcript` from the displayed fields + the record's pinned
/// `firmware_id` / `screen_template_id`, rebuilds the canonical challenge, and checks the signature
/// against the pinned `leaf_spki`. Returns `id_island = SHA-256(leaf SPKI)` on success. A mismatch
/// (the device displayed/signed something other than this exact transition) is rejected.
pub fn verify_anchor_signature(
    record: &AnchorIdentityRecord,
    req: &AnchorSignRequest<'_>,
    signature: &[u8],
) -> Result<[u8; 32], DsmError> {
    let ui = dsm_ui_transcript(
        req.amount,
        req.asset,
        req.counterparty_id,
        req.h_n,
        req.payload_hash,
        req.policy_id,
        &record.firmware_id,
        record.screen_template_id,
    );
    let anchor_pubkey_hash = crate::attestation::dsm_anchor_pubkey_hash(&record.leaf_spki);
    let receipt_commit = crate::attestation::dsm_offline_bearer_receipt_commit(
        &anchor_pubkey_hash,
        &record.firmware_hash,
        req.policy_hash,
        req.parent_root,
        req.successor_root,
        req.state_number,
    );
    let intent = IslandIntent {
        h_n: req.h_n,
        payload_hash: req.payload_hash,
        relationship_id: req.relationship_id,
        device_id: req.device_id,
        value_capability: req.value_capability,
        offline_bearer_mode: req.offline_bearer_mode,
        nonce: req.nonce,
        expiry_tick: req.expiry_tick,
        ui_transcript: &ui,
        receipt_commit: &receipt_commit,
    };
    verify_island_intent_signature(&record.leaf_spki, &intent, signature)
}

// ===== In-process mock (tests + host wiring without hardware) =====

/// In-process Ed25519 anchor that mirrors the cut-1 TROPIC01-native signing path: a fixed,
/// non-exported signing key; identity = its own SPKI; signature = Ed25519 over the framed challenge
/// the DEVICE computes from the request. Faithful to cut-1 (no SPHINCS+ / σ-derivation — that is
/// the PQ swap).
///
/// It provides NO hardware anti-clone guarantee (the key lives in host memory) and is never wired
/// in production — it exists so the Phase-5 gate and host integration can be exercised without an
/// emulator or device. Gated behind `cfg(test)` or the `test-mock` feature.
#[cfg(any(test, feature = "test-mock"))]
#[derive(Debug)]
pub struct MockAnchorTransport {
    signing_key: ed25519_dalek::SigningKey,
    firmware_id: [u8; 32],
    screen_template_id: u32,
    commitment_c: [u8; 32],
    reject: bool,
}

#[cfg(any(test, feature = "test-mock"))]
impl MockAnchorTransport {
    /// Deterministic mock from a 32-byte seed. Different seeds → different identities, which is how
    /// the clone-rejection test models a same-model clone holding a different element.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let firmware_id = {
            let mut h = crate::crypto::blake3::dsm_domain_hasher("DSM/mock-anchor-firmware-id/v1");
            h.update(&seed);
            *h.finalize().as_bytes()
        };
        let commitment_c = {
            let mut h = crate::crypto::blake3::dsm_domain_hasher("DSM/mock-anchor-commitment/v1");
            h.update(&seed);
            *h.finalize().as_bytes()
        };
        Self {
            signing_key,
            firmware_id,
            screen_template_id: 1,
            commitment_c,
            reject: false,
        }
    }

    /// A mock whose `sign` always errors, modelling a human rejection or an unreachable device.
    /// Used to prove the gate's fail-closed fallback to the online-checked path.
    pub fn rejecting(seed: [u8; 32]) -> Self {
        Self {
            reject: true,
            ..Self::from_seed(seed)
        }
    }

    fn leaf_spki(&self) -> Vec<u8> {
        ed25519_raw_to_spki(self.signing_key.verifying_key().as_bytes())
    }

    fn identity(&self) -> AnchorIdentityRecord {
        let leaf_spki = self.leaf_spki();
        let id_anchor = {
            let mut h = crate::crypto::blake3::dsm_domain_hasher("DSM/anchor-id/v1");
            h.update(&self.commitment_c);
            h.update(self.signing_key.verifying_key().as_bytes());
            *h.finalize().as_bytes()
        };
        AnchorIdentityRecord {
            id_anchor,
            commitment_c: self.commitment_c,
            leaf_spki,
            firmware_id: self.firmware_id,
            screen_template_id: self.screen_template_id,
            // Host-memory mock has no secure-element measurement; zero until enrollment wires the
            // real measured hash (Step 2 / Track 3).
            firmware_hash: [0u8; 32],
        }
    }
}

/// Wrap a raw 32-byte Ed25519 public key in minimal SubjectPublicKeyInfo DER (matches the form the
/// verifier parses via `ed25519_pubkey_from_spki`).
#[cfg(any(test, feature = "test-mock"))]
fn ed25519_raw_to_spki(raw_pubkey: &[u8; 32]) -> Vec<u8> {
    let mut spki = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    spki.extend_from_slice(raw_pubkey);
    spki
}

#[cfg(any(test, feature = "test-mock"))]
#[async_trait]
impl AnchorTransport for MockAnchorTransport {
    async fn birth(&self, _device_context: &[u8]) -> Result<AnchorIdentityRecord, DsmError> {
        Ok(self.identity())
    }

    async fn get_identity(&self) -> Result<AnchorIdentityRecord, DsmError> {
        Ok(self.identity())
    }

    async fn sign(&self, req: &AnchorSignRequest<'_>) -> Result<Vec<u8>, DsmError> {
        use ed25519_dalek::Signer;
        if self.reject {
            return Err(DsmError::verification(
                "mock anchor: human rejected / device unreachable",
            ));
        }
        // Mirror the device: compute the UI transcript and challenge over the DISPLAYED fields,
        // using this device's own firmware_id / screen_template_id, then sign the framed challenge.
        let ui = dsm_ui_transcript(
            req.amount,
            req.asset,
            req.counterparty_id,
            req.h_n,
            req.payload_hash,
            req.policy_id,
            &self.firmware_id,
            self.screen_template_id,
        );
        let anchor_pubkey_hash = crate::attestation::dsm_anchor_pubkey_hash(&self.leaf_spki());
        let receipt_commit = crate::attestation::dsm_offline_bearer_receipt_commit(
            &anchor_pubkey_hash,
            &[0u8; 32],
            req.policy_hash,
            req.parent_root,
            req.successor_root,
            req.state_number,
        );
        let intent = IslandIntent {
            h_n: req.h_n,
            payload_hash: req.payload_hash,
            relationship_id: req.relationship_id,
            device_id: req.device_id,
            value_capability: req.value_capability,
            offline_bearer_mode: req.offline_bearer_mode,
            nonce: req.nonce,
            expiry_tick: req.expiry_tick,
            ui_transcript: &ui,
            receipt_commit: &receipt_commit,
        };
        let framed = crate::attestation::frame_authenticate_device(&intent.challenge())?;
        Ok(self.signing_key.sign(&framed).to_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::id_island_from_spki;

    fn sample_request<'a>(
        h_n: &'a [u8; 32],
        payload: &'a [u8; 32],
        rel: &'a [u8; 32],
        dev: &'a [u8; 32],
        cp: &'a [u8; 32],
        policy: &'a [u8; 32],
        amount: u64,
    ) -> AnchorSignRequest<'a> {
        AnchorSignRequest {
            h_n,
            payload_hash: payload,
            relationship_id: rel,
            device_id: dev,
            value_capability: 1,
            offline_bearer_mode: 1,
            nonce: b"n0",
            expiry_tick: 9,
            amount,
            asset: b"ERA",
            counterparty_id: cp,
            policy_id: policy,
            policy_hash: &[0u8; 32],
            parent_root: &[0u8; 32],
            successor_root: &[0u8; 32],
            state_number: 1,
        }
    }

    #[tokio::test]
    async fn mock_anchor_round_trips_through_the_gate() {
        let anchor = MockAnchorTransport::from_seed([7u8; 32]);
        let rec = anchor.birth(b"ctx").await.expect("birth");
        let (h_n, payload, rel, dev, cp, policy) = (
            [1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32], [6u8; 32],
        );
        let req = sample_request(&h_n, &payload, &rel, &dev, &cp, &policy, 10);

        let sig = anchor.sign(&req).await.expect("sign");
        // The host independently recomputes the consent ceremony and verifies.
        let id = verify_anchor_signature(&rec, &req, &sig).expect("anchor signature verifies");
        assert_eq!(id, id_island_from_spki(&rec.leaf_spki));
        // get_identity is stable across calls.
        assert_eq!(anchor.get_identity().await.expect("id"), rec);
    }

    #[tokio::test]
    async fn clone_with_a_different_element_is_rejected() {
        // Same-model clone: holds a DIFFERENT element (different seed → different key).
        let genuine = MockAnchorTransport::from_seed([7u8; 32]);
        let clone = MockAnchorTransport::from_seed([8u8; 32]);
        let genuine_rec = genuine.get_identity().await.expect("id");
        let (h_n, payload, rel, dev, cp, policy) = (
            [1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32], [6u8; 32],
        );
        let req = sample_request(&h_n, &payload, &rel, &dev, &cp, &policy, 10);

        // The clone signs the same transition, but under the GENUINE device's pinned identity its
        // signature does not verify — the anti-clone primitive.
        let clone_sig = clone.sign(&req).await.expect("clone signs");
        assert!(verify_anchor_signature(&genuine_rec, &req, &clone_sig).is_err());
    }

    #[tokio::test]
    async fn host_displaying_a_different_amount_is_rejected() {
        // Consent oracle: the device signed amount=10 (what the human saw); a host that later
        // claims the transition was amount=11 fails verification.
        let anchor = MockAnchorTransport::from_seed([7u8; 32]);
        let rec = anchor.get_identity().await.expect("id");
        let (h_n, payload, rel, dev, cp, policy) = (
            [1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32], [6u8; 32],
        );
        let signed = sample_request(&h_n, &payload, &rel, &dev, &cp, &policy, 10);
        let claimed = sample_request(&h_n, &payload, &rel, &dev, &cp, &policy, 11);

        let sig = anchor.sign(&signed).await.expect("sign");
        assert!(verify_anchor_signature(&rec, &signed, &sig).is_ok());
        assert!(verify_anchor_signature(&rec, &claimed, &sig).is_err());
    }

    #[tokio::test]
    async fn rejecting_anchor_errors_so_the_gate_can_fall_back() {
        let anchor = MockAnchorTransport::rejecting([7u8; 32]);
        let (h_n, payload, rel, dev, cp, policy) = (
            [1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32], [6u8; 32],
        );
        let req = sample_request(&h_n, &payload, &rel, &dev, &cp, &policy, 10);
        assert!(anchor.sign(&req).await.is_err());
    }

    #[tokio::test]
    async fn receipt_field_tamper_is_rejected() {
        // The receipt_commit binds the frontier state_number into the challenge: a signature for
        // state_number=5 must NOT verify when re-presented as state_number=6.
        let anchor = MockAnchorTransport::from_seed([7u8; 32]);
        let rec = anchor.get_identity().await.expect("id");
        let (h_n, payload, rel, dev, cp, policy) = (
            [1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32], [6u8; 32],
        );
        let signed = AnchorSignRequest {
            state_number: 5,
            ..sample_request(&h_n, &payload, &rel, &dev, &cp, &policy, 10)
        };
        let claimed = AnchorSignRequest {
            state_number: 6,
            ..signed
        };
        let sig = anchor.sign(&signed).await.expect("sign");
        assert!(verify_anchor_signature(&rec, &signed, &sig).is_ok());
        assert!(verify_anchor_signature(&rec, &claimed, &sig).is_err());
    }
}
