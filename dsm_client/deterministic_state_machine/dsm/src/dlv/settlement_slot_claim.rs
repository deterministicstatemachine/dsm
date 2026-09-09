// SPDX-License-Identifier: MIT OR Apache-2.0

//! Settlement-slot claim: the write-once value a contestant submits to every
//! member of a vault's canonical storage set to acquire the right to consume
//! vault parent `parent_sequence`.
//!
//! The register the claim lands in is a distributed, crash-fault-tolerant,
//! ONE-SHOT quorum register keyed `(vault_id, parent_sequence)`: each member
//! holds at most one value per slot, forever, and a claimant wins only when a
//! quorum of the vault's set accepted the SAME envelope bytes. It provides
//! concurrency serialization for mutually-unknown actors — never validity: the
//! canonical DSM transition still decides whether a settlement or close is
//! valid, and members never judge that.
//!
//! Byte discipline, because members compare EXACT bytes:
//! * the signature covers the BODY only (`H(tag ‖ 0x00 ‖ canonical body
//!   bytes)`) — you cannot sign bytes that contain the signature;
//! * the envelope is canonically encoded ONCE by the claimant and those exact
//!   bytes are retained for every retry and recovery replay; a
//!   semantically-equal re-encode that differs by a byte would read as a
//!   different claimant at a member;
//! * verification is strict: fixed 32-byte fields, bounded key/signature,
//!   decode→re-encode equality (so unknown/duplicate fields and non-canonical
//!   encodings are refused), signature under the body's own
//!   `claimant_public_key`. Attribution to the authenticated caller (that key
//!   IS the caller's) is the storage node's check, layered on top.

use crate::common::domain_tags::{
    TAG_DSM_SETTLEMENT_SLOT_CLAIM_ENVELOPE_V2, TAG_DSM_SETTLEMENT_SLOT_CLAIM_V2,
};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::types::proto as generated;
use prost::Message;

/// Upper bound for the SPHINCS+ key / signature fields (matches the proto's
/// `dsm_max_len`; prost does not enforce it, so this module does).
const MAX_KEY_OR_SIG_BYTES: usize = 65_535;

/// The unsigned claim body — what the signature covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementSlotClaimBody {
    pub vault_id: [u8; 32],
    pub parent_sequence: u64,
    /// The trade's external commitment (trader) or the close commitment
    /// (owner) — the `x` the slot's discovery pointer names.
    pub x: [u8; 32],
    pub claimant_public_key: Vec<u8>,
    /// The vault's birth-bound canonical storage set (from its signed anchor).
    pub storage_set_id: [u8; 32],
    /// KEY BY NAME, BIND BY STATE (3.6): the exact parent vault state this
    /// claim consumes, `c_n = H(DSM/vault-state, CCB(V_n))`. The register key
    /// stays `(vault_id, parent_sequence)` — keying on `c_n` would let two
    /// contestants holding different alleged `V_n` occupy different cells and
    /// BOTH win exactly when views diverge; binding it in the signed body
    /// turns a silent divergence into a detectable contradiction. Members do
    /// not judge it; the 0x0026 provenance arm does.
    pub parent_binding_c_n: [u8; 32],
}

/// A claim envelope that decoded strictly and whose signature verified under
/// its own `claimant_public_key`. Attribution to the caller is checked by the
/// storage node separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSettlementSlotClaim {
    pub body: SettlementSlotClaimBody,
    /// `H(envelope tag ‖ 0x00 ‖ exact envelope bytes)` — the digest a register
    /// member stores and compares.
    pub envelope_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimError {
    /// The envelope did not decode, or decoded to something whose canonical
    /// re-encoding is not the input bytes (unknown/duplicate fields, non-minimal
    /// varints, out-of-order fields), or a fixed field had the wrong width, or
    /// a bounded field was oversized.
    Malformed(&'static str),
    /// The signature does not verify over the body under the body's key.
    SignatureInvalid,
    /// SPHINCS+ signing failed.
    SignFailed(String),
}

impl core::fmt::Display for ClaimError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ClaimError::Malformed(why) => write!(f, "settlement-slot claim malformed: {why}"),
            ClaimError::SignatureInvalid => write!(f, "settlement-slot claim signature invalid"),
            ClaimError::SignFailed(e) => write!(f, "settlement-slot claim sign failed: {e}"),
        }
    }
}

impl std::error::Error for ClaimError {}

impl SettlementSlotClaimBody {
    fn to_proto(&self) -> generated::SettlementSlotClaimBodyV2 {
        generated::SettlementSlotClaimBodyV2 {
            vault_id: self.vault_id.to_vec(),
            parent_sequence: self.parent_sequence,
            x: self.x.to_vec(),
            claimant_public_key: self.claimant_public_key.clone(),
            storage_set_id: self.storage_set_id.to_vec(),
            parent_binding_c_n: self.parent_binding_c_n.to_vec(),
        }
    }

    /// The canonical body bytes: prost's deterministic encoding of the
    /// well-formed message (fields in tag order, minimal varints).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.to_proto().encode_to_vec()
    }

    fn from_proto(p: &generated::SettlementSlotClaimBodyV2) -> Result<Self, ClaimError> {
        let fixed = |v: &[u8], what: &'static str| -> Result<[u8; 32], ClaimError> {
            <[u8; 32]>::try_from(v).map_err(|_| ClaimError::Malformed(what))
        };
        if p.claimant_public_key.is_empty() || p.claimant_public_key.len() > MAX_KEY_OR_SIG_BYTES {
            return Err(ClaimError::Malformed("claimant_public_key length"));
        }
        Ok(Self {
            vault_id: fixed(&p.vault_id, "vault_id must be 32 bytes")?,
            parent_sequence: p.parent_sequence,
            x: fixed(&p.x, "x must be 32 bytes")?,
            claimant_public_key: p.claimant_public_key.clone(),
            storage_set_id: fixed(&p.storage_set_id, "storage_set_id must be 32 bytes")?,
            parent_binding_c_n: fixed(
                &p.parent_binding_c_n,
                "parent_binding_c_n must be 32 bytes (v1 claims are burned)",
            )?,
        })
    }
}

/// The signed preimage: `H(TAG_DSM_SETTLEMENT_SLOT_CLAIM_V2 ‖ 0x00 ‖ canonical
/// body bytes)`. Body only — never the envelope.
pub fn claim_sign_payload(canonical_body_bytes: &[u8]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_SETTLEMENT_SLOT_CLAIM_V2);
    h.update(canonical_body_bytes);
    *h.finalize().as_bytes()
}

/// The digest a register member stores and compares for a held claim:
/// `H(envelope tag ‖ 0x00 ‖ exact envelope bytes)`.
pub fn claim_envelope_digest(envelope_bytes: &[u8]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_SETTLEMENT_SLOT_CLAIM_ENVELOPE_V2);
    h.update(envelope_bytes);
    *h.finalize().as_bytes()
}

/// Sign `body` with the claimant's SPHINCS+ secret key and return the
/// canonical ENVELOPE bytes — the exact bytes to freeze, submit to every member,
/// and replay verbatim on retry/recovery. Never re-encode; keep these.
pub fn sign_settlement_slot_claim(
    body: &SettlementSlotClaimBody,
    claimant_secret_key: &[u8],
) -> Result<Vec<u8>, ClaimError> {
    let body_bytes = body.canonical_bytes();
    let payload = claim_sign_payload(&body_bytes);
    let signature = crate::crypto::sphincs::sphincs_sign(claimant_secret_key, &payload)
        .map_err(|e| ClaimError::SignFailed(format!("{e:?}")))?;
    let env = generated::SettlementSlotClaimV2 {
        body: Some(body.to_proto()),
        signature,
    };
    Ok(env.encode_to_vec())
}

/// Strictly decode an envelope and verify its signature under the body's own
/// `claimant_public_key`. Refuses anything that does not re-encode to exactly
/// the input bytes.
pub fn decode_and_verify_settlement_slot_claim(
    envelope_bytes: &[u8],
) -> Result<VerifiedSettlementSlotClaim, ClaimError> {
    if envelope_bytes.is_empty() {
        return Err(ClaimError::Malformed("empty envelope"));
    }
    let env = generated::SettlementSlotClaimV2::decode(envelope_bytes)
        .map_err(|_| ClaimError::Malformed("envelope does not decode"))?;
    let body_proto = env
        .body
        .as_ref()
        .ok_or(ClaimError::Malformed("envelope has no body"))?;
    if env.signature.is_empty() || env.signature.len() > MAX_KEY_OR_SIG_BYTES {
        return Err(ClaimError::Malformed("signature length"));
    }
    let body = SettlementSlotClaimBody::from_proto(body_proto)?;
    // Canonical-bytes discipline: the ONLY acceptable envelope is prost's
    // encoding of the well-formed message. Unknown fields, duplicates and
    // non-canonical encodings all fail this comparison.
    let reencoded = generated::SettlementSlotClaimV2 {
        body: Some(body.to_proto()),
        signature: env.signature.clone(),
    }
    .encode_to_vec();
    if reencoded != envelope_bytes {
        return Err(ClaimError::Malformed("envelope is not canonical"));
    }
    let payload = claim_sign_payload(&body.canonical_bytes());
    let ok =
        crate::crypto::sphincs::sphincs_verify(&body.claimant_public_key, &payload, &env.signature)
            .map_err(|_| ClaimError::SignatureInvalid)?;
    if !ok {
        return Err(ClaimError::SignatureInvalid);
    }
    Ok(VerifiedSettlementSlotClaim {
        body,
        envelope_digest: claim_envelope_digest(envelope_bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kp() -> (Vec<u8>, Vec<u8>) {
        crate::crypto::sphincs::generate_sphincs_keypair().expect("keypair")
    }

    fn body(pk: &[u8]) -> SettlementSlotClaimBody {
        SettlementSlotClaimBody {
            vault_id: [0x11; 32],
            parent_sequence: 7,
            x: [0x22; 32],
            claimant_public_key: pk.to_vec(),
            storage_set_id: [0x6B; 32],
            parent_binding_c_n: [0x77; 32],
        }
    }

    #[test]
    fn sign_then_verify_round_trips_and_the_envelope_is_canonical() {
        let (pk, sk) = kp();
        let b = body(&pk);
        let env = sign_settlement_slot_claim(&b, &sk).expect("sign");
        let v = decode_and_verify_settlement_slot_claim(&env).expect("verify");
        assert_eq!(v.body, b);
        assert_eq!(v.envelope_digest, claim_envelope_digest(&env));
        // The contract is that the CLIENT retains the first envelope bytes and
        // replays them; nothing here relies on re-signing reproducing them.
        assert_eq!(
            decode_and_verify_settlement_slot_claim(&env.clone()).unwrap(),
            v,
            "verifying the retained bytes again yields the same claim"
        );
    }

    #[test]
    fn the_signature_covers_the_body_only_and_any_body_change_is_refused() {
        let (pk, sk) = kp();
        let b = body(&pk);
        let env = sign_settlement_slot_claim(&b, &sk).expect("sign");
        let decoded = generated::SettlementSlotClaimV2::decode(env.as_slice()).unwrap();
        let mut tampered = decoded.clone();
        tampered.body.as_mut().unwrap().parent_sequence = 8;
        let bytes = tampered.encode_to_vec();
        assert_eq!(
            decode_and_verify_settlement_slot_claim(&bytes),
            Err(ClaimError::SignatureInvalid)
        );
        let mut tampered = decoded.clone();
        tampered.body.as_mut().unwrap().storage_set_id = vec![0x6C; 32];
        assert_eq!(
            decode_and_verify_settlement_slot_claim(&tampered.encode_to_vec()),
            Err(ClaimError::SignatureInvalid),
            "the set is inside the signed body"
        );
        // A different signature under the same body: refused.
        let mut tampered = decoded;
        tampered.signature[0] ^= 0xff;
        assert_eq!(
            decode_and_verify_settlement_slot_claim(&tampered.encode_to_vec()),
            Err(ClaimError::SignatureInvalid)
        );
    }

    #[test]
    fn non_canonical_or_malformed_envelopes_are_refused() {
        let (pk, sk) = kp();
        let b = body(&pk);
        let env = sign_settlement_slot_claim(&b, &sk).expect("sign");
        // Appending an unknown field: decodes, but does not re-encode to the
        // same bytes → refused as non-canonical.
        let mut with_unknown = env.clone();
        with_unknown.extend_from_slice(&[0x7a, 0x01, 0x00]); // field 15, varint 0
        assert!(matches!(
            decode_and_verify_settlement_slot_claim(&with_unknown),
            Err(ClaimError::Malformed(_))
        ));
        // Wrong-width fixed field.
        let mut short = generated::SettlementSlotClaimV2::decode(env.as_slice()).unwrap();
        short.body.as_mut().unwrap().vault_id = vec![0x11; 31];
        assert!(matches!(
            decode_and_verify_settlement_slot_claim(&short.encode_to_vec()),
            Err(ClaimError::Malformed(_))
        ));
        // Empty / garbage.
        assert!(matches!(
            decode_and_verify_settlement_slot_claim(&[]),
            Err(ClaimError::Malformed(_))
        ));
        assert!(matches!(
            decode_and_verify_settlement_slot_claim(&[0xff, 0xff, 0xff]),
            Err(ClaimError::Malformed(_))
        ));
        // Envelope without a body.
        let no_body = generated::SettlementSlotClaimV2 {
            body: None,
            signature: vec![1, 2, 3],
        }
        .encode_to_vec();
        assert!(matches!(
            decode_and_verify_settlement_slot_claim(&no_body),
            Err(ClaimError::Malformed(_))
        ));
    }

    /// The v1 shape — no `parent_binding_c_n` — is BURNED: bytes without the
    /// binding decode as an empty field 6 and fail the fixed-width check. A
    /// tampered binding is caught by the signature (it is inside the body).
    #[test]
    fn a_burned_v1_shaped_claim_is_refused_and_the_binding_is_signed() {
        let (pk, sk) = kp();
        let b = body(&pk);
        let env = sign_settlement_slot_claim(&b, &sk).expect("sign");
        let mut decoded = generated::SettlementSlotClaimV2::decode(env.as_slice()).unwrap();
        // The v1 shape: strip the parent binding entirely.
        decoded.body.as_mut().unwrap().parent_binding_c_n = Vec::new();
        assert!(matches!(
            decode_and_verify_settlement_slot_claim(&decoded.encode_to_vec()),
            Err(ClaimError::Malformed(_))
        ));
        // A different binding under the same signature: refused as unsigned.
        let mut decoded = generated::SettlementSlotClaimV2::decode(env.as_slice()).unwrap();
        decoded.body.as_mut().unwrap().parent_binding_c_n = vec![0x78; 32];
        assert_eq!(
            decode_and_verify_settlement_slot_claim(&decoded.encode_to_vec()),
            Err(ClaimError::SignatureInvalid),
            "the parent binding is inside the signed body"
        );
    }

    #[test]
    fn envelope_digest_distinguishes_claimants_and_slots() {
        let (pk1, sk1) = kp();
        let (pk2, sk2) = kp();
        let e1 = sign_settlement_slot_claim(&body(&pk1), &sk1).unwrap();
        let e2 = sign_settlement_slot_claim(&body(&pk2), &sk2).unwrap();
        assert_ne!(claim_envelope_digest(&e1), claim_envelope_digest(&e2));
        let mut other_slot = body(&pk1);
        other_slot.parent_sequence = 8;
        let e3 = sign_settlement_slot_claim(&other_slot, &sk1).unwrap();
        assert_ne!(claim_envelope_digest(&e1), claim_envelope_digest(&e3));
    }
}
