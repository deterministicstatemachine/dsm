// SPDX-License-Identifier: Apache-2.0

//! `GenesisParamsV3` — registry §5.15, substrate class `0x0018`.
//!
//! `G = H_dom(DSM/genesis/v3, CCB(GenesisParamsV3))`. The genesis identifier
//! is a commitment to its own parameters, and the Genesis Root Key is one of
//! them — which is what lets a verifier holding `g_o` authenticate `GRK_pk`
//! **by recomputation alone**: no fetch, no signature, no lookup, nothing
//! that could itself require an authority. That property is the non-circular
//! `g_o → R_G` edge the whole area 8 chain rests on.

use super::{push_bytes, push_digest32, push_envelope, push_u16, push_u32, CcbError, CcbObject};
use crate::common::domain_tags::TAG_DSM_GENESIS_V3;
use crate::crypto::blake3::dsm_domain_hasher;

/// `signature_alg` — registry §3.1. Identifies an algorithm together with the
/// exact encoding of its public keys and signatures. Committed wherever a
/// public key is, so a future variant can never be substituted for the
/// committed one: the algorithm and the key bytes stand or fall together.
pub mod sigalg {
    /// SPHINCS+ SPX256f: 64-byte public key (`2n`, `n = 32`), 49_856-byte
    /// signature. The only member the beta profile declares.
    pub const SPHINCS_PLUS_SPX256F: u16 = 0x0001;

    /// Declared public-key width for a known algorithm; `None` for an
    /// undeclared one. Enumerations range over values declared in the
    /// registry, never values invented at a call site.
    pub fn public_key_len(alg: u16) -> Option<usize> {
        match alg {
            SPHINCS_PLUS_SPX256F => Some(64),
            _ => None,
        }
    }
}

/// `0x0018` schema 1 — the Genesis v3 parameter set.
///
/// Field 5 is the **exact key, not a commitment to it**. `H(GRK_pk)` would
/// need its own preimage rules — the same canonicalization question one layer
/// down, which §2.7 refuses for nested objects. `G` is already a hash;
/// folding the key directly *is* the commitment.
///
/// Deliberately **not** members: `device_slot`, `authority_policy_hash`,
/// `AttA`, and any device key. Every device-scoped value derives from `G` and
/// therefore cannot appear inside it without circularity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisParamsV3 {
    /// Public; `KDF(wallet_seed, DSM/genesis-public-nonce/v2 ‖ network_id ‖
    /// wallet_index)` — the v2 nonce derivation, unchanged.
    pub genesis_nonce: [u8; 32],
    /// Length-prefixed. The v2 preimage concatenated it bare, which was
    /// recoverable with one variable-length field; with `grk_pk` also in the
    /// preimage, unprefixed concatenation cannot say where the first ends.
    pub network_id: Vec<u8>,
    /// `3` for this class; big-endian per §2.2, where the v2 preimage was
    /// little-endian.
    pub genesis_version: u32,
    /// Fixes the key encoding of `grk_pk`.
    pub grk_alg_id: u16,
    /// The exact Genesis Root Key public key bytes.
    pub grk_pk: Vec<u8>,
}

impl CcbObject for GenesisParamsV3 {
    const CLASS: u16 = super::class::GENESIS_PARAMS_V3;
    const SCHEMA: u16 = 1;
}

impl GenesisParamsV3 {
    /// Validates the algorithm against the declared enumeration and the key
    /// against that algorithm's declared width. Refuses rather than repairs:
    /// an undeclared algorithm or a mis-sized key is a producer bug, not a
    /// normalization opportunity.
    pub fn new(
        genesis_nonce: [u8; 32],
        network_id: &[u8],
        genesis_version: u32,
        grk_alg_id: u16,
        grk_pk: &[u8],
    ) -> Result<Self, CcbError> {
        let expected = sigalg::public_key_len(grk_alg_id)
            .ok_or(CcbError::UnknownSignatureAlg { alg: grk_alg_id })?;
        if grk_pk.len() != expected {
            return Err(CcbError::KeyLengthMismatch {
                alg: grk_alg_id,
                expected,
                got: grk_pk.len(),
            });
        }
        Ok(Self {
            genesis_nonce,
            network_id: network_id.to_vec(),
            genesis_version,
            grk_alg_id,
            grk_pk: grk_pk.to_vec(),
        })
    }

    /// Fields 1..5 in registry order.
    pub fn encode(&self) -> Result<Vec<u8>, CcbError> {
        let mut out = Vec::new();
        push_envelope::<Self>(&mut out);
        push_digest32(&mut out, &self.genesis_nonce); // 1
        push_bytes(&mut out, &self.network_id)?; // 2
        push_u32(&mut out, self.genesis_version); // 3
        push_u16(&mut out, self.grk_alg_id); // 4
        push_bytes(&mut out, &self.grk_pk)?; // 5
        Ok(out)
    }
}

/// `G = H_dom(DSM/genesis/v3, CCB(GenesisParamsV3))`.
pub fn genesis_v3_commitment(params: &GenesisParamsV3) -> Result<[u8; 32], CcbError> {
    let ccb = params.encode()?;
    let mut h = dsm_domain_hasher(TAG_DSM_GENESIS_V3);
    h.update(&ccb);
    Ok(*h.finalize().as_bytes())
}
