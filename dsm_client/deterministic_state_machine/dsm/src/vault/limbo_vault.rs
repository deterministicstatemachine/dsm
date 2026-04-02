//! Deterministic Limbo Vault (DLV)
//!
//! Protobuf-only I/O (prost). Binary digests internally.
//! No wall-clock usage; verification relies on state numbers and deterministic data.
//! No hex/json/base64/serde anywhere in Rust.

use core::fmt;
use std::collections::{HashMap, HashSet};

use prost::Message;
use crate::crypto::kyber;
use crate::crypto::pedersen::{PedersenCommitment, PedersenParams, SecurityLevel};
use crate::crypto::sphincs;
use crate::types::error::DsmError;
use crate::types::policy_types::VaultCondition;
use crate::types::state_types::State;

use crate::core::state_machine::random_walk::algorithms::{generate_positions, generate_seed, Position};

use crate::crypto::blake3::{dsm_domain_hasher, domain_hash, domain_hash_bytes};

use super::FulfillmentMechanism;

/* ---------- small internal helpers (no encodings, no clocks) ---------- */

#[inline]
fn secure_eq(a: &[u8], b: &[u8]) -> bool {
    // Constant-time equality: XOR-accumulate without early returns
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for i in 0..a.len() {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}

/// Concatenate byte slices (deterministic; no allocation surprises beyond sum).
#[inline]
fn concat_bytes(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

/// Produce a human-readable decimal label from bytes (not an encoding).
/// Take first 8 bytes of BLAKE3(hash(material)), interpret LE u64, print in base-10.
fn decimal_label(prefix: &str, material: &[u8]) -> String {
    let h = domain_hash("DSM/dlv-label", material);
    let mut w = [0u8; 8];
    w.copy_from_slice(&h.as_bytes()[0..8]);
    let n = u64::from_le_bytes(w);
    format!("{prefix}{n}")
}

/* -------------------- Position <-> bytes (deterministic) -------------------- */

fn encode_position(pos: &Position) -> Vec<u8> {
    // [len u32 LE][coords i32 LE...]
    let mut out = Vec::with_capacity(4 + 4 * pos.0.len());
    let len = pos.0.len() as u32;
    out.extend_from_slice(&len.to_le_bytes());
    for c in &pos.0 {
        out.extend_from_slice(&c.to_le_bytes());
    }
    out
}

fn decode_position(bytes: &[u8]) -> Result<Position, DsmError> {
    if bytes.len() < 4 {
        return Err(DsmError::serialization_error(
            "position",
            "short_len",
            None::<&str>,
            None::<core::convert::Infallible>,
        ));
    }
    let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if bytes.len() != 4 + 4 * len {
        return Err(DsmError::serialization_error(
            "position",
            "invalid_size",
            None::<&str>,
            None::<core::convert::Infallible>,
        ));
    }
    let mut coords = Vec::with_capacity(len);
    let mut off = 4usize;
    for _ in 0..len {
        let a = [bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]];
        coords.push(i32::from_le_bytes(a));
        off += 4;
    }
    Ok(Position(coords))
}

/* -------------------------------- VaultState -------------------------------- */

#[derive(Debug, Clone, PartialEq)]
pub enum VaultState {
    Limbo,
    /// Entry anchor buried — dBTC tradeable, but vault NOT unlocked.
    /// Preimage/skV only derivable after a Burn transition (dBTC §6.2-6.4).
    Active {
        activated_state_number: u64,
    },
    Unlocked {
        unlocked_state_number: u64,
        fulfillment_proof: Box<FulfillmentProof>,
    },
    Claimed {
        claimed_state_number: u64,
        claimant: Vec<u8>,
        claim_proof: Vec<u8>,
    },
    Invalidated {
        invalidated_state_number: u64,
        reason: String,
        creator_signature: Vec<u8>,
    },
}

/* ------------------------------ FulfillmentProof ---------------------------- */

#[derive(Debug, Clone, PartialEq)]
pub enum FulfillmentProof {
    PaymentProof {
        state_transition: Vec<u8>,
        merkle_proof: Vec<u8>,
        /// σ commitment from bilateral stitched receipt (§7.3).
        stitched_receipt_sigma: Option<[u8; 32]>,
    },
    CryptoConditionProof {
        solution: Vec<u8>,
        proof: Vec<u8>,
        /// σ commitment from bilateral stitched receipt (§7.3).
        stitched_receipt_sigma: Option<[u8; 32]>,
    },
    MultiSignatureProof {
        signatures: Vec<(Vec<u8>, Vec<u8>)>, // (public_key, signature)
        signed_data: Vec<u8>,
        /// σ commitment from bilateral stitched receipt (§7.3).
        stitched_receipt_sigma: Option<[u8; 32]>,
    },
    RandomWalkProof {
        positions: Vec<Position>,
        hash_chain_proof: Vec<u8>,
        /// σ commitment from bilateral stitched receipt (§7.3).
        stitched_receipt_sigma: Option<[u8; 32]>,
    },
    /// Bitcoin HTLC proof: preimage reveal + SPV proof of Bitcoin payment
    BitcoinHTLCProof {
        /// The secret s where SHA256(s) == hash_lock
        preimage: Vec<u8>,
        /// Bitcoin transaction ID (32 bytes, little-endian)
        bitcoin_txid: [u8; 32],
        /// Raw serialized Bitcoin transaction bytes containing the HTLC output.
        bitcoin_tx_raw: Vec<u8>,
        /// Serialized SPV Merkle proof of inclusion in a Bitcoin block
        spv_proof: Vec<u8>,
        /// Expected output scriptPubKey (raw bytes). If empty, only amount check is enforced.
        expected_script_pubkey: Vec<u8>,
        /// Raw 80-byte Bitcoin block header
        block_header: Box<[u8; 80]>,
        /// Chain of 80-byte headers connecting a known checkpoint to block_header.
        /// Empty for test networks; required for mainnet.
        /// Confirmation depth is derived from `header_chain.len() + 1` — never caller-attested.
        header_chain: Vec<[u8; 80]>,
        /// Legacy carrier field for canonical protocol-transition bytes
        /// corresponding to this unlock. This is not a bilateral stitched receipt
        /// for sovereign Bitcoin/DLV progression.
        stitched_receipt: Option<Vec<u8>>,
        /// Commitment for the protocol-transition payload carried above.
        /// Required for mainnet/testnet/signet DLV unlocks.
        stitched_receipt_sigma: Option<[u8; 32]>,
    },
    CompoundProof(Vec<FulfillmentProof>),
}

impl FulfillmentProof {
    /// Deterministic variant-tagged, length-prefixed encoding for hashing/storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            FulfillmentProof::PaymentProof {
                state_transition,
                merkle_proof,
                stitched_receipt_sigma,
            } => {
                out.push(1);
                put_len(&mut out, state_transition);
                put_len(&mut out, merkle_proof);
                match stitched_receipt_sigma {
                    Some(s) => {
                        out.push(0x01);
                        out.extend_from_slice(s);
                    }
                    None => out.push(0x00),
                }
            }
            FulfillmentProof::CryptoConditionProof {
                solution,
                proof,
                stitched_receipt_sigma,
            } => {
                out.push(2);
                put_len(&mut out, solution);
                put_len(&mut out, proof);
                match stitched_receipt_sigma {
                    Some(s) => {
                        out.push(0x01);
                        out.extend_from_slice(s);
                    }
                    None => out.push(0x00),
                }
            }
            FulfillmentProof::MultiSignatureProof {
                signatures,
                signed_data,
                stitched_receipt_sigma,
            } => {
                out.push(3);
                put_u32(&mut out, signatures.len() as u32);
                for (pk, sig) in signatures {
                    put_len(&mut out, pk);
                    put_len(&mut out, sig);
                }
                put_len(&mut out, signed_data);
                match stitched_receipt_sigma {
                    Some(s) => {
                        out.push(0x01);
                        out.extend_from_slice(s);
                    }
                    None => out.push(0x00),
                }
            }
            FulfillmentProof::RandomWalkProof {
                positions,
                hash_chain_proof,
                stitched_receipt_sigma,
            } => {
                out.push(4);
                put_u32(&mut out, positions.len() as u32);
                for p in positions {
                    let pb = encode_position(p);
                    put_len(&mut out, &pb);
                }
                put_len(&mut out, hash_chain_proof);
                match stitched_receipt_sigma {
                    Some(s) => {
                        out.push(0x01);
                        out.extend_from_slice(s);
                    }
                    None => out.push(0x00),
                }
            }
            FulfillmentProof::BitcoinHTLCProof {
                preimage,
                bitcoin_txid,
                bitcoin_tx_raw,
                spv_proof,
                expected_script_pubkey,
                block_header,
                header_chain,
                stitched_receipt,
                stitched_receipt_sigma,
            } => {
                out.push(6);
                put_len(&mut out, preimage);
                out.extend_from_slice(bitcoin_txid);
                put_len(&mut out, bitcoin_tx_raw);
                put_len(&mut out, spv_proof);
                put_len(&mut out, expected_script_pubkey);
                out.extend_from_slice(block_header.as_ref());
                put_u32(&mut out, header_chain.len() as u32);
                for h in header_chain {
                    out.extend_from_slice(h);
                }
                match stitched_receipt {
                    Some(r) => {
                        out.push(0x01);
                        put_len(&mut out, r);
                    }
                    None => out.push(0x00),
                }
                // §7.3: Optional stitched receipt sigma (presence tag + 32 bytes)
                match stitched_receipt_sigma {
                    Some(sigma) => {
                        out.push(0x01);
                        out.extend_from_slice(sigma);
                    }
                    None => {
                        out.push(0x00);
                    }
                }
            }
            FulfillmentProof::CompoundProof(v) => {
                out.push(5);
                put_u32(&mut out, v.len() as u32);
                for p in v {
                    let b = p.to_bytes();
                    put_len(&mut out, &b);
                }
            }
        }
        out
    }
}

use crate::types::serialization::{put_bytes as put_len, put_u32};

/// Extract `stitched_receipt_sigma` from any proof variant that carries one.
fn extract_sigma_from_proof(proof: &FulfillmentProof) -> Option<[u8; 32]> {
    match proof {
        FulfillmentProof::BitcoinHTLCProof {
            stitched_receipt_sigma,
            ..
        }
        | FulfillmentProof::PaymentProof {
            stitched_receipt_sigma,
            ..
        }
        | FulfillmentProof::CryptoConditionProof {
            stitched_receipt_sigma,
            ..
        }
        | FulfillmentProof::MultiSignatureProof {
            stitched_receipt_sigma,
            ..
        }
        | FulfillmentProof::RandomWalkProof {
            stitched_receipt_sigma,
            ..
        } => *stitched_receipt_sigma,
        FulfillmentProof::CompoundProof(_) => None,
    }
}

/* --------------------------------- Core types -------------------------------- */

#[derive(Debug, Clone)]
pub struct EncryptedContent {
    pub encapsulated_key: Vec<u8>,
    pub encrypted_data: Vec<u8>,
    pub nonce: Vec<u8>,
    pub aad: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct VaultPost {
    pub vault_id: String,
    pub lock_description: String,
    pub creator_id: String,
    pub commitment_hash: Vec<u8>,
    pub status: String,
    pub metadata: HashMap<String, String>,
    pub vault_data: Vec<u8>,
}

impl From<&VaultPost> for crate::types::proto::VaultPostProto {
    fn from(v: &VaultPost) -> Self {
        // Sort metadata for deterministic encoding (map -> sorted repeated ParamKV)
        let mut metadata_vec: Vec<_> = v
            .metadata
            .iter()
            .map(|(k, val)| crate::types::proto::ParamKv {
                key: k.clone(),
                value: val.clone(),
            })
            .collect();
        metadata_vec.sort_by(|a, b| a.key.cmp(&b.key));

        crate::types::proto::VaultPostProto {
            vault_id: v.vault_id.clone(),
            lock_description: v.lock_description.clone(),
            creator_id: v.creator_id.clone(),
            commitment_hash: v.commitment_hash.clone(),
            status: v.status.clone(),
            metadata: metadata_vec,
            vault_data: v.vault_data.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LimboVault {
    pub id: String,
    pub created_at_state: u64,
    pub creator_public_key: Vec<u8>,
    pub fulfillment_condition: FulfillmentMechanism,
    pub intended_recipient: Option<Vec<u8>>,
    pub state: VaultState,
    pub content_type: String,
    pub encrypted_content: EncryptedContent,
    pub content_commitment: PedersenCommitment,
    pub parameters_hash: Vec<u8>,
    pub creator_signature: Vec<u8>,
    pub verification_positions: Vec<Position>,
    pub reference_state_hash: [u8; 32],
    /// Bitcoin block header cached at entry time (80 bytes).
    /// dBTC paper §12.2.3, Invariant 19: exit proofs must chain back to this anchor.
    pub entry_header: Option<[u8; 80]>,
}

#[derive(Debug, Clone)]
pub struct ClaimResult {
    pub vault: LimboVault,
    pub content: Vec<u8>,
    pub claim_proof: Vec<u8>,
}

/* ------------------------------ Proto conversions ---------------------------- */

impl TryFrom<crate::types::proto::LimboVaultProto> for LimboVault {
    type Error = DsmError;

    fn try_from(p: crate::types::proto::LimboVaultProto) -> Result<Self, Self::Error> {
        let id = p.id;
        let created_at_state = p.created_at_state;
        let creator_public_key = p.creator_public_key;

        let fulfillment_condition_proto = p.fulfillment_condition.ok_or_else(|| {
            DsmError::serialization_error(
                "fulfillment_proto",
                "missing_kind",
                None::<&str>,
                None::<core::convert::Infallible>,
            )
        })?;
        let fulfillment_condition = FulfillmentMechanism::try_from(fulfillment_condition_proto)
            .map_err(|e| {
                DsmError::serialization_error("fulfillment_proto", "convert", None::<&str>, Some(e))
            })?;

        let intended_recipient = p.intended_recipient;

        let encrypted_content_proto = p
            .encrypted_content
            .ok_or_else(|| DsmError::invalid_operation("Missing encrypted content"))?;
        let encrypted_content = EncryptedContent {
            encapsulated_key: encrypted_content_proto.encapsulated_key,
            encrypted_data: encrypted_content_proto.encrypted_data,
            nonce: encrypted_content_proto.nonce,
            aad: encrypted_content_proto.aad,
        };

        let content_commitment =
            PedersenCommitment::from_bytes(&p.content_commitment).map_err(|e| {
                DsmError::serialization_error(
                    "content_commitment",
                    "deserialize",
                    None::<&str>,
                    Some(e),
                )
            })?;

        // Decode RW positions
        let mut verification_positions: Vec<Position> =
            Vec::with_capacity(p.verification_positions.len());
        for b in p.verification_positions.iter() {
            verification_positions.push(decode_position(b).map_err(|e| {
                DsmError::serialization_error(
                    "verification_positions",
                    "decode",
                    None::<&str>,
                    Some(e),
                )
            })?);
        }

        Ok(LimboVault {
            id,
            created_at_state,
            creator_public_key,
            fulfillment_condition,
            intended_recipient,
            state: VaultState::Limbo, // domain state kept internal
            content_type: p.content_type,
            encrypted_content,
            content_commitment,
            parameters_hash: p.parameters_hash,
            creator_signature: p.creator_signature,
            verification_positions,
            reference_state_hash: {
                if p.reference_state_hash.len() != 32 {
                    return Err(DsmError::SerializationError(
                        "Invalid reference state hash length".into(),
                    ));
                }
                let mut h = [0u8; 32];
                h.copy_from_slice(&p.reference_state_hash);
                h
            },
            entry_header: p.entry_header.and_then(|eh| {
                if eh.len() == 80 {
                    let mut hdr = [0u8; 80];
                    hdr.copy_from_slice(&eh);
                    Some(hdr)
                } else {
                    None
                }
            }),
        })
    }
}

impl From<&LimboVault> for crate::types::proto::LimboVaultProto {
    fn from(v: &LimboVault) -> Self {
        crate::types::proto::LimboVaultProto {
            id: v.id.clone(),
            created_at_state: v.created_at_state,
            creator_public_key: v.creator_public_key.clone(),
            fulfillment_condition: Some((&v.fulfillment_condition).into()),
            intended_recipient: v.intended_recipient.clone(),
            state: None, // domain-only
            content_type: v.content_type.clone(),
            encrypted_content: Some(crate::types::proto::EncryptedContentProto {
                encapsulated_key: v.encrypted_content.encapsulated_key.clone(),
                encrypted_data: v.encrypted_content.encrypted_data.clone(),
                nonce: v.encrypted_content.nonce.clone(),
                aad: v.encrypted_content.aad.clone(),
            }),
            content_commitment: v.content_commitment.to_bytes(),
            parameters_hash: v.parameters_hash.clone(),
            creator_signature: v.creator_signature.clone(),
            verification_positions: v
                .verification_positions
                .iter()
                .map(encode_position)
                .collect(),
            reference_state_hash: v.reference_state_hash.to_vec(),
            entry_header: v.entry_header.map(|eh| eh.to_vec()),
        }
    }
}

/* -------------------- Proto conversions for FulfillmentMechanism ------------- */

impl From<&FulfillmentMechanism> for crate::types::proto::FulfillmentMechanism {
    fn from(f: &FulfillmentMechanism) -> Self {
        use crate::types::proto;
        use crate::types::proto::fulfillment_mechanism;
        match f {
            FulfillmentMechanism::Payment {
                amount,
                token_id,
                recipient,
                verification_state,
            } => proto::FulfillmentMechanism {
                kind: Some(fulfillment_mechanism::Kind::Payment(proto::Payment {
                    amount: *amount,
                    token_id: token_id.clone(),
                    recipient: recipient.clone(),
                    verification_state: verification_state.clone(),
                })),
            },
            FulfillmentMechanism::CryptoCondition {
                condition_hash,
                public_params,
            } => proto::FulfillmentMechanism {
                kind: Some(fulfillment_mechanism::Kind::CryptoCondition(
                    proto::CryptoCondition {
                        condition_hash: condition_hash.clone(),
                        public_params: public_params.clone(),
                    },
                )),
            },
            FulfillmentMechanism::MultiSignature {
                public_keys,
                threshold,
            } => proto::FulfillmentMechanism {
                kind: Some(fulfillment_mechanism::Kind::MultiSignature(
                    proto::MultiSignature {
                        public_keys: public_keys.clone(),
                        threshold: *threshold as u32,
                    },
                )),
            },
            FulfillmentMechanism::StateReference {
                reference_states,
                parameters,
            } => proto::FulfillmentMechanism {
                kind: Some(fulfillment_mechanism::Kind::StateReference(
                    proto::StateReference {
                        reference_states: reference_states.clone(),
                        parameters: parameters.clone(),
                    },
                )),
            },
            FulfillmentMechanism::RandomWalkVerification {
                verification_key,
                statement,
            } => proto::FulfillmentMechanism {
                kind: Some(fulfillment_mechanism::Kind::RandomWalkVerification(
                    proto::RandomWalkVerification {
                        verification_key: verification_key.clone(),
                        statement: statement.clone(),
                    },
                )),
            },
            FulfillmentMechanism::BitcoinHTLC {
                hash_lock,
                refund_hash_lock,
                refund_iterations,
                bitcoin_pubkey,
                expected_btc_amount_sats,
                network,
                min_confirmations,
            } => proto::FulfillmentMechanism {
                kind: Some(fulfillment_mechanism::Kind::BitcoinHtlc(
                    proto::BitcoinHtlc {
                        hash_lock: hash_lock.to_vec(),
                        refund_hash_lock: refund_hash_lock.to_vec(),
                        refund_iterations: *refund_iterations,
                        bitcoin_pubkey: bitcoin_pubkey.clone(),
                        expected_btc_amount_sats: *expected_btc_amount_sats,
                        network: *network,
                        min_confirmations: *min_confirmations,
                    },
                )),
            },
            FulfillmentMechanism::And(conds) => {
                let inner: Vec<_> = conds.iter().map(|c| c.into()).collect();
                proto::FulfillmentMechanism {
                    kind: Some(fulfillment_mechanism::Kind::And(proto::And {
                        conditions: inner,
                    })),
                }
            }
            FulfillmentMechanism::Or(conds) => {
                let inner: Vec<_> = conds.iter().map(|c| c.into()).collect();
                proto::FulfillmentMechanism {
                    kind: Some(fulfillment_mechanism::Kind::Or(proto::Or {
                        conditions: inner,
                    })),
                }
            }
        }
    }
}

impl TryFrom<crate::types::proto::FulfillmentMechanism> for FulfillmentMechanism {
    type Error = DsmError;

    fn try_from(p: crate::types::proto::FulfillmentMechanism) -> Result<Self, Self::Error> {
        use crate::types::proto::fulfillment_mechanism::Kind;
        let kind = p.kind.ok_or_else(|| {
            DsmError::serialization_error(
                "fulfillment",
                "missing_kind",
                None::<&str>,
                None::<core::convert::Infallible>,
            )
        })?;
        Ok(match kind {
            Kind::Payment(pay) => FulfillmentMechanism::Payment {
                amount: pay.amount,
                token_id: pay.token_id,
                recipient: pay.recipient,
                verification_state: pay.verification_state,
            },
            Kind::CryptoCondition(cc) => FulfillmentMechanism::CryptoCondition {
                condition_hash: cc.condition_hash,
                public_params: cc.public_params,
            },
            Kind::MultiSignature(ms) => FulfillmentMechanism::MultiSignature {
                public_keys: ms.public_keys,
                threshold: ms.threshold as usize,
            },
            Kind::StateReference(sr) => FulfillmentMechanism::StateReference {
                reference_states: sr.reference_states,
                parameters: sr.parameters,
            },
            Kind::RandomWalkVerification(rw) => FulfillmentMechanism::RandomWalkVerification {
                verification_key: rw.verification_key,
                statement: rw.statement,
            },
            Kind::BitcoinHtlc(btc) => {
                if btc.hash_lock.len() != 32 {
                    return Err(DsmError::serialization_error(
                        "BitcoinHTLC",
                        "hash_lock must be 32 bytes",
                        None::<&str>,
                        None::<core::convert::Infallible>,
                    ));
                }
                let mut hash_lock = [0u8; 32];
                hash_lock.copy_from_slice(&btc.hash_lock);
                let mut refund_hash_lock = [0u8; 32];
                if btc.refund_hash_lock.len() >= 32 {
                    refund_hash_lock.copy_from_slice(&btc.refund_hash_lock[..32]);
                }
                FulfillmentMechanism::BitcoinHTLC {
                    hash_lock,
                    refund_hash_lock,
                    refund_iterations: btc.refund_iterations,
                    bitcoin_pubkey: btc.bitcoin_pubkey,
                    expected_btc_amount_sats: btc.expected_btc_amount_sats,
                    network: btc.network,
                    min_confirmations: btc.min_confirmations,
                }
            }
            Kind::And(a) => {
                let mut out = Vec::with_capacity(a.conditions.len());
                for c in a.conditions {
                    out.push(FulfillmentMechanism::try_from(c)?);
                }
                FulfillmentMechanism::And(out)
            }
            Kind::Or(o) => {
                let mut out = Vec::with_capacity(o.conditions.len());
                for c in o.conditions {
                    out.push(FulfillmentMechanism::try_from(c)?);
                }
                FulfillmentMechanism::Or(out)
            }
        })
    }
}

/* --------------------------------- Builders --------------------------------- */

impl LimboVault {
    /// Rehydrate and verify a vault from its decentralized storage post.
    pub fn from_vault_post(post: &VaultPost) -> Result<Self, DsmError> {
        // Decode proto
        let proto = crate::types::proto::LimboVaultProto::decode(post.vault_data.as_ref())
            .map_err(|e| {
                DsmError::serialization_error("LimboVaultProto", "decode", None::<&str>, Some(e))
            })?;

        let vault = Self::try_from(proto)?;

        // Parameter commitment matches
        if !secure_eq(&vault.parameters_hash, &post.commitment_hash) {
            return Err(DsmError::invalid_operation("commitment hash mismatch"));
        }

        // Vault ID matches
        if vault.id != post.vault_id {
            return Err(DsmError::invalid_operation("vault id mismatch"));
        }

        // Creator label matches (decimal label of creator public key)
        let expected_creator = decimal_label("pk-", &vault.creator_public_key);
        if post.creator_id != expected_creator {
            return Err(DsmError::invalid_operation("creator label mismatch"));
        }

        // Signature over parameters
        if !sphincs::sphincs_verify(
            &vault.creator_public_key,
            &vault.parameters_hash,
            &vault.creator_signature,
        )? {
            return Err(DsmError::invalid_operation("invalid creator signature"));
        }

        Ok(vault)
    }

    /// Construct a minimal `LimboVault` from only the essential fields needed for
    /// dBTC exit operations. Used when loading vaults from storage nodes where only
    /// the `LimboVaultProto` is available, carrying the fulfillment condition and
    /// operational data — no `encrypted_content`, `content_commitment`, or creator
    /// signature (since dBTC vaults use the Bitcoin HTLC as the sole exit mechanism,
    /// not Kyber-based content decryption).
    ///
    /// The vault starts in `Limbo` state. Fields like `encrypted_content`,
    /// `content_commitment`, and `creator_signature` are set to dummy/empty values.
    /// This is safe because:
    /// - `unlock()` and `activate()` only need the `fulfillment_condition` + state
    /// - `claim()` is never called for dBTC vaults (exit goes through `draw_tap`)
    /// - `verify_fulfillment()` only checks the fulfillment condition
    pub fn new_minimal(
        id: String,
        fulfillment_condition: FulfillmentMechanism,
        reference_state_hash: [u8; 32],
    ) -> Self {
        Self {
            id,
            created_at_state: 0,
            creator_public_key: Vec::new(),
            fulfillment_condition,
            intended_recipient: None,
            state: VaultState::Limbo,
            content_type: "application/dsm-dbtc-mint".to_string(),
            encrypted_content: EncryptedContent {
                encapsulated_key: Vec::new(),
                encrypted_data: Vec::new(),
                nonce: Vec::new(),
                aad: Vec::new(),
            },
            content_commitment: PedersenCommitment::default(),
            parameters_hash: Vec::new(),
            creator_signature: Vec::new(),
            verification_positions: Vec::new(),
            reference_state_hash,
            entry_header: None,
        }
    }

    /// Create a vault anchored to a reference state.
    /// Uses Kyber KEM + AES-GCM and binds all parameters via BLAKE3 + SPHINCS+.
    pub fn new(
        creator_keypair: (&[u8], &[u8]), // (SPHINCS public, SPHINCS private)
        fulfillment_condition: FulfillmentMechanism,
        content: &[u8],
        content_type: &str,
        intended_recipient: Option<Vec<u8>>, // Kyber public key for access control (if Some)
        encryption_public_key: &[u8],        // Kyber public key for content encryption (required)
        reference_state: &State,
    ) -> Result<Self, DsmError> {
        let state_number = reference_state.state_number;
        let ref_hash = if reference_state.hash == [0u8; 32] {
            reference_state.compute_hash()?
        } else {
            reference_state.hash
        };

        // Fix #2: Encode fulfillment condition early so its domain-hash can be bound
        // into id_material. This prevents two vaults with identical creator/state/content
        // but different fulfillment conditions (e.g. different HTLCs) from colliding on vault_id.
        let fm_proto: crate::types::proto::FulfillmentMechanism = (&fulfillment_condition).into();
        let mut fm_bytes = Vec::new();
        fm_proto.encode(&mut fm_bytes).map_err(|e| {
            DsmError::serialization_error("FulfillmentMechanism", "encode", None::<&str>, Some(e))
        })?;

        // Deterministic ID label (decimal) from (creator_pk || state# || H(content) || H(fulfillment))
        let id_material = concat_bytes(&[
            creator_keypair.0,
            &state_number.to_le_bytes(),
            domain_hash("DSM/dlv-content", content).as_bytes(),
            domain_hash("DSM/dlv-fulfillment", &fm_bytes).as_bytes(),
        ]);
        let vault_id = decimal_label("vault-", &id_material);

        // Recipient KEM — always use the explicit Kyber encryption key
        let (shared_secret, encapsulated_key) = kyber::kyber_encapsulate(encryption_public_key)
            .map_err(|e| DsmError::crypto("kyber_encapsulate", Some(e)))?;

        // Nonce and AAD (deterministic; no clocks)
        let nonce_seed = concat_bytes(&[
            domain_hash("DSM/dlv-vault-id", &id_material).as_bytes(),
            &state_number.to_le_bytes(),
        ]);
        let nonce = domain_hash_bytes("DSM/dlv-nonce", &nonce_seed)[0..12].to_vec();

        let mut aad = Vec::new();
        aad.extend_from_slice(creator_keypair.0);
        aad.extend_from_slice(vault_id.as_bytes());
        aad.extend_from_slice(&state_number.to_le_bytes());
        aad.extend_from_slice(&ref_hash);

        // Symmetric key for AES-GCM: bind KEM secret + aad + content hash
        let sym_key = domain_hash_bytes(
            "DSM/dlv-sym-key",
            &concat_bytes(&[
                &shared_secret,
                &aad,
                domain_hash("DSM/dlv-content", content).as_bytes(),
            ]),
        )
        .to_vec();

        let encrypted_data = kyber::aes_encrypt(&sym_key, &nonce, content)
            .map_err(|e| DsmError::crypto("aes_encrypt", Some(e)))?;

        // Pedersen commitment to content
        let params = PedersenParams::new(SecurityLevel::Standard128)?;
        let commitment = PedersenCommitment::commit(content, &params)?;

        // Parameters hash (protobuf of fulfillment + core fields)
        let mut parameters = Vec::new();
        parameters.extend_from_slice(creator_keypair.0);
        parameters.extend_from_slice(vault_id.as_bytes());
        parameters.extend_from_slice(&state_number.to_le_bytes());
        parameters.extend_from_slice(&ref_hash);

        // fm_bytes already computed above for id_material; reuse here.
        parameters.extend_from_slice(&fm_bytes);

        if let Some(rec) = &intended_recipient {
            parameters.extend_from_slice(rec);
        }
        parameters.extend_from_slice(&commitment.to_bytes());

        let parameters_hash = domain_hash_bytes("DSM/dlv-params", &parameters).to_vec();
        let creator_signature = sphincs::sphincs_sign(creator_keypair.1, &parameters_hash)
            .map_err(|e| DsmError::crypto("sphincs_sign", Some(e)))?;

        // Random-walk positions
        let seed = generate_seed(
            &domain_hash("DSM/dlv-params", &parameters),
            vault_id.as_bytes(),
            None,
        );
        let verification_positions = generate_positions(
            &seed,
            None::<crate::core::state_machine::random_walk::algorithms::RandomWalkConfig>,
        )?;

        Ok(LimboVault {
            id: vault_id,
            created_at_state: state_number,
            creator_public_key: creator_keypair.0.to_vec(),
            fulfillment_condition,
            intended_recipient,
            state: VaultState::Limbo,
            content_type: content_type.to_string(),
            encrypted_content: EncryptedContent {
                encapsulated_key,
                encrypted_data,
                nonce,
                aad,
            },
            content_commitment: commitment,
            parameters_hash,
            creator_signature,
            verification_positions,
            reference_state_hash: ref_hash,
            entry_header: None,
        })
    }

    /// Create from an existing state (anchors also to state entropy).
    pub fn from_state(
        state: &State,
        creator_keypair: (&[u8], &[u8]),
        fulfillment_condition: FulfillmentMechanism,
        content: &[u8],
        content_type: &str,
        intended_recipient: Option<Vec<u8>>,
        encryption_public_key: &[u8],
    ) -> Result<Self, DsmError> {
        let state_number = state.state_number;
        // Ensure we bind to a real state root (mirrors `new(...)`)
        let ref_hash = if state.hash == [0u8; 32] {
            state.compute_hash()?
        } else {
            state.hash
        };

        let id_material = concat_bytes(&[
            creator_keypair.0,
            &state_number.to_le_bytes(),
            &state.entropy,
            domain_hash("DSM/dlv-content", content).as_bytes(),
        ]);
        let vault_id = decimal_label("state-vault-", &id_material);

        let (shared_secret, encapsulated_key) = kyber::kyber_encapsulate(encryption_public_key)
            .map_err(|e| DsmError::crypto("kyber_encapsulate", Some(e)))?;

        let nonce_seed = concat_bytes(&[&state.entropy, &state_number.to_le_bytes()]);
        let nonce = domain_hash_bytes("DSM/dlv-nonce", &nonce_seed)[0..12].to_vec();

        let mut aad = Vec::new();
        aad.extend_from_slice(creator_keypair.0);
        aad.extend_from_slice(vault_id.as_bytes());
        aad.extend_from_slice(&state_number.to_le_bytes());
        aad.extend_from_slice(&ref_hash);

        let sym_key = domain_hash_bytes(
            "DSM/dlv-sym-key",
            &concat_bytes(&[
                &shared_secret,
                domain_hash("DSM/dlv-content", content).as_bytes(),
                &aad,
            ]),
        )
        .to_vec();

        let encrypted_data = kyber::aes_encrypt(&sym_key, &nonce, content)
            .map_err(|e| DsmError::crypto("aes_encrypt", Some(e)))?;

        let params = PedersenParams::new(SecurityLevel::Standard128)?;
        let commitment = PedersenCommitment::commit(content, &params)?;

        let mut parameters = Vec::new();
        parameters.extend_from_slice(creator_keypair.0);
        parameters.extend_from_slice(vault_id.as_bytes());
        parameters.extend_from_slice(&state_number.to_le_bytes());
        parameters.extend_from_slice(&ref_hash);

        let fm_proto: crate::types::proto::FulfillmentMechanism = (&fulfillment_condition).into();
        let mut fm_bytes = Vec::new();
        fm_proto.encode(&mut fm_bytes).map_err(|e| {
            DsmError::serialization_error("FulfillmentMechanism", "encode", None::<&str>, Some(e))
        })?;
        parameters.extend_from_slice(&fm_bytes);

        if let Some(rec) = &intended_recipient {
            parameters.extend_from_slice(rec);
        }
        parameters.extend_from_slice(&commitment.to_bytes());

        let parameters_hash = domain_hash_bytes("DSM/dlv-params", &parameters).to_vec();
        let creator_signature = sphincs::sphincs_sign(creator_keypair.1, &parameters_hash)
            .map_err(|e| DsmError::crypto("sphincs_sign", Some(e)))?;

        let seed = domain_hash(
            "DSM/dlv-seed",
            &concat_bytes(&[&parameters_hash, &state.entropy]),
        );
        let verification_positions = generate_positions(
            &seed,
            None::<crate::core::state_machine::random_walk::algorithms::RandomWalkConfig>,
        )?;

        Ok(LimboVault {
            id: vault_id,
            created_at_state: state_number,
            creator_public_key: creator_keypair.0.to_vec(),
            fulfillment_condition,
            intended_recipient,
            state: VaultState::Limbo,
            content_type: content_type.to_string(),
            encrypted_content: EncryptedContent {
                encapsulated_key,
                encrypted_data,
                nonce,
                aad,
            },
            content_commitment: commitment,
            parameters_hash,
            creator_signature,
            verification_positions,
            reference_state_hash: ref_hash,
            entry_header: None,
        })
    }
}

/* --------------------------------- Verify API -------------------------------- */

impl LimboVault {
    /// Verify parameters and signature deterministically.
    pub fn verify(&self) -> Result<bool, DsmError> {
        let mut parameters = Vec::new();
        parameters.extend_from_slice(&self.creator_public_key);
        parameters.extend_from_slice(self.id.as_bytes());
        parameters.extend_from_slice(&self.created_at_state.to_le_bytes());
        parameters.extend_from_slice(&self.reference_state_hash);

        let fm_proto: crate::types::proto::FulfillmentMechanism =
            (&self.fulfillment_condition).into();
        let mut fm_bytes = Vec::new();
        fm_proto.encode(&mut fm_bytes).map_err(|e| {
            DsmError::serialization_error("FulfillmentMechanism", "encode", None::<&str>, Some(e))
        })?;
        parameters.extend_from_slice(&fm_bytes);

        if let Some(rec) = &self.intended_recipient {
            parameters.extend_from_slice(rec);
        }
        parameters.extend_from_slice(&self.content_commitment.to_bytes());

        let computed = domain_hash_bytes("DSM/dlv-params", &parameters).to_vec();
        if !secure_eq(&computed, &self.parameters_hash) {
            return Ok(false);
        }

        let sig_ok = sphincs::sphincs_verify(
            &self.creator_public_key,
            &self.parameters_hash,
            &self.creator_signature,
        )?;
        Ok(sig_ok)
    }

    /// Check that `proof` fulfills `self.fulfillment_condition` against `reference_state`.
    pub fn verify_fulfillment(
        &self,
        proof: &FulfillmentProof,
        reference_state: &State,
    ) -> Result<bool, DsmError> {
        match (&self.fulfillment_condition, proof) {
            // Payment: verify state transition protobuf parameters + Merkle inclusion into verification_state root.
            (
                FulfillmentMechanism::Payment {
                    amount,
                    token_id,
                    recipient,
                    verification_state,
                },
                proof_ref @ FulfillmentProof::PaymentProof {
                    state_transition,
                    merkle_proof,
                    ..
                },
            ) => {
                let result = self.verify_payment_proof(
                    *amount,
                    token_id,
                    recipient,
                    verification_state,
                    state_transition,
                    merkle_proof,
                )?;
                if result && extract_sigma_from_proof(proof_ref).is_none() {
                    return Err(DsmError::invalid_operation(
                        "DLV unlock requires stitched_receipt_sigma (§7.3)",
                    ));
                }
                Ok(result)
            }

            // Crypto condition: hash(solution || public_params) must match condition_hash
            (
                FulfillmentMechanism::CryptoCondition {
                    condition_hash,
                    public_params,
                },
                proof_ref @ FulfillmentProof::CryptoConditionProof { solution, .. },
            ) => {
                let h = domain_hash(
                    "DSM/dlv-crypto-cond",
                    &concat_bytes(&[solution, public_params]),
                );
                let result = secure_eq(h.as_bytes(), condition_hash);
                if result && extract_sigma_from_proof(proof_ref).is_none() {
                    return Err(DsmError::invalid_operation(
                        "DLV unlock requires stitched_receipt_sigma (§7.3)",
                    ));
                }
                Ok(result)
            }

            // Multi-sig: threshold of unique known public keys verifying over signed_data
            (
                FulfillmentMechanism::MultiSignature {
                    public_keys,
                    threshold,
                },
                proof_ref @ FulfillmentProof::MultiSignatureProof {
                    signatures,
                    signed_data,
                    ..
                },
            ) => {
                if signatures.len() < *threshold {
                    return Ok(false);
                }
                let keyset: HashSet<&Vec<u8>> = public_keys.iter().collect();
                let mut ok = 0usize;
                for (pk, sig) in signatures {
                    if !keyset.contains(pk) {
                        continue;
                    }
                    if sphincs::sphincs_verify(pk, signed_data, sig)? {
                        ok = ok.saturating_add(1);
                    }
                }
                let result = ok >= *threshold;
                if result && extract_sigma_from_proof(proof_ref).is_none() {
                    return Err(DsmError::invalid_operation(
                        "DLV unlock requires stitched_receipt_sigma (§7.3)",
                    ));
                }
                Ok(result)
            }

            // Random-walk: regenerate positions from seed(verification_key||statement), compare, then verify hash-chain.
            (
                FulfillmentMechanism::RandomWalkVerification {
                    verification_key,
                    statement,
                },
                proof_ref @ FulfillmentProof::RandomWalkProof {
                    positions,
                    hash_chain_proof,
                    ..
                },
            ) => {
                let seed = domain_hash(
                    "DSM/dlv-rw-seed",
                    &concat_bytes(&[verification_key, statement.as_bytes()]),
                );
                let expected = generate_positions(
                    &seed,
                    None::<crate::core::state_machine::random_walk::algorithms::RandomWalkConfig>,
                )?;
                if positions.len() != expected.len() {
                    return Ok(false);
                }
                for (a, b) in positions.iter().zip(expected.iter()) {
                    if a.0.len() != b.0.len() {
                        return Ok(false);
                    }
                    for (x, y) in a.0.iter().zip(b.0.iter()) {
                        if x != y {
                            return Ok(false);
                        }
                    }
                }
                let result = self.verify_hash_chain(hash_chain_proof, reference_state)?;
                if result && extract_sigma_from_proof(proof_ref).is_none() {
                    return Err(DsmError::invalid_operation(
                        "DLV unlock requires stitched_receipt_sigma (§7.3)",
                    ));
                }
                Ok(result)
            }

            // Bitcoin HTLC: SHA256(preimage) == hash_lock + SPV proof of Bitcoin payment + header chain
            // dBTC paper §6.4/§12.1.3: confirmation depth is enforced, not advisory
            (
                FulfillmentMechanism::BitcoinHTLC {
                    hash_lock,
                    refund_hash_lock: _,
                    bitcoin_pubkey,
                    expected_btc_amount_sats,
                    refund_iterations: _,
                    network,
                    min_confirmations,
                },
                FulfillmentProof::BitcoinHTLCProof {
                    preimage,
                    bitcoin_txid,
                    bitcoin_tx_raw,
                    spv_proof,
                    expected_script_pubkey,
                    block_header,
                    header_chain,
                    stitched_receipt,
                    stitched_receipt_sigma,
                },
            ) => self.verify_bitcoin_htlc(
                hash_lock,
                bitcoin_pubkey,
                *expected_btc_amount_sats,
                preimage,
                bitcoin_txid,
                bitcoin_tx_raw,
                spv_proof,
                expected_script_pubkey,
                block_header.as_ref(),
                header_chain,
                *network,
                *min_confirmations,
                stitched_receipt.as_ref(),
                *stitched_receipt_sigma,
            ),

            // Compound AND/OR
            (FulfillmentMechanism::And(conds), FulfillmentProof::CompoundProof(proofs)) => {
                if conds.len() != proofs.len() {
                    return Ok(false);
                }
                for (c, p) in conds.iter().zip(proofs.iter()) {
                    let mut tmp = self.clone();
                    tmp.fulfillment_condition = c.clone();
                    if !tmp.verify_fulfillment(p, reference_state)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            (FulfillmentMechanism::Or(conds), FulfillmentProof::CompoundProof(proofs)) => {
                if proofs.is_empty() {
                    return Ok(false);
                }
                for p in proofs {
                    for c in conds {
                        let mut tmp = self.clone();
                        tmp.fulfillment_condition = c.clone();
                        if tmp.verify_fulfillment(p, reference_state)? {
                            return Ok(true);
                        }
                    }
                }
                Ok(false)
            }

            _ => Ok(false),
        }
    }

    // verify_state_reference removed: unused internal helper

    fn verify_payment_proof(
        &self,
        amount: u64,
        token_id: &str,
        recipient: &str,
        verification_state: &[u8],
        state_transition: &[u8],
        merkle_proof: &[u8],
    ) -> Result<bool, DsmError> {
        // Decode transition
        let tr =
            crate::types::proto::StateTransitionProto::decode(state_transition).map_err(|e| {
                DsmError::serialization_error(
                    "StateTransitionProto",
                    "decode",
                    None::<&str>,
                    Some(e),
                )
            })?;

        // Recipient: accept either exact bytes match to label field or decimal label equivalence
        let label = decimal_label("pk-", &tr.counterparty_id);
        if !(recipient.as_bytes() == tr.counterparty_id.as_slice() || recipient == label) {
            return Ok(false);
        }

        // Direction should be "send"
        if !tr.transaction_direction.eq_ignore_ascii_case("send") {
            return Ok(false);
        }

        // Find token entry with -amount delta (i128 LE)
        let mut ok_token = false;
        for e in tr.balance_delta.iter() {
            if e.token_id == token_id {
                if let Some(delta) = &e.delta {
                    if delta.le.len() == 16 {
                        let mut a = [0u8; 16];
                        a.copy_from_slice(&delta.le);
                        let val = i128::from_le_bytes(a);
                        if val == -(amount as i128) {
                            ok_token = true;
                            break;
                        }
                    }
                }
            }
        }
        if !ok_token {
            return Ok(false);
        }

        // Hash transition (protobuf) -> Blake3 -> compare via Merkle path
        let mut hasher = dsm_domain_hasher("DSM/dlv-merkle");
        hasher.update(state_transition);
        let mut cur = hasher.finalize().as_bytes().to_vec();

        if merkle_proof.len() < 4 {
            return Ok(false);
        }
        let path_len = u32::from_le_bytes([
            merkle_proof[0],
            merkle_proof[1],
            merkle_proof[2],
            merkle_proof[3],
        ]) as usize;
        if merkle_proof.len() < 4 + 32 * path_len {
            return Ok(false);
        }
        let path = &merkle_proof[4..4 + 32 * path_len];

        for i in 0..path_len {
            let sib = &path[i * 32..(i + 1) * 32];
            let mut hasher = dsm_domain_hasher("DSM/dlv-merkle");
            hasher.update(&cur);
            hasher.update(sib);
            cur = hasher.finalize().as_bytes().to_vec();
        }

        let expected_root = domain_hash_bytes("DSM/dlv-merkle", verification_state).to_vec();
        Ok(secure_eq(&cur, &expected_root))
    }

    /// Verify a Bitcoin HTLC proof (dBTC paper §6.4.5 SPV Verification Stack):
    /// 1. SHA256(preimage) == hash_lock
    /// 2. SPV proof validates txid inclusion in block header's Merkle root
    /// 3. Block header meets minimum proof-of-work
    /// 4. Header chain connects block to a known checkpoint (mainnet only)
    /// 5. Confirmation depth >= min_confirmations (dBTC paper §6.4.1/§6.4.3, §12.1.3)
    #[allow(clippy::too_many_arguments)]
    fn verify_bitcoin_htlc(
        &self,
        hash_lock: &[u8; 32],
        bitcoin_pubkey: &[u8],
        expected_btc_amount_sats: u64,
        preimage: &[u8],
        bitcoin_txid: &[u8; 32],
        bitcoin_tx_raw: &[u8],
        spv_proof_bytes: &[u8],
        expected_script_pubkey: &[u8],
        block_header: &[u8; 80],
        header_chain: &[[u8; 80]],
        network: u32,
        min_confirmations: u64,
        stitched_receipt: Option<&Vec<u8>>,
        stitched_receipt_sigma: Option<[u8; 32]>,
    ) -> Result<bool, DsmError> {
        use bitcoin::hashes::Hash as _;
        use crate::bitcoin::spv::{
            SpvProof, extract_merkle_root, verify_block_header_work, verify_spv_proof,
        };
        use crate::bitcoin::header_chain::verify_header_chain;
        use crate::bitcoin::types::BitcoinNetwork;
        use crate::bitcoin::{BitcoinSettlementObservation, RustVerifierAcceptedEvidence};

        // Basic policy-bound sanity checks.
        if bitcoin_pubkey.len() != 33 {
            return Err(DsmError::invalid_operation(format!(
                "Invalid Bitcoin pubkey length in HTLC condition: {}",
                bitcoin_pubkey.len()
            )));
        }
        if expected_btc_amount_sats == 0 {
            return Err(DsmError::invalid_operation(
                "Invalid expected BTC amount in HTLC condition: 0",
            ));
        }

        // 1. Deep-anchor depth check (dBTC paper §6.4, Invariants 10-11):
        //    Derive confirmation depth from the PoW-validated header chain length.
        //    For test networks (empty header_chain, no checkpoints): depth defaults to 1.
        //    For mainnet: depth = header_chain.len() + 1 (chain from checkpoint to block, inclusive).
        let confirmations = (header_chain.len() as u64) + 1;
        if confirmations < min_confirmations {
            return Err(DsmError::invalid_operation(format!(
                "Insufficient confirmation depth: {} < {} required (provide more header chain headers)",
                confirmations, min_confirmations
            )));
        }

        // §18.4: DLV unlocks require canonical protocol-transition bytes + commitment.
        let sigma = stitched_receipt_sigma.ok_or_else(|| {
            DsmError::invalid_operation("DLV unlock requires stitched_receipt_sigma (§18.4)")
        })?;
        let receipt_bytes = stitched_receipt.ok_or_else(|| {
            DsmError::invalid_operation(
                "DLV unlock requires canonical protocol transition bytes (§18.4)",
            )
        })?;

        let computed_sigma =
            crate::crypto::blake3::domain_hash_bytes("DSM/protocol-transition", receipt_bytes);
        if !secure_eq(&computed_sigma, &sigma) {
            return Err(DsmError::invalid_operation(
                "stitched_receipt_sigma does not match canonical protocol transition commitment",
            ));
        }

        // 2. Verify hash-lock: SHA256(preimage) must equal hash_lock
        let computed = crate::bitcoin::script::sha256_hash_lock(preimage);
        if !secure_eq(&computed, hash_lock) {
            log::error!("verify_bitcoin_htlc failed: hash_lock mismatch");
            return Ok(false);
        }

        // 3. Decode and verify SPV proof
        let spv_proof = SpvProof::from_bytes(spv_proof_bytes)
            .map_err(|e| DsmError::invalid_operation(format!("Invalid SPV proof: {e}")))?;

        // 4. Decode raw transaction, check txid consistency, and verify expected output.
        if bitcoin_tx_raw.is_empty() {
            return Err(DsmError::invalid_operation(
                "Missing raw Bitcoin transaction bytes for HTLC output verification",
            ));
        }
        let tx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize(bitcoin_tx_raw)
            .map_err(|e| {
                DsmError::invalid_operation(format!("Invalid raw Bitcoin transaction bytes: {e}"))
            })?;
        let computed_txid = tx.compute_txid();
        let proof_txid_le = bitcoin::Txid::from_byte_array(*bitcoin_txid);
        let mut proof_txid_be_bytes = *bitcoin_txid;
        proof_txid_be_bytes.reverse();
        let proof_txid_be = bitcoin::Txid::from_byte_array(proof_txid_be_bytes);
        if computed_txid != proof_txid_le && computed_txid != proof_txid_be {
            return Err(DsmError::invalid_operation(
                "Raw Bitcoin transaction txid does not match proof txid",
            ));
        }

        let has_matching_output = tx.output.iter().any(|out| {
            let amount_ok = out.value.to_sat() == expected_btc_amount_sats;
            if expected_script_pubkey.is_empty() {
                return amount_ok;
            }
            amount_ok && out.script_pubkey.as_bytes() == expected_script_pubkey
        });
        if !has_matching_output {
            return Err(DsmError::invalid_operation(
                "Bitcoin transaction does not contain expected HTLC output (amount/script)",
            ));
        }

        // 5. Verify txid is in the block and block meets PoW.
        // These map directly to the `spvValid` and `powValid` fields in the
        // formal `RustVerifierAccepted` predicate.
        let merkle_root = extract_merkle_root(block_header);
        let spv_inclusion_valid = verify_spv_proof(bitcoin_txid, &merkle_root, &spv_proof);
        if !spv_inclusion_valid {
            log::error!("verify_bitcoin_htlc failed: verify_spv_proof failed");
            return Ok(false);
        }
        let pow_valid = verify_block_header_work(block_header);
        if !pow_valid {
            log::error!("verify_bitcoin_htlc failed: verify_block_header_work failed");
            return Ok(false);
        }

        // 6. Verify header chain connects block to a known checkpoint
        let btc_network = BitcoinNetwork::from_u32(network);
        let header_chain_ok = verify_header_chain(block_header, header_chain, btc_network)?;
        if !header_chain_ok {
            log::error!("verify_bitcoin_htlc failed: verify_header_chain failed");
            return Ok(false);
        }
        let checkpoint_rooted = matches!(btc_network, BitcoinNetwork::Mainnet) && header_chain_ok;

        // 7. Entry-header anchor check (dBTC paper §12.2.3, Invariant 19):
        //    If this vault has a cached entry header (from BTC→dBTC entry),
        //    verify the exit block chains forward from it.
        let mut same_chain_anchored = true;
        if let Some(ref entry_hdr) = self.entry_header {
            use crate::bitcoin::header_chain::verify_entry_anchor;
            same_chain_anchored =
                verify_entry_anchor(entry_hdr, block_header, header_chain, btc_network)?;
            if !same_chain_anchored {
                return Err(DsmError::invalid_operation(
                    "Exit block does not chain from entry header anchor (Invariant 19)",
                ));
            }
        }

        let verifier_evidence = RustVerifierAcceptedEvidence {
            observation: BitcoinSettlementObservation {
                network: btc_network,
                bitcoin_spend_observed: true,
                confirmation_depth: confirmations,
                min_confirmations,
            },
            spv_inclusion_valid,
            pow_valid,
            checkpoint_rooted,
            same_chain_anchored,
        };

        if !verifier_evidence.runtime_accepts() {
            return Ok(false);
        }

        debug_assert!(
            !matches!(btc_network, BitcoinNetwork::Mainnet)
                || verifier_evidence.runtime_acceptance_implies_formal_mainnet(),
            "mainnet dBTC acceptance must imply the formal RustVerifierAccepted predicate"
        );

        Ok(true)
    }

    fn verify_hash_chain(&self, proof: &[u8], reference_state: &State) -> Result<bool, DsmError> {
        // Layout: [len u32][state_numbers u64 * len][state_hashes 32 * len]
        if proof.len() < 4 {
            return Ok(false);
        }
        let len = u32::from_le_bytes([proof[0], proof[1], proof[2], proof[3]]) as usize;
        let need = 4 + len * 8 + len * 32;
        if proof.len() < need {
            return Ok(false);
        }

        let mut off = 4usize;
        let mut nums = Vec::with_capacity(len);
        for _ in 0..len {
            if off + 8 > proof.len() {
                return Ok(false);
            }
            let n = u64::from_le_bytes([
                proof[off],
                proof[off + 1],
                proof[off + 2],
                proof[off + 3],
                proof[off + 4],
                proof[off + 5],
                proof[off + 6],
                proof[off + 7],
            ]);
            nums.push(n);
            off += 8;
        }
        let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(len);
        for _ in 0..len {
            if off + 32 > proof.len() {
                return Ok(false);
            }
            let mut h = [0u8; 32];
            h.copy_from_slice(&proof[off..off + 32]);
            hashes.push(h);
            off += 32;
        }
        if len == 0 {
            return Ok(false);
        }

        // Monotonic +1
        for i in 1..nums.len() {
            if nums[i] != nums[i - 1].saturating_add(1) {
                return Ok(false);
            }
        }

        // Linkage check (strict structural check)
        for i in 0..(hashes.len() - 1) {
            let mut hasher = dsm_domain_hasher("DSM/dlv-chain-link");
            hasher.update(&hashes[i]);
            hasher.update(&nums[i + 1].to_le_bytes());
            let expected = hasher.finalize();

            if !secure_eq(expected.as_bytes(), &hashes[i + 1]) {
                // Strict validation: chain must be unbroken
                return Ok(false);
            }
        }

        let final_hash = &hashes[hashes.len() - 1];
        let refh = reference_state.hash()?;
        let match_ref = secure_eq(final_hash, &refh);
        let reach_ref = reference_state.state_number >= nums[nums.len() - 1];

        Ok(match_ref || reach_ref)
    }
}

/* --------------------------- State transitions (API) ------------------------- */

impl LimboVault {
    /// Attempt to unlock the vault with a valid proof (no clocks; uses state_number).
    pub fn unlock(
        &mut self,
        proof: FulfillmentProof,
        requester_public_key: &[u8], // informational binding
        reference_state: &State,
    ) -> Result<bool, DsmError> {
        if !matches!(self.state, VaultState::Limbo | VaultState::Active { .. }) {
            return Err(DsmError::invalid_operation(
                "vault must be in limbo or active to unlock",
            ));
        }

        // §7.2 Mathematical Abdication: dBTC vaults (BitcoinHTLC) use fungible
        // CPTA-manifold tokens as authorization. Any holder who can produce a valid
        // Burn proof σ may exit through any active vault on the same manifold.
        // The intended_recipient Kyber-key check is only enforced for non-dBTC vaults.
        let is_dbtc_vault = matches!(
            &self.fulfillment_condition,
            FulfillmentMechanism::BitcoinHTLC { .. }
        );
        if !is_dbtc_vault {
            if let Some(rec) = &self.intended_recipient {
                if !secure_eq(rec, requester_public_key) {
                    return Err(DsmError::invalid_operation(
                        "requester is not intended recipient",
                    ));
                }
            }
        }

        if !self.verify_fulfillment(&proof, reference_state)? {
            return Ok(false);
        }

        self.state = VaultState::Unlocked {
            unlocked_state_number: reference_state.state_number,
            fulfillment_proof: Box::new(proof),
        };
        Ok(true)
    }

    /// Activate a vault after entry anchor burial (dBTC §6.4.1).
    ///
    /// Verifies the fulfillment proof (SPV proof + preimage) without storing it
    /// in the vault state. Transitions `Limbo` → `Active`. The vault remains
    /// sealed — the preimage/skV is NOT derivable until a Burn transition.
    ///
    /// This is the deposit-side counterpart of `unlock()`. Use `unlock()` for
    /// withdrawals where the fulfillment proof needs to be stored.
    pub fn activate(
        &mut self,
        proof: &FulfillmentProof,
        requester_public_key: &[u8],
        reference_state: &State,
    ) -> Result<bool, DsmError> {
        if !matches!(self.state, VaultState::Limbo) {
            return Err(DsmError::invalid_operation("vault not in limbo"));
        }

        // §7.2 Mathematical Abdication: dBTC vaults skip intended_recipient check.
        let is_dbtc_vault = matches!(
            &self.fulfillment_condition,
            FulfillmentMechanism::BitcoinHTLC { .. }
        );
        if !is_dbtc_vault {
            if let Some(rec) = &self.intended_recipient {
                if !secure_eq(rec, requester_public_key) {
                    return Err(DsmError::invalid_operation(
                        "requester is not intended recipient",
                    ));
                }
            }
        }

        if !self.verify_fulfillment(proof, reference_state)? {
            return Ok(false);
        }

        self.state = VaultState::Active {
            activated_state_number: reference_state.state_number,
        };
        Ok(true)
    }

    /// Claim the content of an unlocked vault.
    ///
    /// For non-dBTC vaults: `claimant_secret_key` must be the Kyber **secret key** matching
    /// the `intended_recipient` Kyber public key (or the creator’s key if None). The vault’s
    /// encrypted content is decrypted using the Kyber KEM shared secret + unlocking key.
    ///
    /// For dBTC/BitcoinHTLC vaults: the exit happens through the Bitcoin HTLC (via `draw_tap`),
    /// not through Kyber content decryption. `claim()` still transitions the DSM-side vault
    /// to `Claimed` state and returns an empty content vector. The `claimant_secret_key` is
    /// recorded as the claimant identity but is not used for decryption.
    pub fn claim(
        &mut self,
        claimant_secret_key: &[u8],
        reference_state: &State,
    ) -> Result<ClaimResult, DsmError> {
        let proof = match &self.state {
            VaultState::Unlocked {
                fulfillment_proof, ..
            } => (*fulfillment_proof).clone(),
            _ => return Err(DsmError::invalid_operation("vault not unlocked")),
        };

        // Re-verify under current reference (no clock usage)
        if !self.verify_fulfillment(&proof, reference_state)? {
            return Err(DsmError::invalid_operation(
                "fulfillment proof invalid under current reference",
            ));
        }

        // Construct claim binding
        let mut claim_data = Vec::new();
        claim_data.extend_from_slice(self.id.as_bytes());
        claim_data.extend_from_slice(&self.parameters_hash);
        claim_data.extend_from_slice(&reference_state.state_number.to_le_bytes());
        claim_data.extend_from_slice(domain_hash("DSM/dlv-claim", &proof.to_bytes()).as_bytes());
        let claim_proof = domain_hash_bytes("DSM/dlv-claim", &claim_data).to_vec();

        // §7.2 Mathematical Abdication: dBTC/BitcoinHTLC vaults exit through the Bitcoin
        // HTLC script, not through Kyber content decryption. Skip the KEM + AES path and
        // transition directly to Claimed state. The actual BTC sweep happens in draw_tap().
        let is_dbtc_vault = matches!(
            &self.fulfillment_condition,
            FulfillmentMechanism::BitcoinHTLC { .. }
        );

        if is_dbtc_vault {
            self.state = VaultState::Claimed {
                claimed_state_number: reference_state.state_number,
                claimant: claimant_secret_key.to_vec(),
                claim_proof: claim_proof.clone(),
            };
            return Ok(ClaimResult {
                vault: self.clone(),
                content: Vec::new(), // dBTC exit content is the Bitcoin HTLC preimage, not encrypted vault content
                claim_proof,
            });
        }

        // Non-dBTC path: derive unlocking key and decrypt encrypted content via Kyber KEM.
        //
        // Derive unlocking key per §7.3:
        //   sk_V = BLAKE3-256("DSM/dlv-unlock\0" || L || C || σ)
        // where L = serialized fulfillment condition, C = parameters_hash, σ = receipt commitment.
        // σ is mandatory on all networks — no fallback derivation permitted.
        let fm_proto: crate::types::proto::FulfillmentMechanism =
            (&self.fulfillment_condition).into();
        let mut cond_bytes = Vec::new();
        fm_proto.encode(&mut cond_bytes).map_err(|e| {
            DsmError::serialization_error("FulfillmentMechanism", "encode", None::<&str>, Some(e))
        })?;
        // §7.3: sk_V = BLAKE3-256("DSM/dlv-unlock\0" || L || C || σ)
        let sigma = extract_sigma_from_proof(&proof).ok_or_else(|| {
            DsmError::invalid_operation(
                "DLV claim requires stitched_receipt_sigma in fulfillment proof (§7.3)",
            )
        })?;
        let mut hasher = dsm_domain_hasher("DSM/dlv-unlock");
        hasher.update(&cond_bytes); // L (serialized condition)
        hasher.update(&self.parameters_hash); // C (condition parameters hash)
        hasher.update(&sigma); // σ (receipt commitment)
        let unlocking_key = hasher.finalize().as_bytes().to_vec();

        // Decapsulate shared secret using claimant’s Kyber secret key
        let shared_secret = kyber::kyber_decapsulate(
            claimant_secret_key,
            &self.encrypted_content.encapsulated_key,
        )
        .map_err(|e| DsmError::crypto("kyber_decapsulate", Some(e)))?;

        // Final symmetric key binds KEM secret + unlocking key + AAD
        let final_key = domain_hash_bytes(
            "DSM/dlv-final-key",
            &concat_bytes(&[&shared_secret, &unlocking_key, &self.encrypted_content.aad]),
        )
        .to_vec();

        // Decrypt
        let content = kyber::aes_decrypt(
            &final_key,
            &self.encrypted_content.nonce,
            &self.encrypted_content.encrypted_data,
        )
        .map_err(|e| DsmError::crypto("aes_decrypt", Some(e)))?;

        // Transition to Claimed
        self.state = VaultState::Claimed {
            claimed_state_number: reference_state.state_number,
            claimant: claimant_secret_key.to_vec(), // record who claimed (key identity bytes)
            claim_proof: claim_proof.clone(),
        };

        Ok(ClaimResult {
            vault: self.clone(),
            content,
            claim_proof,
        })
    }

    /// Invalidate a vault (only creator can do so).
    ///
    /// Precondition: vault must be in Limbo or Active state (not yet claimed).
    /// Matches TLA+ DSM_BilateralLiveness.tla VaultInvalidate guard:
    ///   `vaults[vid].state \in {"Limbo", "Unlocked"}`
    /// and DSM_dBTC_Concrete.tla ExpireVault guard:
    ///   `vault[vid].status = "Live" /\ vault[vid].boundTo = NULL`
    pub fn invalidate(
        &mut self,
        reason: &str,
        creator_private_key: &[u8],
        reference_state: &State,
    ) -> Result<(), DsmError> {
        // Terminal states (Claimed, Invalidated) are irreversible.
        // Only Limbo, Active, or Unlocked vaults may be invalidated.
        if matches!(
            self.state,
            VaultState::Claimed { .. } | VaultState::Invalidated { .. }
        ) {
            let label = match &self.state {
                VaultState::Claimed { .. } => "Claimed",
                VaultState::Invalidated { .. } => "Invalidated",
                _ => "terminal",
            };
            return Err(DsmError::invalid_operation(format!(
                "vault {} is in {label} state and cannot be invalidated",
                self.id
            )));
        }
        // Bind id + reason + reference state hash
        let mut data = Vec::new();
        data.extend_from_slice(self.id.as_bytes());
        data.extend_from_slice(reason.as_bytes());
        data.extend_from_slice(&reference_state.hash);

        let sig = sphincs::sphincs_sign(creator_private_key, &data)
            .map_err(|e| DsmError::crypto("sphincs_sign", Some(e)))?;

        let ok = sphincs::sphincs_verify(&self.creator_public_key, &data, &sig)?;
        if !ok {
            return Err(DsmError::invalid_operation("invalid creator signature"));
        }

        self.state = VaultState::Invalidated {
            invalidated_state_number: reference_state.state_number,
            reason: reason.to_string(),
            creator_signature: sig,
        };
        Ok(())
    }

    /// Convert to a storage post (protobuf payload + metadata).
    pub fn to_vault_post(
        &self,
        purpose: &str,
        timeout: Option<u64>,
    ) -> Result<VaultPost, DsmError> {
        let proto: crate::types::proto::LimboVaultProto = self.into();
        let vault_data = proto.encode_to_vec();

        let lock_description = match &self.fulfillment_condition {
            FulfillmentMechanism::Payment {
                amount,
                token_id,
                recipient,
                ..
            } => format!("Payment of {} {} to {}", amount, token_id, recipient),
            FulfillmentMechanism::MultiSignature {
                threshold,
                public_keys,
            } => format!("Requires {} of {} signatures", threshold, public_keys.len()),
            FulfillmentMechanism::CryptoCondition { .. } => "Cryptographic condition".to_string(),
            FulfillmentMechanism::StateReference { .. } => {
                "Reference state verification".to_string()
            }
            FulfillmentMechanism::RandomWalkVerification { statement, .. } => {
                format!("Random walk verification: {}", statement)
            }
            FulfillmentMechanism::BitcoinHTLC {
                expected_btc_amount_sats,
                ..
            } => format!("Bitcoin HTLC vault ({expected_btc_amount_sats} sats)"),
            FulfillmentMechanism::And(v) => format!("All of {} conditions must be met", v.len()),
            FulfillmentMechanism::Or(v) => format!("Any of {} conditions must be met", v.len()),
        };

        let mut metadata = HashMap::new();
        metadata.insert("purpose".to_string(), purpose.to_string());
        if let Some(t) = timeout {
            // Stored as decimal text label; not an encoding of bytes
            metadata.insert("timeout".to_string(), t.to_string());
        }

        let status = match &self.state {
            VaultState::Limbo => "unresolved",
            VaultState::Active { .. } => "active",
            VaultState::Unlocked { .. } => "unlocked",
            VaultState::Claimed { .. } => "claimed",
            VaultState::Invalidated { .. } => "invalidated",
        }
        .to_string();

        let creator_id = decimal_label("pk-", &self.creator_public_key);

        Ok(VaultPost {
            vault_id: self.id.clone(),
            lock_description,
            creator_id,
            commitment_hash: self.parameters_hash.clone(),
            status,
            metadata,
            vault_data,
        })
    }
}

/* -------------------------------- Defaults/Tests ----------------------------- */

impl Default for LimboVault {
    fn default() -> Self {
        Self {
            id: String::new(),
            created_at_state: 0,
            creator_public_key: Vec::new(),
            fulfillment_condition: FulfillmentMechanism::CryptoCondition {
                condition_hash: vec![],
                public_params: vec![],
            },
            intended_recipient: None,
            state: VaultState::Limbo,
            content_type: "application/octet-stream".to_string(),
            encrypted_content: EncryptedContent {
                encapsulated_key: Vec::new(),
                encrypted_data: Vec::new(),
                nonce: Vec::new(),
                aad: Vec::new(),
            },
            content_commitment: PedersenCommitment::default(),
            parameters_hash: Vec::new(),
            creator_signature: Vec::new(),
            verification_positions: Vec::new(),
            reference_state_hash: [0u8; 32],
            entry_header: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::state_machine::random_walk::algorithms::Position;
    use crate::types::policy_types::VaultCondition;

    // ───────── secure_eq ─────────

    #[test]
    fn secure_eq_equal_slices() {
        assert!(secure_eq(b"hello", b"hello"));
    }

    #[test]
    fn secure_eq_different_slices() {
        assert!(!secure_eq(b"hello", b"world"));
    }

    #[test]
    fn secure_eq_different_lengths() {
        assert!(!secure_eq(b"short", b"longer_slice"));
    }

    #[test]
    fn secure_eq_empty_slices() {
        assert!(secure_eq(b"", b""));
    }

    #[test]
    fn secure_eq_one_empty() {
        assert!(!secure_eq(b"", b"x"));
    }

    #[test]
    fn secure_eq_single_bit_diff() {
        let a = [0xFFu8; 32];
        let mut b = [0xFFu8; 32];
        b[31] = 0xFE;
        assert!(!secure_eq(&a, &b));
    }

    // ───────── concat_bytes ─────────

    #[test]
    fn concat_bytes_multiple() {
        let result = concat_bytes(&[b"ab", b"cd", b"ef"]);
        assert_eq!(result, b"abcdef");
    }

    #[test]
    fn concat_bytes_with_empty() {
        let result = concat_bytes(&[b"a", b"", b"b"]);
        assert_eq!(result, b"ab");
    }

    #[test]
    fn concat_bytes_all_empty() {
        let result = concat_bytes(&[b"", b"", b""]);
        assert!(result.is_empty());
    }

    #[test]
    fn concat_bytes_no_parts() {
        let result = concat_bytes(&[]);
        assert!(result.is_empty());
    }

    // ───────── decimal_label ─────────

    #[test]
    fn decimal_label_deterministic() {
        let l1 = decimal_label("pfx-", b"material");
        let l2 = decimal_label("pfx-", b"material");
        assert_eq!(l1, l2);
    }

    #[test]
    fn decimal_label_different_prefix() {
        let l1 = decimal_label("a-", b"mat");
        let l2 = decimal_label("b-", b"mat");
        assert!(l1.starts_with("a-"));
        assert!(l2.starts_with("b-"));
        let num1 = &l1[2..];
        let num2 = &l2[2..];
        assert_eq!(num1, num2);
    }

    #[test]
    fn decimal_label_different_material() {
        let l1 = decimal_label("x-", b"aaa");
        let l2 = decimal_label("x-", b"bbb");
        assert_ne!(l1, l2);
    }

    // ───────── encode_position / decode_position roundtrip ─────────

    #[test]
    fn position_roundtrip_basic() {
        let pos = Position(vec![1, -2, 3, 0]);
        let bytes = encode_position(&pos);
        let decoded = decode_position(&bytes).unwrap();
        assert_eq!(pos.0, decoded.0);
    }

    #[test]
    fn position_roundtrip_empty() {
        let pos = Position(vec![]);
        let bytes = encode_position(&pos);
        assert_eq!(bytes.len(), 4); // only the length prefix
        let decoded = decode_position(&bytes).unwrap();
        assert!(decoded.0.is_empty());
    }

    #[test]
    fn position_roundtrip_single_coord() {
        let pos = Position(vec![i32::MAX]);
        let bytes = encode_position(&pos);
        let decoded = decode_position(&bytes).unwrap();
        assert_eq!(decoded.0, vec![i32::MAX]);
    }

    #[test]
    fn position_roundtrip_many_coords() {
        let coords: Vec<i32> = (0..100).collect();
        let pos = Position(coords.clone());
        let bytes = encode_position(&pos);
        let decoded = decode_position(&bytes).unwrap();
        assert_eq!(decoded.0, coords);
    }

    #[test]
    fn decode_position_short_input() {
        let result = decode_position(&[0, 1]);
        assert!(result.is_err());
    }

    #[test]
    fn decode_position_wrong_length() {
        // Header says 2 coords (8 extra bytes needed) but only 4 provided
        let mut bytes = vec![2, 0, 0, 0]; // len=2
        bytes.extend_from_slice(&1i32.to_le_bytes());
        let result = decode_position(&bytes);
        assert!(result.is_err());
    }

    // ───────── FulfillmentProof::to_bytes ─────────

    #[test]
    fn payment_proof_to_bytes_no_sigma() {
        let proof = FulfillmentProof::PaymentProof {
            state_transition: vec![1, 2, 3],
            merkle_proof: vec![4, 5],
            stitched_receipt_sigma: None,
        };
        let bytes = proof.to_bytes();
        assert_eq!(bytes[0], 1); // variant tag
        assert!(!bytes.is_empty());
        // last byte should be 0x00 (no sigma)
        assert_eq!(*bytes.last().unwrap(), 0x00);
    }

    #[test]
    fn payment_proof_to_bytes_with_sigma() {
        let sigma = [0xABu8; 32];
        let proof = FulfillmentProof::PaymentProof {
            state_transition: vec![10],
            merkle_proof: vec![20],
            stitched_receipt_sigma: Some(sigma),
        };
        let bytes = proof.to_bytes();
        assert_eq!(bytes[0], 1);
        // sigma present: ..., 0x01, <32 bytes of 0xAB>
        let tail = &bytes[bytes.len() - 33..];
        assert_eq!(tail[0], 0x01);
        assert_eq!(&tail[1..], &sigma);
    }

    #[test]
    fn crypto_condition_proof_to_bytes() {
        let proof = FulfillmentProof::CryptoConditionProof {
            solution: vec![0xFF; 5],
            proof: vec![0xEE; 3],
            stitched_receipt_sigma: None,
        };
        let bytes = proof.to_bytes();
        assert_eq!(bytes[0], 2);
    }

    #[test]
    fn multi_signature_proof_to_bytes() {
        let proof = FulfillmentProof::MultiSignatureProof {
            signatures: vec![(vec![1], vec![2]), (vec![3], vec![4])],
            signed_data: vec![5, 6],
            stitched_receipt_sigma: None,
        };
        let bytes = proof.to_bytes();
        assert_eq!(bytes[0], 3);
    }

    #[test]
    fn random_walk_proof_to_bytes() {
        let proof = FulfillmentProof::RandomWalkProof {
            positions: vec![Position(vec![1, 2]), Position(vec![3, 4])],
            hash_chain_proof: vec![0xCC; 8],
            stitched_receipt_sigma: None,
        };
        let bytes = proof.to_bytes();
        assert_eq!(bytes[0], 4);
    }

    #[test]
    fn compound_proof_to_bytes() {
        let inner = FulfillmentProof::PaymentProof {
            state_transition: vec![1],
            merkle_proof: vec![2],
            stitched_receipt_sigma: None,
        };
        let proof = FulfillmentProof::CompoundProof(vec![inner]);
        let bytes = proof.to_bytes();
        assert_eq!(bytes[0], 5);
    }

    #[test]
    fn bitcoin_htlc_proof_to_bytes() {
        let proof = FulfillmentProof::BitcoinHTLCProof {
            preimage: vec![0x01; 32],
            bitcoin_txid: [0x02; 32],
            bitcoin_tx_raw: vec![0x03; 10],
            spv_proof: vec![0x04; 8],
            expected_script_pubkey: vec![0x05; 4],
            block_header: Box::new([0x06; 80]),
            header_chain: vec![],
            stitched_receipt: None,
            stitched_receipt_sigma: None,
        };
        let bytes = proof.to_bytes();
        assert_eq!(bytes[0], 6);
    }

    #[test]
    fn to_bytes_deterministic() {
        let proof = FulfillmentProof::PaymentProof {
            state_transition: vec![9, 8, 7],
            merkle_proof: vec![6, 5],
            stitched_receipt_sigma: Some([0x42; 32]),
        };
        let b1 = proof.to_bytes();
        let b2 = proof.to_bytes();
        assert_eq!(b1, b2);
    }

    // ───────── extract_sigma_from_proof ─────────

    #[test]
    fn extract_sigma_payment_some() {
        let sigma = [0x11u8; 32];
        let proof = FulfillmentProof::PaymentProof {
            state_transition: vec![],
            merkle_proof: vec![],
            stitched_receipt_sigma: Some(sigma),
        };
        assert_eq!(extract_sigma_from_proof(&proof), Some(sigma));
    }

    #[test]
    fn extract_sigma_payment_none() {
        let proof = FulfillmentProof::PaymentProof {
            state_transition: vec![],
            merkle_proof: vec![],
            stitched_receipt_sigma: None,
        };
        assert_eq!(extract_sigma_from_proof(&proof), None);
    }

    #[test]
    fn extract_sigma_crypto_condition() {
        let sigma = [0x22u8; 32];
        let proof = FulfillmentProof::CryptoConditionProof {
            solution: vec![],
            proof: vec![],
            stitched_receipt_sigma: Some(sigma),
        };
        assert_eq!(extract_sigma_from_proof(&proof), Some(sigma));
    }

    #[test]
    fn extract_sigma_multi_sig() {
        let sigma = [0x33u8; 32];
        let proof = FulfillmentProof::MultiSignatureProof {
            signatures: vec![],
            signed_data: vec![],
            stitched_receipt_sigma: Some(sigma),
        };
        assert_eq!(extract_sigma_from_proof(&proof), Some(sigma));
    }

    #[test]
    fn extract_sigma_random_walk() {
        let sigma = [0x44u8; 32];
        let proof = FulfillmentProof::RandomWalkProof {
            positions: vec![],
            hash_chain_proof: vec![],
            stitched_receipt_sigma: Some(sigma),
        };
        assert_eq!(extract_sigma_from_proof(&proof), Some(sigma));
    }

    #[test]
    fn extract_sigma_bitcoin_htlc() {
        let sigma = [0x55u8; 32];
        let proof = FulfillmentProof::BitcoinHTLCProof {
            preimage: vec![],
            bitcoin_txid: [0; 32],
            bitcoin_tx_raw: vec![],
            spv_proof: vec![],
            expected_script_pubkey: vec![],
            block_header: Box::new([0; 80]),
            header_chain: vec![],
            stitched_receipt: None,
            stitched_receipt_sigma: Some(sigma),
        };
        assert_eq!(extract_sigma_from_proof(&proof), Some(sigma));
    }

    #[test]
    fn extract_sigma_compound_returns_none() {
        let proof = FulfillmentProof::CompoundProof(vec![]);
        assert_eq!(extract_sigma_from_proof(&proof), None);
    }

    // ───────── VaultState ─────────

    #[test]
    fn vault_state_limbo_equality() {
        assert_eq!(VaultState::Limbo, VaultState::Limbo);
    }

    #[test]
    fn vault_state_active_equality() {
        let a = VaultState::Active {
            activated_state_number: 42,
        };
        let b = VaultState::Active {
            activated_state_number: 42,
        };
        assert_eq!(a, b);
    }

    #[test]
    fn vault_state_active_inequality() {
        let a = VaultState::Active {
            activated_state_number: 1,
        };
        let b = VaultState::Active {
            activated_state_number: 2,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn vault_state_limbo_ne_active() {
        assert_ne!(
            VaultState::Limbo,
            VaultState::Active {
                activated_state_number: 0
            }
        );
    }

    // ───────── DeterministicLimboVault ─────────

    #[test]
    fn dlv_new_and_getters() {
        let cond = VaultCondition::Hash(b"test".to_vec());
        let v = DeterministicLimboVault::new("alice", "bob", vec![1, 2, 3], cond);

        assert!(v.id().starts_with("dlv-"));
        assert_eq!(v.creator_id(), "alice");
        assert_eq!(v.recipient_id(), "bob");
        assert_eq!(v.data(), &[1, 2, 3]);
        assert_eq!(*v.status(), VaultStatus::Active);
    }

    #[test]
    fn dlv_set_status() {
        let cond = VaultCondition::Hash(vec![]);
        let mut v = DeterministicLimboVault::new("c", "r", vec![], cond);

        v.set_status(VaultStatus::Claimed);
        assert_eq!(*v.status(), VaultStatus::Claimed);

        v.set_status(VaultStatus::Revoked);
        assert_eq!(*v.status(), VaultStatus::Revoked);

        v.set_status(VaultStatus::Expired);
        assert_eq!(*v.status(), VaultStatus::Expired);
    }

    #[test]
    fn dlv_id_is_deterministic() {
        let cond1 = VaultCondition::Hash(b"h".to_vec());
        let cond2 = VaultCondition::Hash(b"h".to_vec());
        let v1 = DeterministicLimboVault::new("alice", "bob", vec![42], cond1);
        let v2 = DeterministicLimboVault::new("alice", "bob", vec![42], cond2);
        assert_eq!(v1.id(), v2.id());
    }

    #[test]
    fn dlv_different_data_different_id() {
        let cond1 = VaultCondition::Hash(vec![]);
        let cond2 = VaultCondition::Hash(vec![]);
        let v1 = DeterministicLimboVault::new("a", "b", vec![1], cond1);
        let v2 = DeterministicLimboVault::new("a", "b", vec![2], cond2);
        assert_ne!(v1.id(), v2.id());
    }

    // ───────── factory functions ─────────

    #[test]
    fn create_deterministic_limbo_vault_basic() {
        let v = create_deterministic_limbo_vault(
            "creator1",
            vec![10, 20],
            VaultCondition::MinimumBalance(100),
        );
        assert!(v.id().starts_with("dlv-"));
        assert_eq!(v.creator_id(), "creator1");
        assert_eq!(v.recipient_id(), "");
        assert_eq!(v.data(), &[10, 20]);
    }

    #[test]
    fn create_deterministic_limbo_vault_with_timeout_basic() {
        let v = create_deterministic_limbo_vault_with_timeout("creator2", vec![30], 999);
        assert!(v.id().starts_with("dlv-"));
        assert_eq!(v.creator_id(), "creator2");
        assert_eq!(v.recipient_id(), "");
    }

    #[test]
    fn create_deterministic_limbo_vault_with_timeout_and_recipient_basic() {
        let v = create_deterministic_limbo_vault_with_timeout_and_recipient(
            "creator3",
            "recip3",
            vec![40],
            500,
        );
        assert!(v.id().starts_with("dlv-"));
        assert_eq!(v.creator_id(), "creator3");
        assert_eq!(v.recipient_id(), "recip3");
    }

    // ───────── VaultPost from LimboVault (proto conversion) ─────────

    #[test]
    fn vault_post_proto_metadata_sorted() {
        let mut metadata = HashMap::new();
        metadata.insert("zebra".to_string(), "z_val".to_string());
        metadata.insert("alpha".to_string(), "a_val".to_string());
        metadata.insert("mid".to_string(), "m_val".to_string());

        let post = VaultPost {
            vault_id: "v1".to_string(),
            lock_description: "test".to_string(),
            creator_id: "c1".to_string(),
            commitment_hash: vec![],
            status: "unresolved".to_string(),
            metadata,
            vault_data: vec![],
        };

        let proto: crate::types::proto::VaultPostProto = (&post).into();
        let keys: Vec<&str> = proto.metadata.iter().map(|kv| kv.key.as_str()).collect();
        assert_eq!(keys, vec!["alpha", "mid", "zebra"]);
    }

    #[test]
    fn vault_post_proto_fields_match() {
        let post = VaultPost {
            vault_id: "vid".to_string(),
            lock_description: "lock".to_string(),
            creator_id: "cid".to_string(),
            commitment_hash: vec![99],
            status: "active".to_string(),
            metadata: HashMap::new(),
            vault_data: vec![1, 2, 3],
        };

        let proto: crate::types::proto::VaultPostProto = (&post).into();
        assert_eq!(proto.vault_id, "vid");
        assert_eq!(proto.lock_description, "lock");
        assert_eq!(proto.creator_id, "cid");
        assert_eq!(proto.commitment_hash, vec![99]);
        assert_eq!(proto.status, "active");
        assert_eq!(proto.vault_data, vec![1, 2, 3]);
    }

    // ───────── LimboVault::new_minimal ─────────

    #[test]
    fn new_minimal_fields() {
        let cond = FulfillmentMechanism::CryptoCondition {
            condition_hash: vec![1],
            public_params: vec![2],
        };
        let ref_hash = [0xAAu8; 32];
        let v = LimboVault::new_minimal("test-vault".to_string(), cond, ref_hash);

        assert_eq!(v.id, "test-vault");
        assert_eq!(v.created_at_state, 0);
        assert!(v.creator_public_key.is_empty());
        assert!(v.intended_recipient.is_none());
        assert_eq!(v.state, VaultState::Limbo);
        assert_eq!(v.content_type, "application/dsm-dbtc-mint");
        assert!(v.encrypted_content.encapsulated_key.is_empty());
        assert!(v.encrypted_content.encrypted_data.is_empty());
        assert!(v.encrypted_content.nonce.is_empty());
        assert!(v.encrypted_content.aad.is_empty());
        assert!(v.parameters_hash.is_empty());
        assert!(v.creator_signature.is_empty());
        assert!(v.verification_positions.is_empty());
        assert_eq!(v.reference_state_hash, ref_hash);
        assert!(v.entry_header.is_none());
    }

    // ───────── LimboVault::default ─────────

    #[test]
    fn limbo_vault_default() {
        let v = LimboVault::default();

        assert!(v.id.is_empty());
        assert_eq!(v.created_at_state, 0);
        assert!(v.creator_public_key.is_empty());
        assert!(v.intended_recipient.is_none());
        assert_eq!(v.state, VaultState::Limbo);
        assert_eq!(v.content_type, "application/octet-stream");
        assert!(v.parameters_hash.is_empty());
        assert!(v.creator_signature.is_empty());
        assert!(v.verification_positions.is_empty());
        assert_eq!(v.reference_state_hash, [0u8; 32]);
        assert!(v.entry_header.is_none());
    }

    #[test]
    fn limbo_vault_default_fulfillment_is_crypto_condition() {
        let v = LimboVault::default();
        assert!(matches!(
            v.fulfillment_condition,
            FulfillmentMechanism::CryptoCondition { .. }
        ));
    }

    // ───────── VaultStatus Display ─────────

    #[test]
    fn vault_status_display_active() {
        assert_eq!(format!("{}", VaultStatus::Active), "active");
    }

    #[test]
    fn vault_status_display_claimed() {
        assert_eq!(format!("{}", VaultStatus::Claimed), "claimed");
    }

    #[test]
    fn vault_status_display_revoked() {
        assert_eq!(format!("{}", VaultStatus::Revoked), "revoked");
    }

    #[test]
    fn vault_status_display_expired() {
        assert_eq!(format!("{}", VaultStatus::Expired), "expired");
    }

    // ───────── to_vault_post lock descriptions ─────────

    fn make_minimal_vault_with_condition(cond: FulfillmentMechanism) -> LimboVault {
        LimboVault {
            fulfillment_condition: cond,
            ..LimboVault::default()
        }
    }

    #[test]
    fn to_vault_post_payment_description() {
        let v = make_minimal_vault_with_condition(FulfillmentMechanism::Payment {
            amount: 100,
            token_id: "DSM".to_string(),
            recipient: "alice".to_string(),
            verification_state: vec![],
        });
        let post = v.to_vault_post("test", None).unwrap();
        assert_eq!(post.lock_description, "Payment of 100 DSM to alice");
        assert_eq!(post.status, "unresolved");
    }

    #[test]
    fn to_vault_post_multi_sig_description() {
        let v = make_minimal_vault_with_condition(FulfillmentMechanism::MultiSignature {
            public_keys: vec![vec![1], vec![2], vec![3]],
            threshold: 2,
        });
        let post = v.to_vault_post("governance", None).unwrap();
        assert_eq!(post.lock_description, "Requires 2 of 3 signatures");
    }

    #[test]
    fn to_vault_post_crypto_condition_description() {
        let v = make_minimal_vault_with_condition(FulfillmentMechanism::CryptoCondition {
            condition_hash: vec![],
            public_params: vec![],
        });
        let post = v.to_vault_post("cond", None).unwrap();
        assert_eq!(post.lock_description, "Cryptographic condition");
    }

    #[test]
    fn to_vault_post_state_reference_description() {
        let v = make_minimal_vault_with_condition(FulfillmentMechanism::StateReference {
            reference_states: vec![],
            parameters: vec![],
        });
        let post = v.to_vault_post("ref", None).unwrap();
        assert_eq!(post.lock_description, "Reference state verification");
    }

    #[test]
    fn to_vault_post_random_walk_description() {
        let v = make_minimal_vault_with_condition(FulfillmentMechanism::RandomWalkVerification {
            verification_key: vec![],
            statement: "prove-it".to_string(),
        });
        let post = v.to_vault_post("rw", None).unwrap();
        assert_eq!(post.lock_description, "Random walk verification: prove-it");
    }

    #[test]
    fn to_vault_post_bitcoin_htlc_description() {
        let v = make_minimal_vault_with_condition(FulfillmentMechanism::BitcoinHTLC {
            hash_lock: [0; 32],
            refund_hash_lock: [0; 32],
            refund_iterations: 0,
            bitcoin_pubkey: vec![],
            expected_btc_amount_sats: 50_000,
            network: 0,
            min_confirmations: 6,
        });
        let post = v.to_vault_post("btc", None).unwrap();
        assert_eq!(post.lock_description, "Bitcoin HTLC vault (50000 sats)");
    }

    #[test]
    fn to_vault_post_and_description() {
        let v = make_minimal_vault_with_condition(FulfillmentMechanism::And(vec![
            FulfillmentMechanism::CryptoCondition {
                condition_hash: vec![],
                public_params: vec![],
            },
            FulfillmentMechanism::CryptoCondition {
                condition_hash: vec![],
                public_params: vec![],
            },
        ]));
        let post = v.to_vault_post("compound", None).unwrap();
        assert_eq!(post.lock_description, "All of 2 conditions must be met");
    }

    #[test]
    fn to_vault_post_or_description() {
        let v = make_minimal_vault_with_condition(FulfillmentMechanism::Or(vec![
            FulfillmentMechanism::CryptoCondition {
                condition_hash: vec![],
                public_params: vec![],
            },
        ]));
        let post = v.to_vault_post("compound", None).unwrap();
        assert_eq!(post.lock_description, "Any of 1 conditions must be met");
    }

    #[test]
    fn to_vault_post_with_timeout_metadata() {
        let v = LimboVault::default();
        let post = v.to_vault_post("op", Some(3600)).unwrap();
        assert_eq!(post.metadata.get("purpose").unwrap(), "op");
        assert_eq!(post.metadata.get("timeout").unwrap(), "3600");
    }

    #[test]
    fn to_vault_post_no_timeout_metadata() {
        let v = LimboVault::default();
        let post = v.to_vault_post("op", None).unwrap();
        assert_eq!(post.metadata.get("purpose").unwrap(), "op");
        assert!(!post.metadata.contains_key("timeout"));
    }

    #[test]
    fn to_vault_post_status_reflects_vault_state() {
        let mut v = LimboVault::default();
        assert_eq!(v.to_vault_post("t", None).unwrap().status, "unresolved");

        v.state = VaultState::Active {
            activated_state_number: 1,
        };
        assert_eq!(v.to_vault_post("t", None).unwrap().status, "active");

        v.state = VaultState::Unlocked {
            unlocked_state_number: 2,
            fulfillment_proof: Box::new(FulfillmentProof::CompoundProof(vec![])),
        };
        assert_eq!(v.to_vault_post("t", None).unwrap().status, "unlocked");

        v.state = VaultState::Claimed {
            claimed_state_number: 3,
            claimant: vec![],
            claim_proof: vec![],
        };
        assert_eq!(v.to_vault_post("t", None).unwrap().status, "claimed");

        v.state = VaultState::Invalidated {
            invalidated_state_number: 4,
            reason: "gone".to_string(),
            creator_signature: vec![],
        };
        assert_eq!(v.to_vault_post("t", None).unwrap().status, "invalidated");
    }

    // ───────── from_limbo_vault status mapping ─────────

    #[test]
    fn from_limbo_vault_status_mapping() {
        let cond = VaultCondition::Hash(vec![]);

        let mut v = LimboVault {
            state: VaultState::Limbo,
            ..LimboVault::default()
        };
        let dlv = DeterministicLimboVault::from_limbo_vault(&v, cond.clone()).unwrap();
        assert_eq!(*dlv.status(), VaultStatus::Active);

        v.state = VaultState::Active {
            activated_state_number: 1,
        };
        let dlv = DeterministicLimboVault::from_limbo_vault(&v, cond.clone()).unwrap();
        assert_eq!(*dlv.status(), VaultStatus::Active);

        v.state = VaultState::Claimed {
            claimed_state_number: 2,
            claimant: vec![],
            claim_proof: vec![],
        };
        let dlv = DeterministicLimboVault::from_limbo_vault(&v, cond.clone()).unwrap();
        assert_eq!(*dlv.status(), VaultStatus::Claimed);

        v.state = VaultState::Invalidated {
            invalidated_state_number: 3,
            reason: "test".to_string(),
            creator_signature: vec![],
        };
        let dlv = DeterministicLimboVault::from_limbo_vault(&v, cond).unwrap();
        assert_eq!(*dlv.status(), VaultStatus::Revoked);
    }

    // ───────── EncryptedContent struct ─────────

    #[test]
    fn encrypted_content_clone() {
        let ec = EncryptedContent {
            encapsulated_key: vec![1, 2],
            encrypted_data: vec![3, 4],
            nonce: vec![5],
            aad: vec![6],
        };
        let ec2 = ec.clone();
        assert_eq!(ec.encapsulated_key, ec2.encapsulated_key);
        assert_eq!(ec.encrypted_data, ec2.encrypted_data);
        assert_eq!(ec.nonce, ec2.nonce);
        assert_eq!(ec.aad, ec2.aad);
    }
}

/* ------------------- Optional Deterministic Limbo (lightweight) -------------- */

#[derive(Debug, Clone, PartialEq)]
pub enum VaultStatus {
    Active,
    Claimed,
    Revoked,
    Expired,
}

#[derive(Debug, Clone)]
pub struct DeterministicLimboVault {
    id: String,
    creator_id: String,
    recipient_id: String,
    data: Vec<u8>,
    condition: VaultCondition,
    status: VaultStatus,
}

impl DeterministicLimboVault {
    pub fn new(
        creator_id: &str,
        recipient_id: &str,
        data: Vec<u8>,
        condition: VaultCondition,
    ) -> Self {
        let id = decimal_label(
            "dlv-",
            concat_bytes(&[
                creator_id.as_bytes(),
                recipient_id.as_bytes(),
                &domain_hash_bytes("DSM/dlv-content", &data)[..],
            ])
            .as_slice(),
        );
        Self {
            id,
            creator_id: creator_id.to_string(),
            recipient_id: recipient_id.to_string(),
            data,
            condition,
            status: VaultStatus::Active,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn creator_id(&self) -> &str {
        &self.creator_id
    }
    pub fn recipient_id(&self) -> &str {
        &self.recipient_id
    }
    pub fn data(&self) -> &[u8] {
        &self.data
    }
    pub fn condition(&self) -> &VaultCondition {
        &self.condition
    }
    pub fn status(&self) -> &VaultStatus {
        &self.status
    }
    pub fn set_status(&mut self, s: VaultStatus) {
        self.status = s;
    }

    pub fn from_limbo_vault(v: &LimboVault, condition: VaultCondition) -> Result<Self, DsmError> {
        let creator_id = decimal_label("pk-", &v.creator_public_key);
        let recipient_id = match &v.intended_recipient {
            Some(pk) => decimal_label("pk-", pk),
            None => String::new(),
        };
        Ok(Self {
            id: v.id.clone(),
            creator_id,
            recipient_id,
            data: v.encrypted_content.encrypted_data.clone(),
            condition,
            status: match v.state {
                VaultState::Limbo => VaultStatus::Active,
                VaultState::Active { .. } => VaultStatus::Active,
                VaultState::Unlocked { .. } => VaultStatus::Active,
                VaultState::Claimed { .. } => VaultStatus::Claimed,
                VaultState::Invalidated { .. } => VaultStatus::Revoked,
            },
        })
    }
}

pub fn convert_vault(
    vault: &LimboVault,
    condition: VaultCondition,
) -> Result<DeterministicLimboVault, DsmError> {
    DeterministicLimboVault::from_limbo_vault(vault, condition)
}

pub fn create_deterministic_limbo_vault(
    creator_id: &str,
    data: Vec<u8>,
    condition: VaultCondition,
) -> DeterministicLimboVault {
    DeterministicLimboVault::new(creator_id, "", data, condition)
}

pub fn create_deterministic_limbo_vault_with_timeout(
    creator_id: &str,
    data: Vec<u8>,
    _timeout_ticks: u64, // logical ticks; not used in minimal builder
) -> DeterministicLimboVault {
    let condition = VaultCondition::Hash(b"timeout_disabled".to_vec());
    DeterministicLimboVault::new(creator_id, "", data, condition)
}

pub fn create_deterministic_limbo_vault_with_timeout_and_recipient(
    creator_id: &str,
    recipient_id: &str,
    data: Vec<u8>,
    _timeout_ticks: u64,
) -> DeterministicLimboVault {
    let condition = VaultCondition::Hash(b"timeout_disabled".to_vec());
    DeterministicLimboVault::new(creator_id, recipient_id, data, condition)
}

/* --------------------------------- Display impls ----------------------------- */

impl fmt::Display for VaultStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultStatus::Active => write!(f, "active"),
            VaultStatus::Claimed => write!(f, "claimed"),
            VaultStatus::Revoked => write!(f, "revoked"),
            VaultStatus::Expired => write!(f, "expired"),
        }
    }
}
