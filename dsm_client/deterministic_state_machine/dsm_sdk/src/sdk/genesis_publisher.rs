//! # Genesis Publisher (content-addressed, Task A.4 follow-up)
//!
//! Publishes and retrieves the canonical `PublishableGenesisV1`
//! artifact at the spec §6 content-address
//! `addr = H("DSM/genesis-mirror\0" || G)` — pinned by
//! `dsm::core::identity::genesis_mpc::compute_genesis_mirror_addr`.
//!
//! Replaces the prior bespoke binary `SanitizedGenesisPayload`
//! encoding with a deterministic prost-encoded proto. The artifact
//! carries every input needed for an external verifier to
//! independently recompute `G` per whitepaper §2.5
//! (`device_entropy`, `mpc_entropies`, `participants`, `metadata`)
//! plus the post-G `pk_1` / Kyber public keys derived per §11.1.
//!
//! Retrieval is device-side strict:
//! 1. Compute `addr` from the known `G`.
//! 2. GET bytes from the storage node by `addr`.
//! 3. Decode `PublishableGenesisV1`.
//! 4. Verify `decoded.genesis_hash == G` (rejects wrong-content at
//!    the address) and that the payload recomputes `G` byte-for-byte
//!    via the canonical §2.5 formula (rejects forged inputs).
//!
//! Per Task A.4 plan, an unauthenticated `/api/v2/genesis-mirror/*`
//! endpoint that bypasses `device_auth` is a separate follow-up
//! (needed for freshly-created devices that have not yet registered).
//! Until then publish uses the existing object-store PUT path —
//! storage-auth-aware callers can publish; un-auth'd ones get a
//! clear auth error.

use prost::Message;

use dsm::core::identity::genesis_mpc::compute_genesis_mirror_addr;
use dsm::crypto::blake3::dsm_domain_hasher;
use dsm::types::error::DsmError;
use dsm::types::proto as pb;

use crate::sdk::storage_node_sdk::StorageNodeSDK;
use crate::util::text_id::encode_base32_crockford;

pub struct SdkGenesisPublisher {
    storage_sdk: StorageNodeSDK,
}

impl SdkGenesisPublisher {
    pub fn new(storage_sdk: StorageNodeSDK) -> Self {
        Self { storage_sdk }
    }

    /// Object-store key for a published genesis: the base32-Crockford
    /// encoding of `addr = H("DSM/genesis-mirror\0" || G)`. The
    /// `genesis-mirror/` prefix is operational tagging only (lets
    /// operators identify these objects in the store); the actual
    /// content-addressing predicate is `addr_b32` itself.
    fn key_for(g: &[u8; 32]) -> String {
        let addr = compute_genesis_mirror_addr(g);
        format!("genesis-mirror/{}", encode_base32_crockford(&addr))
    }

    /// Encode the artifact into deterministic prost bytes and PUT
    /// to the storage node under the content-addressed key.
    pub async fn publish(&self, payload: &pb::PublishableGenesisV1) -> Result<(), DsmError> {
        if payload.genesis_hash.len() != 32 {
            return Err(DsmError::invalid_parameter(
                "PublishableGenesisV1.genesis_hash must be 32 bytes",
            ));
        }
        let g: [u8; 32] = payload
            .genesis_hash
            .as_slice()
            .try_into()
            .map_err(|_| DsmError::invalid_parameter("genesis_hash length mismatch"))?;
        let body = payload.encode_to_vec();
        let key = Self::key_for(&g);

        log::info!(
            "SdkGenesisPublisher::publish: addr_b32={} size={}",
            key,
            body.len()
        );

        self.storage_sdk.put(&key, &body, None).await.map_err(|e| {
            DsmError::network(
                format!("Failed to publish genesis: {e}"),
                None::<std::io::Error>,
            )
        })?;

        Ok(())
    }

    /// Fetch and strictly verify a published genesis by its hash `G`.
    /// Rejects if the address content doesn't match, if the proto
    /// decode fails, if `decoded.genesis_hash != g`, or if the
    /// payload's public inputs don't recompute to `g`.
    pub async fn retrieve(&self, g: &[u8; 32]) -> Result<pb::PublishableGenesisV1, DsmError> {
        let key = Self::key_for(g);
        log::info!("SdkGenesisPublisher::retrieve: addr_b32={key}");

        let body = self.storage_sdk.get(&key).await.map_err(|e| {
            DsmError::network(
                format!("Failed to retrieve genesis: {e}"),
                None::<std::io::Error>,
            )
        })?;

        let payload = pb::PublishableGenesisV1::decode(body.as_slice()).map_err(|e| {
            DsmError::invalid_operation(format!("PublishableGenesisV1 proto decode failed: {e}"))
        })?;

        if payload.genesis_hash.as_slice() != g.as_slice() {
            return Err(DsmError::invalid_operation(
                "PublishableGenesisV1.genesis_hash does not match requested G",
            ));
        }

        // Strict recomputation of G per whitepaper §2.5:
        //
        //   G = H("DSM/genesis\0" || device_entropy || mpc_1..n || A)
        //
        // where A = canonical_a(device_id, sorted_participants, metadata).
        // Rejecting on mismatch defeats a malicious publisher that
        // posts a payload whose stated G doesn't recompute from the
        // accompanying public inputs.
        let recomputed = recompute_g_strict(&payload)?;
        if recomputed != *g {
            return Err(DsmError::invalid_operation(
                "PublishableGenesisV1 public inputs do not recompute the requested G",
            ));
        }

        Ok(payload)
    }
}

/// Independent recomputation of `G` from the public inputs of a
/// `PublishableGenesisV1`. Mirrors
/// `GenesisSession::compute_genesis_id` byte-for-byte (which the core
/// unit test `genesis_id_is_recomputable_from_public_inputs` pins).
fn recompute_g_strict(p: &pb::PublishableGenesisV1) -> Result<[u8; 32], DsmError> {
    if p.device_id.len() != 32 || p.device_entropy.len() != 32 {
        return Err(DsmError::invalid_parameter(
            "PublishableGenesisV1: device_id/device_entropy must be 32 bytes",
        ));
    }
    for m in &p.mpc_entropies {
        if m.len() != 32 {
            return Err(DsmError::invalid_parameter(
                "PublishableGenesisV1: each mpc_entropy must be 32 bytes",
            ));
        }
    }
    for p32 in &p.participants {
        if p32.len() != 32 {
            return Err(DsmError::invalid_parameter(
                "PublishableGenesisV1: each participant must be 32 bytes",
            ));
        }
    }

    let mut device_id = [0u8; 32];
    device_id.copy_from_slice(&p.device_id);

    let mut h = dsm_domain_hasher("DSM/genesis");
    h.update(&p.device_entropy);
    for m in &p.mpc_entropies {
        h.update(m);
    }
    h.update(&canonical_a_publishable(
        &device_id,
        &p.participants,
        &p.metadata,
    ));
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    Ok(out)
}

/// Canonical `A` binding parameters per whitepaper §2.5, computed
/// from the wire-form `PublishableGenesisV1` participant list. Mirrors
/// `dsm::core::identity::genesis_mpc::canonical_a` byte-for-byte:
///
/// ```text
///   device_id          : 32 bytes
///   participant_count  : u32 LE
///   for each participant (lex-sorted on raw 32-byte id):
///     length           : u32 LE
///     bytes
///   metadata_length    : u32 LE
///   metadata           : bytes
/// ```
fn canonical_a_publishable(
    device_id: &[u8; 32],
    participants: &[Vec<u8>],
    metadata: &[u8],
) -> Vec<u8> {
    let mut sorted: Vec<&[u8]> = participants.iter().map(|p| p.as_slice()).collect();
    sorted.sort();

    let participant_bytes_total: usize = sorted.iter().map(|p| p.len() + 4).sum();
    let mut a = Vec::with_capacity(32 + 4 + participant_bytes_total + 4 + metadata.len());

    a.extend_from_slice(device_id);
    a.extend_from_slice(&(sorted.len() as u32).to_le_bytes());
    for p in &sorted {
        a.extend_from_slice(&(p.len() as u32).to_le_bytes());
        a.extend_from_slice(p);
    }
    a.extend_from_slice(&(metadata.len() as u32).to_le_bytes());
    a.extend_from_slice(metadata);

    a
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `recompute_g_strict` must match the canonical core formula
    /// byte-for-byte. Reuses the same input pattern as the core's
    /// `genesis_id_is_recomputable_from_public_inputs` test.
    #[test]
    fn recompute_g_strict_matches_core_formula() {
        let device_id = [0x42u8; 32];
        let device_entropy = [0xD0u8; 32];
        let mpc_entropies = vec![[0xE1u8; 32], [0xE2u8; 32], [0xE3u8; 32]];
        let participants = vec![[0x10u8; 32], [0x20u8; 32], [0x30u8; 32]];
        let metadata = b"DSMv2|publishable".to_vec();

        // Reference: build a GenesisSession and read its genesis_id.
        let mut session = dsm::core::identity::genesis_mpc::GenesisSession::new(metadata.clone())
            .expect("new session");
        let storage_nodes: Vec<dsm::types::identifiers::NodeId> = participants
            .iter()
            .map(|p| dsm::types::identifiers::NodeId::from_bytes(p.to_vec()))
            .collect();
        session
            .initialize_mpc(device_id, storage_nodes)
            .expect("init mpc");
        session
            .set_entropies(device_entropy, mpc_entropies.clone())
            .expect("set entropies");
        session.set_dbrw_binding([0xDBu8; 32]);
        session.compute_commitments();
        session.compute_genesis_id();

        // Build a PublishableGenesisV1 with the same inputs and recompute.
        let publishable = pb::PublishableGenesisV1 {
            genesis_hash: session.genesis_id.to_vec(),
            device_id: device_id.to_vec(),
            device_entropy: device_entropy.to_vec(),
            mpc_entropies: mpc_entropies.iter().map(|m| m.to_vec()).collect(),
            participants: participants.iter().map(|p| p.to_vec()).collect(),
            metadata,
            initiator_pk_post_genesis: vec![],
            initiator_kyber_pk: vec![],
        };
        let recomputed = recompute_g_strict(&publishable).expect("recompute");
        assert_eq!(
            recomputed, session.genesis_id,
            "recompute_g_strict must match core canonical_a + compute_genesis_id"
        );
    }

    /// Tampering with any public input must break recomputation —
    /// the strict check rejects forged-input publications.
    #[test]
    fn recompute_g_strict_rejects_tampered_inputs() {
        let device_id = [0x42u8; 32];
        let device_entropy = [0xD0u8; 32];
        let mpc_entropies = vec![[0xE1u8; 32], [0xE2u8; 32], [0xE3u8; 32]];
        let participants = vec![[0x10u8; 32], [0x20u8; 32], [0x30u8; 32]];

        let base = pb::PublishableGenesisV1 {
            genesis_hash: vec![],
            device_id: device_id.to_vec(),
            device_entropy: device_entropy.to_vec(),
            mpc_entropies: mpc_entropies.iter().map(|m| m.to_vec()).collect(),
            participants: participants.iter().map(|p| p.to_vec()).collect(),
            metadata: b"orig".to_vec(),
            initiator_pk_post_genesis: vec![],
            initiator_kyber_pk: vec![],
        };
        let g_base = recompute_g_strict(&base).expect("base");

        // Tamper device_entropy -> different G.
        let mut tampered = base.clone();
        tampered.device_entropy[0] ^= 0xFF;
        assert_ne!(g_base, recompute_g_strict(&tampered).unwrap());

        // Tamper metadata -> different G.
        let mut tampered = base.clone();
        tampered.metadata.push(0xFF);
        assert_ne!(g_base, recompute_g_strict(&tampered).unwrap());

        // Permute participant order -> SAME G (canonical_a sorts).
        let mut permuted = base.clone();
        permuted.participants.reverse();
        assert_eq!(g_base, recompute_g_strict(&permuted).unwrap());
    }
}
