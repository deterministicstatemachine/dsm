//! Canonical Genesis Anchor (A_0) — WP §2.5 / §4.2.1 / §11.1.
//!
//! Produces the byte-exact preimage that defines a genesis identifier:
//!
//!     G = BLAKE3("DSM/genesis\0" || canonical_a0_bytes(A_0))
//!
//! and the deterministic per-device PQ key material derived from it.
//!
//! Canonical encoding (this module is the normative reference for the dsm
//! crate; see proto/dsm_app.proto::GenesisA0V1 for the transport view):
//!
//!   Each field is emitted in fixed semantic order, each prefixed with its
//!   wire length as a u64 big-endian. No optional fields, no maps, no unknown
//!   fields. participants are bytes-only NodeIds in bytewise-ascending sort
//!   order. The schema_version is a fixed u64 (0x0002_0005_0000 == 2.5.0).
//!
//! Privacy invariant (HARD): K_DBRW (WP §12) MUST NOT appear in `GenesisA0`.
//! It is mixed only into the per-device key derivation in `derive_pq_keys`.

use crate::common::dbrw;
use crate::crypto::blake3::dsm_domain_hasher;
use crate::crypto::kyber;
use crate::crypto::sphincs::{self, SphincsVariant};
use crate::types::error::DsmError;
use crate::types::identifiers::NodeId;

/// DSM Schema 2.6.0 packed as `0xMMmm_PPPP_0000`.
///
/// 2.6.0 removed the decorative `threshold` field from the genesis preimage:
/// genesis MPC binds to every reveal in `participants_sorted`, so the
/// effective rule is always n-of-n and the recorded threshold value was
/// never operationally consulted.
pub const SCHEMA_VERSION_2_6_0: u64 = 0x0002_0006_0000;

/// Per-participant reveal in a genesis MPC session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisMpcReveal {
    pub node_id: Vec<u8>,
    pub reveal: [u8; 32],
}

/// Canonical anchor A_0. Byte-exact preimage of the genesis hash.
#[derive(Debug, Clone)]
pub struct GenesisA0 {
    pub session_id: [u8; 32],
    pub devid_a: [u8; 32],
    /// MUST be in bytewise-ascending order (caller responsibility; enforced
    /// by [`canonical_bytes`] returning an error otherwise).
    pub participants_sorted: Vec<Vec<u8>>,
    pub device_entropy: [u8; 32],
    /// Reveals MUST be in the same order as `participants_sorted` and each
    /// `node_id` MUST equal the corresponding entry in `participants_sorted`.
    pub mpc_reveals: Vec<GenesisMpcReveal>,
    pub metadata: Vec<u8>,
    pub schema_version: u64,
}

impl GenesisA0 {
    /// Build a canonical A_0 from raw inputs. Sorts participants/reveals
    /// jointly by node_id (bytewise ascending) so callers cannot smuggle
    /// non-canonical orderings.
    pub fn build(
        session_id: [u8; 32],
        devid_a: [u8; 32],
        participants: Vec<NodeId>,
        device_entropy: [u8; 32],
        node_reveals: Vec<(NodeId, [u8; 32])>,
        metadata: Vec<u8>,
    ) -> Result<Self, DsmError> {
        if participants.len() < 3 {
            return Err(DsmError::invalid_parameter(
                "GenesisA0: requires ≥3 participants",
            ));
        }
        if node_reveals.len() != participants.len() {
            return Err(DsmError::invalid_parameter(
                "GenesisA0: reveal count must equal participants count",
            ));
        }

        // Canonical sort: bytewise-ascending by node_id bytes.
        let mut paired: Vec<(Vec<u8>, [u8; 32])> = node_reveals
            .into_iter()
            .map(|(n, r)| (n.as_bytes().to_vec(), r))
            .collect();
        paired.sort_by(|a, b| a.0.cmp(&b.0));

        // Cross-check: the participants list must contain exactly these node_ids.
        let mut provided: Vec<Vec<u8>> =
            participants.iter().map(|n| n.as_bytes().to_vec()).collect();
        provided.sort();
        let reveal_ids: Vec<Vec<u8>> = paired.iter().map(|(n, _)| n.clone()).collect();
        if provided != reveal_ids {
            return Err(DsmError::invalid_parameter(
                "GenesisA0: participants and reveal node_ids must match (set equality)",
            ));
        }

        let participants_sorted = reveal_ids;
        let mpc_reveals = paired
            .into_iter()
            .map(|(n, r)| GenesisMpcReveal {
                node_id: n,
                reveal: r,
            })
            .collect();

        Ok(Self {
            session_id,
            devid_a,
            participants_sorted,
            device_entropy,
            mpc_reveals,
            metadata,
            schema_version: SCHEMA_VERSION_2_6_0,
        })
    }

    /// Emit the canonical byte preimage. Order is fixed, each variable-length
    /// field is prefixed with a u64-be length. Returns an error if internal
    /// invariants (sort order, reveal pairing) are violated.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DsmError> {
        // Re-validate sort order defensively.
        for w in self.participants_sorted.windows(2) {
            if w[0] >= w[1] {
                return Err(DsmError::invalid_parameter(
                    "GenesisA0: participants_sorted must be strictly ascending",
                ));
            }
        }
        if self.mpc_reveals.len() != self.participants_sorted.len() {
            return Err(DsmError::invalid_parameter(
                "GenesisA0: reveal count != participants count",
            ));
        }
        for (i, rev) in self.mpc_reveals.iter().enumerate() {
            if rev.node_id != self.participants_sorted[i] {
                return Err(DsmError::invalid_parameter(
                    "GenesisA0: reveal node_ids must align with participants_sorted",
                ));
            }
        }

        let mut out = Vec::with_capacity(256 + 64 * self.participants_sorted.len());

        // Field 1: session_id (fixed 32)
        out.extend_from_slice(&self.session_id);
        // Field 2: devid_a (fixed 32)
        out.extend_from_slice(&self.devid_a);
        // Field 3: participants_sorted (count u32-be, then each: u32-be len + bytes)
        let pcount = u32::try_from(self.participants_sorted.len())
            .map_err(|_| DsmError::invalid_parameter("GenesisA0: too many participants"))?;
        out.extend_from_slice(&pcount.to_be_bytes());
        for p in &self.participants_sorted {
            let plen = u32::try_from(p.len())
                .map_err(|_| DsmError::invalid_parameter("GenesisA0: participant too long"))?;
            out.extend_from_slice(&plen.to_be_bytes());
            out.extend_from_slice(p);
        }
        // Field 4: device_entropy (fixed 32)
        out.extend_from_slice(&self.device_entropy);
        // Field 5: mpc_reveals (count u32-be, then each: u32-be node_id_len + bytes + 32B reveal)
        let rcount = u32::try_from(self.mpc_reveals.len())
            .map_err(|_| DsmError::invalid_parameter("GenesisA0: too many reveals"))?;
        out.extend_from_slice(&rcount.to_be_bytes());
        for rev in &self.mpc_reveals {
            let nlen = u32::try_from(rev.node_id.len())
                .map_err(|_| DsmError::invalid_parameter("GenesisA0: node_id too long"))?;
            out.extend_from_slice(&nlen.to_be_bytes());
            out.extend_from_slice(&rev.node_id);
            out.extend_from_slice(&rev.reveal);
        }
        // Field 6: metadata (u32-be len + bytes)
        let mlen = u32::try_from(self.metadata.len())
            .map_err(|_| DsmError::invalid_parameter("GenesisA0: metadata too long"))?;
        out.extend_from_slice(&mlen.to_be_bytes());
        out.extend_from_slice(&self.metadata);
        // Field 7: schema_version (u64 be)
        out.extend_from_slice(&self.schema_version.to_be_bytes());

        Ok(out)
    }

    /// Compute the genesis identifier `G = BLAKE3("DSM/genesis\0" || canonical_bytes)`.
    pub fn genesis_id(&self) -> Result<[u8; 32], DsmError> {
        let bytes = self.canonical_bytes()?;
        let mut h = dsm_domain_hasher("DSM/genesis");
        h.update(&bytes);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        Ok(out)
    }

    /// Compute the A_0 digest `BLAKE3("DSM/a0\0" || canonical_bytes)`.
    pub fn a0_digest(&self) -> Result<[u8; 32], DsmError> {
        let bytes = self.canonical_bytes()?;
        let mut h = dsm_domain_hasher("DSM/a0");
        h.update(&bytes);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        Ok(out)
    }
}

/// Per-device deterministic PQ key material derived from `(G, DevID_A, K_DBRW)`
/// per WP §11.1. K_DBRW is read locally from `crate::common::dbrw` and
/// IMMEDIATELY discarded; it never appears in any field of the returned
/// struct.
#[derive(Debug, Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct DerivedPqKeys {
    pub sphincs_pk: Vec<u8>,
    pub sphincs_sk: Vec<u8>,
    pub kyber_pk: Vec<u8>,
    pub kyber_sk: Vec<u8>,
}

/// Derive deterministic SPHINCS+ and Kyber keypairs from the genesis hash and
/// device identity per WP §11.1. K_DBRW is mixed in but never returned.
pub fn derive_pq_keys(
    genesis_id: &[u8; 32],
    devid_a: &[u8; 32],
) -> Result<DerivedPqKeys, DsmError> {
    let mut k_dbrw = dbrw::binding_for(devid_a);

    // s_master = HKDF-Extract analogue via BLAKE3:
    //   s_master = BLAKE3("DSM/dev\0" || genesis_id || devid_a || K_DBRW)
    let mut h_master = dsm_domain_hasher("DSM/dev");
    h_master.update(genesis_id);
    h_master.update(devid_a);
    h_master.update(&k_dbrw);
    let mut s_master = [0u8; 32];
    s_master.copy_from_slice(h_master.finalize().as_bytes());

    // SPHINCS+ seed: BLAKE3("DSM/ek\0" || s_master)
    let mut h_sp = dsm_domain_hasher("DSM/ek");
    h_sp.update(&s_master);
    let mut sphincs_seed = [0u8; 32];
    sphincs_seed.copy_from_slice(h_sp.finalize().as_bytes());
    let sp_kp = sphincs::generate_keypair_from_seed(SphincsVariant::SPX256f, &sphincs_seed)?;

    // Kyber entropy: BLAKE3("DSM/kyber\0" || s_master)
    let mut h_ky = dsm_domain_hasher("DSM/kyber");
    h_ky.update(&s_master);
    let kyber_entropy = h_ky.finalize();
    let (kyber_pk, kyber_sk) =
        kyber::generate_kyber_keypair_from_entropy(kyber_entropy.as_bytes(), "DSM/genesis-pq")?;

    // Best-effort scrub of intermediate seeds. K_DBRW is a Copy [u8;32]; we
    // hold no other reference, but explicitly zeroize so this stack slot is
    // wiped before return.
    {
        use zeroize::Zeroize;
        s_master.zeroize();
        sphincs_seed.zeroize();
        k_dbrw.zeroize();
    }

    Ok(DerivedPqKeys {
        sphincs_pk: sp_kp.public_key.clone(),
        sphincs_sk: sp_kp.secret_key.clone(),
        kyber_pk,
        kyber_sk,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> Vec<NodeId> {
        vec![
            NodeId::new("node-c"),
            NodeId::new("node-a"),
            NodeId::new("node-b"),
        ]
    }

    #[test]
    fn build_sorts_participants_and_reveals() {
        let nodes = ids();
        let reveals = vec![
            (NodeId::new("node-c"), [0xCC; 32]),
            (NodeId::new("node-a"), [0xAA; 32]),
            (NodeId::new("node-b"), [0xBB; 32]),
        ];
        let a0 =
            GenesisA0::build([1; 32], [2; 32], nodes, [3; 32], reveals, b"meta".to_vec()).unwrap();
        let order: Vec<&[u8]> = a0
            .participants_sorted
            .iter()
            .map(|v| v.as_slice())
            .collect();
        let expected: Vec<&[u8]> = vec![b"node-a", b"node-b", b"node-c"];
        assert_eq!(order, expected);
        assert_eq!(a0.mpc_reveals[0].reveal, [0xAA; 32]);
        assert_eq!(a0.mpc_reveals[1].reveal, [0xBB; 32]);
        assert_eq!(a0.mpc_reveals[2].reveal, [0xCC; 32]);
    }

    #[test]
    fn build_rejects_below_three_participants() {
        let nodes = vec![NodeId::new("node-a"), NodeId::new("node-b")];
        let reveals = vec![
            (NodeId::new("node-a"), [0xAA; 32]),
            (NodeId::new("node-b"), [0xBB; 32]),
        ];
        let err = GenesisA0::build([0; 32], [0; 32], nodes, [0; 32], reveals, vec![]).unwrap_err();
        assert!(format!("{err:?}").contains("participants"));
    }

    #[test]
    fn build_rejects_mismatched_participants_and_reveals() {
        let nodes = ids();
        let reveals = vec![
            (NodeId::new("node-a"), [0xAA; 32]),
            (NodeId::new("node-b"), [0xBB; 32]),
            (NodeId::new("node-z"), [0xCC; 32]),
        ];
        let err = GenesisA0::build([0; 32], [0; 32], nodes, [0; 32], reveals, vec![]).unwrap_err();
        assert!(format!("{err:?}").contains("set equality"));
    }

    #[test]
    fn canonical_bytes_are_byte_stable() {
        let nodes = ids();
        let reveals = vec![
            (NodeId::new("node-a"), [0xAA; 32]),
            (NodeId::new("node-b"), [0xBB; 32]),
            (NodeId::new("node-c"), [0xCC; 32]),
        ];
        let a0 = GenesisA0::build(
            [1; 32],
            [2; 32],
            nodes.clone(),
            [3; 32],
            reveals.clone(),
            b"meta".to_vec(),
        )
        .unwrap();
        let bytes1 = a0.canonical_bytes().unwrap();
        let a0b =
            GenesisA0::build([1; 32], [2; 32], nodes, [3; 32], reveals, b"meta".to_vec()).unwrap();
        let bytes2 = a0b.canonical_bytes().unwrap();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn genesis_id_changes_with_participants() {
        let reveals_3 = vec![
            (NodeId::new("node-a"), [0xAA; 32]),
            (NodeId::new("node-b"), [0xBB; 32]),
            (NodeId::new("node-c"), [0xCC; 32]),
        ];
        let reveals_4 = vec![
            (NodeId::new("node-a"), [0xAA; 32]),
            (NodeId::new("node-b"), [0xBB; 32]),
            (NodeId::new("node-c"), [0xCC; 32]),
            (NodeId::new("node-d"), [0xDD; 32]),
        ];
        let a0_3 = GenesisA0::build([1; 32], [2; 32], ids(), [3; 32], reveals_3, vec![]).unwrap();
        let a0_4 = GenesisA0::build(
            [1; 32],
            [2; 32],
            vec![
                NodeId::new("node-a"),
                NodeId::new("node-b"),
                NodeId::new("node-c"),
                NodeId::new("node-d"),
            ],
            [3; 32],
            reveals_4,
            vec![],
        )
        .unwrap();
        assert_ne!(a0_3.genesis_id().unwrap(), a0_4.genesis_id().unwrap());
    }

    #[test]
    fn derive_pq_keys_is_deterministic() {
        let g = [0x11; 32];
        let dev = [0x22; 32];
        let k1 = derive_pq_keys(&g, &dev).unwrap();
        let k2 = derive_pq_keys(&g, &dev).unwrap();
        assert_eq!(k1.sphincs_pk, k2.sphincs_pk);
        assert_eq!(k1.kyber_pk, k2.kyber_pk);
        assert_eq!(k1.sphincs_sk, k2.sphincs_sk);
        assert_eq!(k1.kyber_sk, k2.kyber_sk);
    }

    #[test]
    fn derive_pq_keys_differs_per_devid() {
        let g = [0x11; 32];
        let k_a = derive_pq_keys(&g, &[0xAA; 32]).unwrap();
        let k_b = derive_pq_keys(&g, &[0xBB; 32]).unwrap();
        assert_ne!(k_a.sphincs_pk, k_b.sphincs_pk);
        assert_ne!(k_a.kyber_pk, k_b.kyber_pk);
    }

    #[test]
    fn derive_pq_keys_differs_per_genesis() {
        let dev = [0x22; 32];
        let k_a = derive_pq_keys(&[0x01; 32], &dev).unwrap();
        let k_b = derive_pq_keys(&[0x02; 32], &dev).unwrap();
        assert_ne!(k_a.sphincs_pk, k_b.sphincs_pk);
        assert_ne!(k_a.kyber_pk, k_b.kyber_pk);
    }
}
