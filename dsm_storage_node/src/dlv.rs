//! DLV slot and object addressing helpers (no signatures, no clocks)
//! Implements DLV slot and object-addressing derivations for the storage node model.

use blake3::{hash, Hasher};

const DOMAIN_DBRW: &[u8] = b"DSM/DBRW\0";
const DOMAIN_NODE: &[u8] = b"DSM/node\0";
const DOMAIN_STORAGE_DLV: &[u8] = b"DSM/storage/dlv\0";
const DOMAIN_MPC_ENTROPY: &[u8] = b"DSM/mpc/entropy\0";
const DOMAIN_OBJECT: &[u8] = b"DSM/object\0";

pub fn blake3_tagged(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(domain);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn derive_knode_dbrw(hw_entropy: &[u8], env_fp: &[u8]) -> [u8; 32] {
    let inner = hash(&[hw_entropy, env_fp].concat());
    blake3_tagged(DOMAIN_DBRW, &[inner.as_bytes()])
}

pub fn derive_node_id(genesis_g: &[u8], knode_dbrw: &[u8]) -> [u8; 32] {
    blake3_tagged(DOMAIN_NODE, &[genesis_g, knode_dbrw])
}

pub fn derive_dlv_slot(
    node_id: &[u8],
    i: u32,
    capacity_bytes: u64,
    stake_bytes: &[u8],
) -> [u8; 32] {
    let i_bytes = i.to_be_bytes();
    let c_bytes = capacity_bytes.to_be_bytes();
    blake3_tagged(
        DOMAIN_STORAGE_DLV,
        &[node_id, &i_bytes, &c_bytes, stake_bytes],
    )
}

pub fn derive_entropy_ei(fp: &[u8], dlv_i: &[u8]) -> [u8; 32] {
    blake3_tagged(DOMAIN_MPC_ENTROPY, &[fp, dlv_i])
}

pub fn derive_object_address(dlv_i: &[u8], path: &[u8], content_hash: &[u8]) -> [u8; 32] {
    blake3_tagged(DOMAIN_OBJECT, &[dlv_i, path, content_hash])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_derivations() {
        let hw = [1u8; 32];
        let env = [2u8; 32];
        let g = [3u8; 32];
        let stake = [4u8; 32];
        let k = derive_knode_dbrw(&hw, &env);
        let nid = derive_node_id(&g, &k);
        let dlv = derive_dlv_slot(&nid, 7, 1024, &stake);
        let ei = derive_entropy_ei(&[9u8; 32], &dlv);
        let addr = derive_object_address(&dlv, b"/bucket/a", &[8u8; 32]);
        assert_ne!(k, [0u8; 32]);
        assert_ne!(nid, [0u8; 32]);
        assert_ne!(dlv, [0u8; 32]);
        assert_ne!(ei, [0u8; 32]);
        assert_ne!(addr, [0u8; 32]);
    }
}
