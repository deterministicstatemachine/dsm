// SPDX-License-Identifier: Apache-2.0

//! A real identity for the integration tests: derived from a wallet seed, with
//! its own signed directory entry and the P0–P6 evidence a wallet publishes in
//! it. The GRK delegates root progression to the AK (`D_0`), the AK installs
//! the single-device tree (`T_0`), and the device's leaf is proved under it.

use prost::Message;

use dsm::ccb::{
    delegation_genesis_sentinel, role, sigalg, transition_genesis_sentinel,
    DeviceTreeRootTransition, GenesisParamsV3, RootProgressionDelegation,
};
use dsm::common::device_tree::DeviceTree;
use dsm::core::identity::directory::{DirectoryEntry, DirectoryEntryBody, KYBER_PUBLIC_KEY_LEN};
use dsm::core::identity::genesis_v2::{derive_atta, genesis_authority_policy_hash};
use dsm::core::identity::genesis_v3::derive_genesis_v3_self_attested;
use dsm::crypto::sphincs;
use dsm::types::proto;

const NETWORK: &[u8] = b"dsm-testnet";

/// A device's identity: its genesis, device id, AttA, AK pair and its own
/// signed directory entry's bytes.
pub struct Identity {
    pub genesis: [u8; 32],
    pub devid: [u8; 32],
    pub att_a: [u8; 32],
    pub ak_public_key: Vec<u8>,
    pub ak_secret_key: Vec<u8>,
    pub directory_entry: Vec<u8>,
}

/// The identity of the wallet seed `[seed; 64]`.
pub fn identity(seed: u8) -> Identity {
    let wallet_seed = [seed; 64];
    let genesis = derive_genesis_v3_self_attested(
        &wallet_seed,
        NETWORK,
        0,
        0,
        3,
        &genesis_authority_policy_hash(),
    )
    .expect("genesis");
    let params = GenesisParamsV3::new(
        genesis.genesis_nonce,
        NETWORK,
        3,
        sigalg::SPHINCS_PLUS_SPX256F,
        &genesis.grk_public,
    )
    .expect("params");
    let d0 = RootProgressionDelegation {
        genesis_id: genesis.g,
        role: role::DEVICE_TREE_ROOT_PROGRESSION,
        role_version: role::BETA_ROLE_VERSION,
        delegated_alg_id: sigalg::SPHINCS_PLUS_SPX256F,
        delegated_pk: genesis.ak_public.clone(),
        delegation_number: 0,
        parent_delegation_digest: delegation_genesis_sentinel(),
        activation_transition_digest: transition_genesis_sentinel(),
    };
    let d0_signature = sphincs::sphincs_sign(
        &genesis.grk_secret,
        &d0.signing_digest().expect("D_0 digest"),
    )
    .expect("GRK signs D_0");
    let tree = DeviceTree::single(genesis.devid);
    let t0 = DeviceTreeRootTransition {
        genesis_id: genesis.g,
        predecessor_transition_digest: transition_genesis_sentinel(),
        new_root: tree.root(),
        version_number: 0,
        delegation_digest: d0.digest().expect("D_0"),
    };
    let t0_signature =
        sphincs::sphincs_sign(&genesis.ak_secret, &t0.signing_digest()).expect("AK signs T_0");
    let att_a = derive_atta(&wallet_seed, &genesis.g, 0);
    let evidence = proto::AuthorityEvidenceV1 {
        genesis_params_ccb: params.encode().expect("params"),
        delegations: vec![proto::SignedAuthorityObjectV1 {
            ccb: d0.encode().expect("D_0"),
            signature: d0_signature,
        }],
        transitions: vec![proto::SignedAuthorityObjectV1 {
            ccb: t0.encode(),
            signature: t0_signature,
        }],
        inclusion_proof: tree.proof(&genesis.devid).expect("own leaf").to_bytes(),
        ak_public_key: genesis.ak_public.clone(),
        atta: att_a.to_vec(),
    };
    let body = DirectoryEntryBody {
        genesis: genesis.g,
        device_id: genesis.devid,
        ak_public_key: genesis.ak_public.clone(),
        att_a,
        kyber_public_key: vec![seed; KYBER_PUBLIC_KEY_LEN],
        counter: 1,
        authority_position: t0.digest(),
        authority_evidence: evidence.encode_to_vec(),
    };
    let entry = DirectoryEntry::sign(body, &genesis.ak_secret).expect("the AK signs its entry");
    Identity {
        genesis: genesis.g,
        devid: genesis.devid,
        att_a,
        ak_public_key: genesis.ak_public.clone(),
        ak_secret_key: genesis.ak_secret.clone(),
        directory_entry: entry.encode(),
    }
}
