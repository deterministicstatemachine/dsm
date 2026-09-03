// SPDX-License-Identifier: MIT OR Apache-2.0

//! Test fixture: devices that hold what the PROTOCOL gave them, and vaults born
//! through the PRODUCTION route.
//!
//! Every balance a device holds here was produced by the same path that
//! produces it in the real system — a faucet admission for ERA, an admitted
//! `token.create` + `token.mint` for a user asset — and every vault was created
//! by the real `dlv.create` handler, which is the only thing that encumbers
//! reserves. There is deliberately no way here to install a balance, a reserve
//! or an admission directly: a fixture that could would let a test go green
//! against a state the product can never reach, which is exactly the shape
//! that kept a settled swap moving zero value for months.
//!
//! What a test may still hand a router directly is an EMPTY head carrying the
//! real installed identity ([`observer_device`]). Having nothing is not an
//! economic claim.

#![cfg(test)]

use dsm::types::device_state::DeviceState;

/// Install a REAL v3 identity for `seed` — the state-identity cut derives
/// every vault birth's authority chain (GRK → D_0 → T_0) from the wallet
/// seed, so fixture identities must be seed-rooted exactly like production
/// ones. Persists the genesis record (the presentation builder reads its
/// derivation inputs back from it, network id in particular), installs the
/// signing authority from the SAME wallet seed (the signing cache IS the
/// wallet-seed cache), and primes AppState. The database must already be
/// initialized. Returns `(signing_public_key, device_id)`.
pub(crate) fn install_v3_identity(seed: u8) -> (Vec<u8>, [u8; 32]) {
    install_v3_identity_on_fleet(seed, &[])
}

/// As [`install_v3_identity`], but records `endpoints` as the identity's
/// storage nodes.
///
/// A funded creation is an ADMITTED economic operation, and admission
/// resolves its root register from the network the genesis record commits.
/// Only the beta network `dsm-testnet` has a register profile — an unknown
/// network fails closed by design — so the fixture commits that, exactly like
/// `test_support::two_device::TestDevice`. The endpoints are what
/// `finish_admission` publishes evidence to and reads quorum from.
pub(crate) fn install_v3_identity_on_fleet(seed: u8, endpoints: &[String]) -> (Vec<u8>, [u8; 32]) {
    let wallet_seed = vec![seed; 64];
    let aph = dsm::core::identity::genesis_session::genesis_authority_policy_hash();
    let genesis = dsm::core::identity::genesis_v3::derive_genesis_v3_self_attested(
        &wallet_seed,
        b"dsm-testnet",
        0,
        0,
        3,
        &aph,
    )
    .expect("v3 genesis");
    let device_id = genesis.devid.to_vec();
    let genesis_hash = genesis.g.to_vec();
    crate::sdk::signing_authority::clear_binding_key_for_testing();
    let (public_key, _sk) = crate::sdk::signing_authority::derive_signing_keys_for_testing(
        &device_id,
        &genesis_hash,
        &wallet_seed,
    )
    .expect("derive signing keypair");
    crate::sdk::signing_authority::set_binding_key_for_testing(wallet_seed);
    crate::storage::client_db::store_genesis_record_with_verification(
        &crate::storage::client_db::GenesisRecord {
            genesis_id: crate::util::text_id::encode_base32_crockford(&genesis.g),
            device_id: crate::util::text_id::encode_base32_crockford(&genesis.devid),
            mpc_proof: String::new(),
            device_birth_binding: String::new(),
            merkle_root: crate::util::text_id::encode_base32_crockford(&[0u8; 32]),
            participant_count: 0,
            progress_marker: "genesis".to_string(),
            publication_hash: crate::util::text_id::encode_base32_crockford(&genesis.g),
            storage_nodes: endpoints.to_vec(),
            entropy_hash: crate::util::text_id::encode_base32_crockford(&genesis.genesis_nonce),
            protocol_version: "genesis-v3".to_string(),
            hash_chain_proof: None,
            smt_proof: None,
            verification_step: None,
            genesis_nonce: crate::util::text_id::encode_base32_crockford(&genesis.genesis_nonce),
            genesis_profile: "MnemonicV3".to_string(),
            network_id: "dsm-testnet".to_string(),
        },
    )
    .expect("store genesis record");
    crate::sdk::app_state::AppState::set_identity_info(
        device_id,
        public_key.clone(),
        genesis_hash,
        vec![0u8; 32],
    );
    crate::sdk::app_state::AppState::set_has_identity(true);
    (public_key, genesis.devid)
}

/// The public key a fixture head must carry: the CURRENTLY INSTALLED signing
/// key. `DeviceState::advance` verifies `DlvSettle` / `DlvOwnerApply` against
/// the advancing device's own key, so a head whose `public_key` is not the key
/// the signer actually holds cannot authorize its own transitions.
fn fixture_public_key() -> Vec<u8> {
    crate::sdk::signing_authority::current_public_key().expect("an identity must be installed")
}

/// Fund `router`'s device through REAL ADMITTED ORIGINS and return the two
/// asset commits, canonically ordered.
///
/// ```text
/// faucet claim            ERA, admitted via 0x0030
/// token.create AAA/BBB    the creation fee, admitted; policies signed by the
///                         DEVICE's real key, which is what lets the mint's
///                         0x0029 authorization verify
/// token.mint  a / b       admitted via 0x0029 -> 0x0023
/// ```
///
/// One faucet claim covers both creation fees. The amounts are assigned by
/// COMMIT ORDER — `a` belongs to the lower commit — and the commits are not
/// known until the policies exist, which is why they come back from here
/// rather than being computed up front: a commit computed any other way names
/// a policy no device can issue under.
pub(crate) fn admitted_device_holding(
    router: &crate::handlers::app_router_impl::AppRouterImpl,
    a: u64,
    b: u64,
) -> ([u8; 32], [u8; 32]) {
    use crate::bridge::{AppInvoke, AppRouter};
    use dsm::types::proto as generated;
    use prost::Message as _;

    let pack = |body: Vec<u8>| {
        generated::ArgPack {
            schema_hash: Some(generated::Hash32 { v: vec![0u8; 32] }),
            codec: generated::Codec::Proto as i32,
            body,
        }
        .encode_to_vec()
    };

    // The head must carry the REAL identity and NOTHING else. Economic
    // admissions re-derive and re-verify everything from (G, DevID), so a
    // lazily-bootstrapped zero-genesis head cannot admit; and it must be EMPTY,
    // because `activate` refuses to self-root a device already holding value.
    // Position 0 with the real identity is the only state that can become
    // position 1.
    router
        .core_sdk
        .set_device_head_for_testing(observer_device());

    crate::runtime::get_runtime().block_on(async {
        crate::sdk::faucet_claim_flow::claim_era_faucet(&router.core_sdk, b"dsm-testnet")
            .await
            .expect("fixture: faucet claim must admit");
        for ticker in ["AAA", "BBB"] {
            let created = router
                .invoke(AppInvoke {
                    method: "token.create".into(),
                    args: pack(
                        generated::TokenCreateRequest {
                            ticker: ticker.into(),
                            alias: format!("{ticker} Test Asset"),
                            decimals: 0,
                            max_supply_u128: 0u128.to_be_bytes().to_vec(),
                            initial_alloc_u128: 0u128.to_be_bytes().to_vec(),
                            mint_burn_enabled: true,
                            transferable: true,
                            unlimited_supply: true,
                            mint_burn_threshold: 1,
                            description: String::new(),
                            icon_url: String::new(),
                            allowlist_device_ids: Vec::new(),
                        }
                        .encode_to_vec(),
                    ),
                })
                .await;
            assert!(
                created.success,
                "fixture: token.create {ticker}: {:?}",
                created.error_message
            );
        }
        let commit_of = |ticker: &str| {
            crate::storage::client_db::token_registry::get_token_by_ticker(ticker)
                .expect("registry read")
                .unwrap_or_else(|| panic!("fixture: {ticker} not registered"))
                .policy_commit
        };
        let (lo_t, hi_t) = if commit_of("AAA") < commit_of("BBB") {
            ("AAA", "BBB")
        } else {
            ("BBB", "AAA")
        };
        for (ticker, amount) in [(lo_t, a), (hi_t, b)] {
            if amount == 0 {
                continue;
            }
            let minted = router
                .invoke(AppInvoke {
                    method: "token.mint".into(),
                    args: pack(
                        generated::TokenMintRequest {
                            token_id: ticker.into(),
                            amount,
                            message: String::new(),
                        }
                        .encode_to_vec(),
                    ),
                })
                .await;
            assert!(
                minted.success,
                "fixture: token.mint {ticker} {amount}: {:?}",
                minted.error_message
            );
        }
    });

    let commit = |ticker: &str| {
        crate::storage::client_db::token_registry::get_token_by_ticker(ticker)
            .expect("registry read")
            .unwrap_or_else(|| panic!("fixture: {ticker} not registered"))
            .policy_commit
    };
    let (x, y) = (commit("AAA"), commit("BBB"));
    if x < y {
        (x, y)
    } else {
        (y, x)
    }
}

/// A device that holds NO economic position and never claims one.
///
/// For tests whose device exists only to receive published bytes, read an
/// advertisement, verify foreign lineage, or exercise artifact transport. It
/// carries the REAL installed identity — so anything it publishes or signs is
/// genuine — and zero balances, zero reserves, position 0. Having nothing is
/// the POINT, not an unfunded accident: a reader cannot reach for it to stand
/// in for a holder.
pub(crate) fn observer_device() -> DeviceState {
    let genesis: [u8; 32] = crate::sdk::app_state::AppState::get_genesis_hash()
        .unwrap_or_default()
        .as_slice()
        .try_into()
        .expect("observer_device: an identity must be installed first");
    let devid: [u8; 32] = crate::sdk::app_state::AppState::get_device_id()
        .unwrap_or_default()
        .as_slice()
        .try_into()
        .expect("observer_device: an identity must be installed first");
    DeviceState::new(genesis, devid, fixture_public_key(), 1024)
}

/// Create a funded AMM vault through the REAL `dlv.create` route and return its
/// id.
///
/// This is the mandatory producer for a market-active vault: the same handler
/// the app calls, including the five birth objects it freezes and publishes.
/// A vault any other way is one the production path can never produce.
pub(crate) fn create_funded_amm_vault(
    router: &crate::handlers::app_router_impl::AppRouterImpl,
    pc_a: &[u8; 32],
    pc_b: &[u8; 32],
    reserve_a: u64,
    reserve_b: u64,
) -> [u8; 32] {
    use crate::bridge::{AppInvoke, AppRouter};
    use dsm::types::proto as generated;
    use prost::Message as _;

    let (lo, hi) = if pc_a <= pc_b {
        (pc_a, pc_b)
    } else {
        (pc_b, pc_a)
    };
    let fulfillment = generated::FulfillmentMechanism {
        kind: Some(generated::fulfillment_mechanism::Kind::AmmConstantProduct(
            generated::AmmConstantProduct {
                token_a: lo.to_vec(),
                token_b: hi.to_vec(),
                fee_bps: 30,
            },
        )),
    }
    .encode_to_vec();
    let req = generated::DlvInstantiateV1 {
        spec: Some(generated::DlvSpecV1 {
            policy_digest: vec![0x5Au8; 32],
            fulfillment_bytes: fulfillment,
            anchor_enforcement: generated::AnchorEnforcement::Required as i32,
            ..Default::default()
        }),
        creator_public_key: Vec::new(),
        signature: Vec::new(),
        funding_legs: vec![
            generated::DlvFundingLegV1 {
                policy_commit: pc_a.to_vec(),
                amount: reserve_a,
            },
            generated::DlvFundingLegV1 {
                policy_commit: pc_b.to_vec(),
                amount: reserve_b,
            },
        ],
    };
    let args = generated::ArgPack {
        schema_hash: Some(generated::Hash32 { v: vec![0u8; 32] }),
        codec: generated::Codec::Proto as i32,
        body: req.encode_to_vec(),
    }
    .encode_to_vec();
    let res = crate::runtime::get_runtime().block_on(async {
        router
            .invoke(AppInvoke {
                method: "dlv.create".to_string(),
                args,
            })
            .await
    });
    assert!(
        res.success,
        "fixture: dlv.create failed: {:?}",
        res.error_message
    );
    crate::storage::client_db::amm_vault_records::list_amm_vault_records()
        .expect("fixture: list vault records")
        .pop()
        .expect("fixture: dlv.create recorded exactly one vault")
        .vault_id
}

#[cfg(test)]
mod tests {
    use dsm::vault::FulfillmentMechanism;
    use prost::Message;

    /// RESERVE-FREE PREDICATE SERIALIZATION.
    ///
    /// The unlock condition names a pair and a fee — never a quantity — in
    /// memory AND on the wire. If a reserve could round-trip through the proto,
    /// the old model (liquidity asserted by the owner, held by nobody) would
    /// survive in serialized form and reappear on the next decode.
    #[test]
    fn the_predicate_serializes_without_reserves() {
        let predicate = FulfillmentMechanism::AmmConstantProduct {
            token_a: b"AAA".to_vec(),
            token_b: b"BBB".to_vec(),
            fee_bps: 30,
        };

        let proto: dsm::types::proto::FulfillmentMechanism = (&predicate).into();
        let bytes = proto.encode_to_vec();
        let back = dsm::types::proto::FulfillmentMechanism::decode(&*bytes).expect("decode");
        let round = FulfillmentMechanism::try_from(back).expect("convert back");

        match (&predicate, &round) {
            (
                FulfillmentMechanism::AmmConstantProduct {
                    token_a: a1,
                    token_b: b1,
                    fee_bps: f1,
                },
                FulfillmentMechanism::AmmConstantProduct {
                    token_a: a2,
                    token_b: b2,
                    fee_bps: f2,
                },
            ) => {
                assert_eq!((a1, b1, f1), (a2, b2, f2), "pair and fee survive");
            }
            other => panic!("expected an AMM predicate both sides, got {other:?}"),
        }
    }
}
