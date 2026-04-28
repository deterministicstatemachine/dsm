// SPDX-License-Identifier: MIT OR Apache-2.0
//! Self-contained DeTFi backend demo.
//!
//! Single public entry point — `run_amm_e2e_demo()` — that walks the
//! entire AMM trade pipeline in one process and returns a structured
//! transcript.  Designed for the `cargo run --example detfi_demo
//! --features demos` invocation: the example just calls this and
//! prints each step.
//!
//! Built behind the `demos` Cargo feature so the in-process mock
//! storage backend is available.  Production builds never see this
//! module.
//!
//! What it proves
//! --------------
//!   * Bob publishes an AMM routing-vault advertisement.
//!   * Alice discovers it, runs path search, builds + signs a
//!     `RouteCommitV1`, computes `X`, publishes the anchor.
//!   * The chunk #4/#5 eligibility gate (SPHINCS+ verify, vault-in-
//!     route, anchor-visible) passes.
//!   * The chunk #7 AMM re-simulation gate passes; trade settles;
//!     reserves advance per the constant-product invariant.
//!   * A second swap signed against STALE reserves is rejected at
//!     the chunk #7 gate with a typed `OutputMismatch`.
//!   * A fresh swap against the post-trade reserves succeeds.

use prost::Message as _;

use crate::sdk::route_commit_sdk::{
    bind_path_to_route_commit, canonicalise_for_commitment, compute_external_commitment,
    is_external_commitment_visible, publish_external_commitment, verify_amm_swap_against_reserves,
    verify_route_commit_unlock_eligibility, AmmVerifyError, BindRouteCommitInput,
};
use crate::sdk::routing_path_sdk::{constant_product_output, find_best_path, DEFAULT_MAX_HOPS};
use crate::sdk::routing_sdk::{
    load_active_advertisements_for_pair, publish_active_advertisement, PublishRoutingAdInput,
};
use dsm::crypto::sphincs::{generate_keypair, sign as sphincs_sign, SphincsVariant};
use dsm::vault::FulfillmentMechanism;

/// One step in the demo transcript.  Carries human-readable narration
/// plus the structured outcome so the example can render either form.
#[derive(Debug, Clone)]
pub struct DemoStep {
    pub label: String,
    pub detail: String,
}

/// Final report of the demo run.  All assertions internal to
/// `run_amm_e2e_demo` returned `Ok` — failure surfaces as
/// `Err(String)` from the entry point with the failing step's name.
#[derive(Debug, Clone)]
pub struct DemoReport {
    pub steps: Vec<DemoStep>,
    pub initial_reserve_a: u128,
    pub initial_reserve_b: u128,
    pub trade_1_input: u128,
    pub trade_1_output: u128,
    pub trade_1_post_reserve_a: u128,
    pub trade_1_post_reserve_b: u128,
    pub stale_attack_simulated_output: u128,
    pub stale_attack_expected_output: u128,
    pub trade_2_input: u128,
    pub trade_2_output: u128,
}

/// Run the full AMM trade pipeline end-to-end.  Self-contained: no
/// frontend, no real network.  Storage backend is the in-process mock
/// gated by the `demos` feature.
pub async fn run_amm_e2e_demo() -> Result<DemoReport, String> {
    let mut steps: Vec<DemoStep> = Vec::new();
    macro_rules! step {
        ($label:expr, $detail:expr) => {
            steps.push(DemoStep {
                label: $label.to_string(),
                detail: $detail,
            });
        };
    }

    // ── Setup ────────────────────────────────────────────────────────
    let alice =
        generate_keypair(SphincsVariant::SPX256f).map_err(|e| format!("alice keygen: {e}"))?;
    let bob = generate_keypair(SphincsVariant::SPX256f).map_err(|e| format!("bob keygen: {e}"))?;
    let token_aaa = b"DEMO_AAA".to_vec();
    let token_bbb = b"DEMO_BBB".to_vec();
    let vault_id = {
        let mut v = [0u8; 32];
        v[0] = 0xDE;
        v[1] = 0x70;
        v[31] = 0xA1;
        v
    };
    let initial_reserve_a: u128 = 1_000_000;
    let initial_reserve_b: u128 = 1_000_000;
    let fee_bps: u32 = 30;
    let trade_input: u128 = 10_000;
    step!(
        "setup",
        format!(
            "Alice + Bob keypairs (SPHINCS+ SPX256f); pair DEMO_AAA/DEMO_BBB; \
             initial reserves = ({initial_reserve_a}, {initial_reserve_b}); \
             fee = {fee_bps} bps; trade input = {trade_input}"
        )
    );

    let mut bobs_fulfillment = FulfillmentMechanism::AmmConstantProduct {
        token_a: token_aaa.clone(),
        token_b: token_bbb.clone(),
        reserve_a: initial_reserve_a,
        reserve_b: initial_reserve_b,
        fee_bps,
    };

    // ── 1. Bob publishes the routing-vault ad ────────────────────────
    let vault_proto_bytes = format!(
        "demo-vault-proto-bytes-{}",
        crate::util::text_id::encode_base32_crockford(&vault_id)
    )
    .into_bytes();
    publish_active_advertisement(PublishRoutingAdInput {
        vault_id: &vault_id,
        token_a: &token_aaa,
        token_b: &token_bbb,
        reserve_a_u128: initial_reserve_a.to_be_bytes(),
        reserve_b_u128: initial_reserve_b.to_be_bytes(),
        fee_bps,
        unlock_spec_digest: [0u8; 32],
        unlock_spec_key: "defi/spec/demo".to_string(),
        owner_public_key: &bob.public_key,
        vault_proto_bytes: &vault_proto_bytes,
    })
    .await
    .map_err(|e| format!("step 1 publish_active_advertisement: {e}"))?;
    step!(
        "1. Bob publishes routing-vault advertisement",
        format!(
            "vault_id={} (Base32); reserves at publish time = ({}, {})",
            crate::util::text_id::encode_base32_crockford(&vault_id),
            initial_reserve_a,
            initial_reserve_b
        )
    );

    // ── 2. Alice discovers ───────────────────────────────────────────
    let advert_set = load_active_advertisements_for_pair(&token_aaa, &token_bbb)
        .await
        .map_err(|e| format!("step 2 list ads: {e}"))?;
    if advert_set.len() != 1 {
        return Err(format!(
            "step 2: expected exactly 1 advertised vault, got {}",
            advert_set.len()
        ));
    }
    step!(
        "2. Alice lists advertisements for the pair",
        format!(
            "{} ad(s) discovered, vault_id={}",
            advert_set.len(),
            crate::util::text_id::encode_base32_crockford(&advert_set[0].advertisement.vault_id)
        )
    );
    let ads_for_search: Vec<_> = advert_set.into_iter().map(|p| p.advertisement).collect();

    // ── 3. Alice runs path search ────────────────────────────────────
    let path = find_best_path(
        &ads_for_search,
        &token_aaa,
        &token_bbb,
        trade_input,
        DEFAULT_MAX_HOPS,
    )
    .map_err(|e| format!("step 3 find_best_path: {e:?}"))?;
    let route_quoted_output = path.final_output_amount;
    step!(
        "3. Alice runs path search",
        format!(
            "single-hop A→B; quoted output = {route_quoted_output}; total fee_bps = {}",
            path.total_fee_bps
        )
    );

    // ── 4. Alice binds + signs ───────────────────────────────────────
    let nonce_1 = {
        let mut n = [0u8; 32];
        n[0] = 0x01;
        n[1] = 0x77;
        n[31] = 0x55;
        n
    };
    let unsigned_rc = bind_path_to_route_commit(BindRouteCommitInput {
        path: &path,
        nonce: nonce_1,
        initiator_public_key: &alice.public_key,
        initiator_signature: vec![],
    })
    .map_err(|e| format!("step 4 bind: {e:?}"))?;
    let canonical_bytes = canonicalise_for_commitment(&unsigned_rc).encode_to_vec();
    let alice_sig = sphincs_sign(SphincsVariant::SPX256f, &alice.secret_key, &canonical_bytes)
        .map_err(|e| format!("step 4 sign: {e}"))?;
    let mut signed_rc = unsigned_rc.clone();
    signed_rc.initiator_signature = alice_sig;
    let signed_rc_bytes = signed_rc.encode_to_vec();
    step!(
        "4. Alice binds + signs the RouteCommit",
        format!(
            "canonical_bytes={} bytes; SPHINCS+ signature = {} bytes",
            canonical_bytes.len(),
            signed_rc.initiator_signature.len()
        )
    );

    // ── 5. Alice publishes external commitment ───────────────────────
    let x_1 = compute_external_commitment(&signed_rc);
    publish_external_commitment(&x_1, &alice.public_key, "trade-1")
        .await
        .map_err(|e| format!("step 5 publish anchor: {e}"))?;
    if !is_external_commitment_visible(&x_1)
        .await
        .map_err(|e| format!("step 5 visibility: {e}"))?
    {
        return Err("step 5: anchor not visible after publish".into());
    }
    step!(
        "5. Alice publishes the external commitment X",
        format!(
            "X = BLAKE3(\"DSM/ext\\0\", canonical) = {} (Base32); anchor visible",
            crate::util::text_id::encode_base32_crockford(&x_1)
        )
    );

    // ── 6. Eligibility gate (chunks #4 + #5) ─────────────────────────
    let bound_hop = verify_route_commit_unlock_eligibility(&signed_rc_bytes, &vault_id)
        .await
        .map_err(|e| format!("step 6 eligibility: {e:?}"))?;
    step!(
        "6. Eligibility gate (chunks #4 + #5)",
        "PASS — SPHINCS+ verified, hop matches vault, X anchor visible".into()
    );

    // ── 7. AMM re-simulation gate (chunk #7) ─────────────────────────
    let outcome = verify_amm_swap_against_reserves(&bound_hop, &bobs_fulfillment)
        .map_err(|e| format!("step 7 AMM gate: {e:?}"))?
        .ok_or_else(|| "step 7: vault unexpectedly non-AMM".to_string())?;
    let pre_k = initial_reserve_a * initial_reserve_b;
    let post_k = outcome.new_reserve_a * outcome.new_reserve_b;
    if post_k < pre_k {
        return Err(format!(
            "step 7: constant-product invariant violated (pre_k={pre_k}, post_k={post_k})"
        ));
    }
    step!(
        "7. AMM re-simulation gate (chunk #7)",
        format!(
            "PASS — output = {route_quoted_output}; new reserves = ({}, {}); \
             pre_k = {pre_k}; post_k = {post_k}; k non-decreasing ✓",
            outcome.new_reserve_a, outcome.new_reserve_b
        )
    );
    let trade_1_post_a = outcome.new_reserve_a;
    let trade_1_post_b = outcome.new_reserve_b;

    // ── 8. Trade 1 settles; vault state advances ─────────────────────
    if let FulfillmentMechanism::AmmConstantProduct {
        ref mut reserve_a,
        ref mut reserve_b,
        ..
    } = bobs_fulfillment
    {
        *reserve_a = trade_1_post_a;
        *reserve_b = trade_1_post_b;
    } else {
        return Err("step 8: vault changed type — impossible".into());
    }
    step!(
        "8. Trade 1 settles",
        format!("Bob's vault state advances: reserves = ({trade_1_post_a}, {trade_1_post_b})")
    );

    // ── 9. Stale-reserves attack ─────────────────────────────────────
    let nonce_stale = {
        let mut n = [0u8; 32];
        n[0] = 0x02;
        n[1] = 0x77;
        n[31] = 0x66;
        n
    };
    let stale_unsigned = bind_path_to_route_commit(BindRouteCommitInput {
        path: &path, // ← original path with PRE-trade-1 reserves
        nonce: nonce_stale,
        initiator_public_key: &alice.public_key,
        initiator_signature: vec![],
    })
    .map_err(|e| format!("step 9 bind: {e:?}"))?;
    let stale_canonical = canonicalise_for_commitment(&stale_unsigned).encode_to_vec();
    let stale_sig = sphincs_sign(SphincsVariant::SPX256f, &alice.secret_key, &stale_canonical)
        .map_err(|e| format!("step 9 sign: {e}"))?;
    let mut stale_signed = stale_unsigned;
    stale_signed.initiator_signature = stale_sig;
    let x_stale = compute_external_commitment(&stale_signed);
    publish_external_commitment(&x_stale, &alice.public_key, "trade-2-stale")
        .await
        .map_err(|e| format!("step 9 publish anchor: {e}"))?;
    let stale_hop =
        verify_route_commit_unlock_eligibility(&stale_signed.encode_to_vec(), &vault_id)
            .await
            .map_err(|e| format!("step 9 eligibility: {e:?}"))?;
    let (sim, exp) = match verify_amm_swap_against_reserves(&stale_hop, &bobs_fulfillment) {
        Err(AmmVerifyError::OutputMismatch {
            simulated,
            expected,
        }) => (simulated, expected),
        other => {
            return Err(format!(
                "step 9: stale-reserves attack must reject with OutputMismatch; got {other:?}"
            ));
        }
    };
    let live = constant_product_output(trade_input, trade_1_post_a, trade_1_post_b, fee_bps)
        .ok_or_else(|| "step 9: live simulator returned None".to_string())?;
    if sim != live {
        return Err(format!("step 9: simulated ({sim}) != live ({live})"));
    }
    step!(
        "9. Stale-reserves attack — rejected at chunk #7 gate",
        format!(
            "Alice's pre-trade-1 route quotes output = {exp}; live reserves yield {sim}; \
             OutputMismatch — typed reject"
        )
    );

    // ── 10. Fresh route — Trade 2 settles ────────────────────────────
    publish_active_advertisement(PublishRoutingAdInput {
        vault_id: &vault_id,
        token_a: &token_aaa,
        token_b: &token_bbb,
        reserve_a_u128: trade_1_post_a.to_be_bytes(),
        reserve_b_u128: trade_1_post_b.to_be_bytes(),
        fee_bps,
        unlock_spec_digest: [0u8; 32],
        unlock_spec_key: "defi/spec/demo".to_string(),
        owner_public_key: &bob.public_key,
        vault_proto_bytes: &vault_proto_bytes,
    })
    .await
    .map_err(|e| format!("step 10 republish ad: {e}"))?;
    let fresh_ads: Vec<_> = load_active_advertisements_for_pair(&token_aaa, &token_bbb)
        .await
        .map_err(|e| format!("step 10 list ads: {e}"))?
        .into_iter()
        .map(|p| p.advertisement)
        .collect();
    let fresh_path = find_best_path(
        &fresh_ads,
        &token_aaa,
        &token_bbb,
        trade_input,
        DEFAULT_MAX_HOPS,
    )
    .map_err(|e| format!("step 10 path: {e:?}"))?;
    let nonce_3 = {
        let mut n = [0u8; 32];
        n[0] = 0x03;
        n[1] = 0x77;
        n[31] = 0x77;
        n
    };
    let fresh_unsigned = bind_path_to_route_commit(BindRouteCommitInput {
        path: &fresh_path,
        nonce: nonce_3,
        initiator_public_key: &alice.public_key,
        initiator_signature: vec![],
    })
    .map_err(|e| format!("step 10 bind: {e:?}"))?;
    let fresh_canonical = canonicalise_for_commitment(&fresh_unsigned).encode_to_vec();
    let fresh_sig = sphincs_sign(SphincsVariant::SPX256f, &alice.secret_key, &fresh_canonical)
        .map_err(|e| format!("step 10 sign: {e}"))?;
    let mut fresh_signed = fresh_unsigned;
    fresh_signed.initiator_signature = fresh_sig;
    let x_3 = compute_external_commitment(&fresh_signed);
    publish_external_commitment(&x_3, &alice.public_key, "trade-3-fresh")
        .await
        .map_err(|e| format!("step 10 publish anchor: {e}"))?;
    let fresh_hop =
        verify_route_commit_unlock_eligibility(&fresh_signed.encode_to_vec(), &vault_id)
            .await
            .map_err(|e| format!("step 10 eligibility: {e:?}"))?;
    let trade2_outcome = verify_amm_swap_against_reserves(&fresh_hop, &bobs_fulfillment)
        .map_err(|e| format!("step 10 AMM gate: {e:?}"))?
        .ok_or_else(|| "step 10: vault non-AMM".to_string())?;
    let pre_k_2 = trade_1_post_a * trade_1_post_b;
    let post_k_2 = trade2_outcome.new_reserve_a * trade2_outcome.new_reserve_b;
    if post_k_2 < pre_k_2 {
        return Err(format!(
            "step 10: constant-product invariant violated (pre_k={pre_k_2}, post_k={post_k_2})"
        ));
    }
    let trade_2_output = fresh_path.final_output_amount;
    step!(
        "10. Fresh route — Trade 2 settles",
        format!(
            "Bob republishes; Alice rebuilds path against post-trade-1 reserves; \
             output = {trade_2_output}; new reserves = ({}, {}); k non-decreasing ✓",
            trade2_outcome.new_reserve_a, trade2_outcome.new_reserve_b
        )
    );

    Ok(DemoReport {
        steps,
        initial_reserve_a,
        initial_reserve_b,
        trade_1_input: trade_input,
        trade_1_output: route_quoted_output,
        trade_1_post_reserve_a: trade_1_post_a,
        trade_1_post_reserve_b: trade_1_post_b,
        stale_attack_simulated_output: sim,
        stale_attack_expected_output: exp,
        trade_2_input: trade_input,
        trade_2_output,
    })
}
