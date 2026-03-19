#![cfg(all(test, feature = "test-utils"))]

use dsm_sdk::handlers::app_router_impl::test_online_chain_tip_from_sdk_context_b32;
use dsm_sdk::{get_sdk_context, initialize_sdk_context, reset_sdk_context_for_testing};

#[test]
fn online_chain_tip_prefers_sdk_context_even_with_contacts() {
    reset_sdk_context_for_testing();

    let device_id = vec![1u8; 32];
    let genesis_hash = vec![2u8; 32];
    let entropy = vec![3u8; 32];
    initialize_sdk_context(device_id, genesis_hash, entropy).expect("sdk_context init");

    // Simulate an updated unilateral chain tip in sdk_context.
    let sdk_tip = vec![9u8; 32];
    get_sdk_context()
        .update_chain_tip(sdk_tip.clone())
        .expect("chain_tip update");

    let (tip_bytes, tip_b32) = test_online_chain_tip_from_sdk_context_b32().expect("online tip");
    assert_eq!(tip_bytes, sdk_tip);

    let expected_b32 = dsm_sdk::util::text_id::encode_base32_crockford(&sdk_tip);
    assert_eq!(tip_b32, expected_b32);
}
