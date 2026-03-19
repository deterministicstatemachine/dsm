use dsm::types::proto as gp;
use prost::Message;
use std::sync::Arc;

#[test]
fn universal_faucet_claim_invoke_routes_to_approuter_claim() {
    // Create a FaucetClaimRequest ArgPack
    let req = gp::FaucetClaimRequest {
        device_id: vec![0u8; 32],
    };

    // Simulate invoking via the core bridge: construct a UniversalOp wrapper
    // The bridge path for UniversalOp::FaucetClaim should route to AppRouter invoke

    // (No direct router call here; we'll exercise the universal envelope path below.)

    // Now exercise the core bridge universal envelope path: create a UniversalOp::FaucetClaim
    let op = gp::UniversalOp {
        op_id: Some(gp::Hash32 { v: vec![1u8; 32] }),
        actor: vec![2u8; 32],
        genesis_hash: vec![3u8; 32],
        kind: Some(gp::universal_op::Kind::FaucetClaim(req)),
    };

    let env = gp::Envelope {
        version: 3,
        headers: Some(gp::Headers {
            device_id: vec![4u8; 32],
            chain_tip: vec![5u8; 32],
            genesis_hash: vec![3u8; 32],
            seq: 1,
        }),
        message_id: vec![6u8; 16],
        payload: Some(gp::envelope::Payload::UniversalTx(gp::UniversalTx {
            ops: vec![op],
            atomic: false,
        })),
    };

    // Install a simple AppRouter to handle "faucet.claim" invokes in this test.
    struct TestRouter;
    impl dsm::core::bridge::AppRouter for TestRouter {
        fn handle_query(&self, _path: &str, _params_proto: &[u8]) -> Result<Vec<u8>, String> {
            Err("query unsupported in test router".to_string())
        }

        fn handle_invoke(
            &self,
            method: &str,
            args_proto: &[u8],
        ) -> Result<(Vec<u8>, Vec<u8>), String> {
            if method != "faucet.claim" {
                return Err("unsupported method".to_string());
            }
            let pack = gp::ArgPack::decode(args_proto)
                .map_err(|e| format!("decode ArgPack failed: {e}"))?;
            if pack.codec != gp::Codec::Proto as i32 {
                return Err("ArgPack.codec must be PROTO".into());
            }
            let req = gp::FaucetClaimRequest::decode(pack.body.as_slice())
                .map_err(|e| format!("decode FaucetClaimRequest failed: {e}"))?;
            if req.device_id.len() != 32 {
                return Err("device_id must be 32 bytes".into());
            }
            let resp = gp::FaucetClaimResponse {
                success: true,
                tokens_received: 1000,
                next_available_index: 0,
                message: "Faucet claim successful (test)".to_string(),
            };
            let arg_pack = gp::ArgPack {
                schema_hash: None,
                codec: gp::Codec::Proto as i32,
                body: resp.encode_to_vec(),
            };
            let mut out = Vec::new();
            arg_pack
                .encode(&mut out)
                .map_err(|e| format!("encode ArgPack failed: {e}"))?;
            Ok((out, vec![]))
        }
    }

    dsm::core::bridge::install_app_router(Arc::new(TestRouter))
        .unwrap_or_else(|e| panic!("install app router failed: {e}"));

    let resp_bytes = dsm::core::bridge::handle_envelope_universal(&env.encode_to_vec());
    let resp_env = gp::Envelope::decode(resp_bytes.as_slice())
        .unwrap_or_else(|e| panic!("decode response envelope failed: {e}"));

    match resp_env.payload {
        Some(gp::envelope::Payload::UniversalRx(rx)) => {
            assert_eq!(rx.results.len(), 1);
            let result = &rx.results[0];
            assert!(result.accepted, "invoke should be accepted");
            let result_pack = result
                .result
                .as_ref()
                .unwrap_or_else(|| panic!("result pack present"));
            assert_eq!(result_pack.codec, gp::Codec::Proto as i32);
            let faucet_resp = gp::FaucetClaimResponse::decode(result_pack.body.as_slice())
                .unwrap_or_else(|e| panic!("FaucetClaimResponse decode failed: {e}"));
            assert!(
                faucet_resp.success,
                "faucet.claim should succeed and return success=true"
            );
        }
        other => panic!("expected UniversalRx, got {:?}", other),
    }
}
