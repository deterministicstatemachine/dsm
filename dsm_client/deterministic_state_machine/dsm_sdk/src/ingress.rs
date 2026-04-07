//! # Shared Native Ingress
//!
//! Platform-agnostic ingress layer that sits between the thin ABI shims
//! (Android JNI, iOS FFI) and the DSM SDK / core library.

use prost::Message;

use crate::generated as pb;
use crate::generated::{ingress_request, ingress_response, Envelope, IngressRequest, IngressResponse};

pub(crate) const ERROR_CODE_INVALID_INPUT: u32 = 1;
pub(crate) const ERROR_CODE_PROCESSING_FAILED: u32 = 2;
pub(crate) const ERROR_CODE_NOT_READY: u32 = 5;

fn ingress_error(code: u32, message: impl Into<String>) -> pb::Error {
    pb::Error {
        code,
        message: message.into(),
        context: Vec::new(),
        source_tag: 0,
        is_recoverable: false,
        debug_b32: String::new(),
    }
}

fn process_envelope_core(envelope_in: Envelope) -> Result<Envelope, pb::Error> {
    let mut raw = Vec::new();
    match envelope_in.encode(&mut raw) {
        Ok(()) => {}
        Err(e) => {
            return Err(ingress_error(
                ERROR_CODE_INVALID_INPUT,
                format!("ingress: envelope re-encode failed: {e}"),
            ));
        }
    }

    let out = dsm::core::bridge::handle_envelope_universal(&raw);
    let payload = if out.first() == Some(&0x03) {
        &out[1..]
    } else {
        &out[..]
    };

    Envelope::decode(payload).map_err(|e| {
        ingress_error(
            ERROR_CODE_PROCESSING_FAILED,
            format!("ingress: response envelope decode failed: {e}"),
        )
    })
}

fn router_query_core(method: String, args: Vec<u8>) -> Result<Vec<u8>, pb::Error> {
    if method.is_empty() {
        return Err(ingress_error(
            ERROR_CODE_INVALID_INPUT,
            "ingress: router query path missing",
        ));
    }

    let router = match crate::bridge::app_router() {
        Some(router) => router,
        None => {
            return Err(ingress_error(
                ERROR_CODE_NOT_READY,
                "ingress: app router not installed",
            ));
        }
    };
    let q = crate::bridge::AppQuery {
        path: method,
        params: args,
    };
    let res = crate::runtime::get_runtime().block_on(router.query(q));

    if res.success {
        Ok(res.data)
    } else {
        Err(ingress_error(
            ERROR_CODE_PROCESSING_FAILED,
            res.error_message
                .unwrap_or_else(|| "router_query_core failed".to_string()),
        ))
    }
}

fn router_invoke_core(method: String, args: Vec<u8>) -> Result<Vec<u8>, pb::Error> {
    if method.is_empty() {
        return Err(ingress_error(
            ERROR_CODE_INVALID_INPUT,
            "ingress: router invoke method missing",
        ));
    }

    let router = match crate::bridge::app_router() {
        Some(router) => router,
        None => {
            return Err(ingress_error(
                ERROR_CODE_NOT_READY,
                "ingress: app router not installed",
            ));
        }
    };
    let invoke = crate::bridge::AppInvoke { method, args };
    let res = crate::runtime::get_runtime().block_on(router.invoke(invoke));

    if res.success {
        Ok(res.data)
    } else {
        Err(ingress_error(
            ERROR_CODE_PROCESSING_FAILED,
            res.error_message
                .unwrap_or_else(|| "router_invoke_core failed".to_string()),
        ))
    }
}

fn update_hardware_facts_core(facts: pb::SessionHardwareFactsProto) -> Result<Vec<u8>, pb::Error> {
    let mut facts_bytes = Vec::new();
    match facts.encode(&mut facts_bytes) {
        Ok(()) => {}
        Err(e) => {
            return Err(ingress_error(
                ERROR_CODE_INVALID_INPUT,
                format!("ingress: hardware facts encode failed: {e}"),
            ));
        }
    }

    crate::sdk::session_manager::update_hardware_and_snapshot(&facts_bytes).map_err(|e| {
        ingress_error(
            ERROR_CODE_PROCESSING_FAILED,
            format!("ingress: hardware facts update failed: {e}"),
        )
    })
}

pub fn dispatch_ingress(request: IngressRequest) -> IngressResponse {
    let result: Result<Vec<u8>, pb::Error> = match request.operation {
        Some(ingress_request::Operation::RouterQuery(op)) => router_query_core(op.method, op.args),
        Some(ingress_request::Operation::RouterInvoke(op)) => {
            router_invoke_core(op.method, op.args)
        }
        Some(ingress_request::Operation::Envelope(op)) => {
            if op.envelope_bytes.is_empty() {
                Err(ingress_error(
                    ERROR_CODE_INVALID_INPUT,
                    "ingress: envelope bytes missing",
                ))
            } else {
                let slice = if op.envelope_bytes.first() == Some(&0x03) {
                    &op.envelope_bytes[1..]
                } else {
                    op.envelope_bytes.as_slice()
                };
                let env_in = Envelope::decode(slice).map_err(|e| {
                    ingress_error(
                        ERROR_CODE_INVALID_INPUT,
                        format!("ingress: envelope decode failed: {e}"),
                    )
                });
                match env_in.and_then(process_envelope_core) {
                    Ok(env_out) => {
                        let mut buf = Vec::with_capacity(1 + env_out.encoded_len());
                        buf.push(0x03);
                        match env_out.encode(&mut buf) {
                            Ok(()) => Ok(buf),
                            Err(e) => Err(ingress_error(
                                ERROR_CODE_PROCESSING_FAILED,
                                format!("ingress: response encode failed: {e}"),
                            )),
                        }
                    }
                    Err(e) => Err(e),
                }
            }
        }
        Some(ingress_request::Operation::HardwareFacts(op)) => match op.facts {
            Some(facts) => update_hardware_facts_core(facts),
            None => Err(ingress_error(
                ERROR_CODE_INVALID_INPUT,
                "ingress: hardware facts missing",
            )),
        },
        None => Err(ingress_error(
            ERROR_CODE_INVALID_INPUT,
            "ingress: empty IngressRequest (no operation set)",
        )),
    };

    match result {
        Ok(bytes) => IngressResponse {
            result: Some(ingress_response::Result::OkBytes(bytes)),
        },
        Err(error) => IngressResponse {
            result: Some(ingress_response::Result::Error(error)),
        },
    }
}

pub fn dispatch_ingress_bytes(request_bytes: &[u8]) -> Vec<u8> {
    let request = match IngressRequest::decode(request_bytes) {
        Ok(r) => r,
        Err(e) => {
            return IngressResponse {
                result: Some(ingress_response::Result::Error(ingress_error(
                    ERROR_CODE_INVALID_INPUT,
                    format!("ingress: IngressRequest decode failed: {e}"),
                ))),
            }
            .encode_to_vec();
        }
    };

    dispatch_ingress(request).encode_to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use once_cell::sync::Lazy;

    use crate::bridge::{install_app_router, AppInvoke, AppQuery, AppResult, AppRouter};

    static TEST_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    struct TestRouter;

    #[async_trait]
    impl AppRouter for TestRouter {
        async fn query(&self, q: AppQuery) -> AppResult {
            AppResult {
                success: true,
                data: format!("query:{}:{}", q.path, q.params.len()).into_bytes(),
                error_message: None,
            }
        }

        async fn invoke(&self, i: AppInvoke) -> AppResult {
            AppResult {
                success: true,
                data: format!("invoke:{}:{}", i.method, i.args.len()).into_bytes(),
                error_message: None,
            }
        }
    }

    fn setup_test_env() -> std::sync::MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("DSM_SDK_TEST_MODE", "1");
        let _ =
            crate::storage_utils::set_storage_base_dir(std::path::PathBuf::from("./.dsm_testdata"));
        crate::sdk::app_state::AppState::reset_memory_for_testing();
        crate::sdk::app_state::AppState::ensure_storage_loaded();
        unsafe { crate::bridge::reset_bridge_handlers_for_tests() };
        guard
    }

    fn expect_ok_bytes(response: IngressResponse) -> Vec<u8> {
        match response.result {
            Some(ingress_response::Result::OkBytes(bytes)) => bytes,
            other => panic!("expected ok bytes, got {:?}", other),
        }
    }

    fn expect_error(response: IngressResponse) -> pb::Error {
        match response.result {
            Some(ingress_response::Result::Error(error)) => error,
            other => panic!("expected error, got {:?}", other),
        }
    }

    #[test]
    fn dispatch_ingress_empty_request_returns_invalid_input() {
        let _guard = setup_test_env();
        let response = dispatch_ingress(IngressRequest { operation: None });
        let error = expect_error(response);
        assert_eq!(error.code, ERROR_CODE_INVALID_INPUT);
        assert!(error.message.contains("empty IngressRequest"));
    }

    #[test]
    fn dispatch_ingress_bytes_invalid_proto_returns_invalid_input() {
        let _guard = setup_test_env();
        let response_bytes = dispatch_ingress_bytes(&[0xff, 0xfe, 0xfd]);
        let response = IngressResponse::decode(response_bytes.as_slice()).expect("decode response");
        let error = expect_error(response);
        assert_eq!(error.code, ERROR_CODE_INVALID_INPUT);
    }

    #[test]
    fn envelope_request_strips_optional_prefix_and_reframes_success_output() {
        let _guard = setup_test_env();
        let request_env = Envelope {
            version: 3,
            message_id: vec![7; 16],
            payload: Some(pb::envelope::Payload::Error(pb::Error {
                code: 99,
                message: "request already a response".to_string(),
                context: Vec::new(),
                source_tag: 0,
                is_recoverable: false,
                debug_b32: String::new(),
            })),
            ..Default::default()
        };
        let mut framed = vec![0x03];
        framed.extend_from_slice(&request_env.encode_to_vec());

        let response = dispatch_ingress(IngressRequest {
            operation: Some(ingress_request::Operation::Envelope(pb::EnvelopeOp {
                envelope_bytes: framed,
            })),
        });
        let ok_bytes = expect_ok_bytes(response);
        assert_eq!(ok_bytes.first(), Some(&0x03));
        let decoded = Envelope::decode(&ok_bytes[1..]).expect("decode framed envelope");
        assert_eq!(decoded.version, 3);
    }

    #[test]
    fn malformed_envelope_returns_invalid_input() {
        let _guard = setup_test_env();
        let response = dispatch_ingress(IngressRequest {
            operation: Some(ingress_request::Operation::Envelope(pb::EnvelopeOp {
                envelope_bytes: vec![0x03, 0xaa, 0xbb, 0xcc],
            })),
        });
        let error = expect_error(response);
        assert_eq!(error.code, ERROR_CODE_INVALID_INPUT);
        assert!(error.message.contains("envelope decode failed"));
    }

    #[test]
    fn router_query_success_returns_router_payload() {
        let _guard = setup_test_env();
        install_app_router(Arc::new(TestRouter)).expect("install router");

        let response = dispatch_ingress(IngressRequest {
            operation: Some(ingress_request::Operation::RouterQuery(pb::RouterQueryOp {
                method: "wallet.balance".to_string(),
                args: vec![1, 2, 3],
            })),
        });
        let ok_bytes = expect_ok_bytes(response);
        assert_eq!(ok_bytes, b"query:wallet.balance:3".to_vec());
    }

    #[test]
    fn router_invoke_success_returns_router_payload() {
        let _guard = setup_test_env();
        install_app_router(Arc::new(TestRouter)).expect("install router");

        let response = dispatch_ingress(IngressRequest {
            operation: Some(ingress_request::Operation::RouterInvoke(
                pb::RouterInvokeOp {
                    method: "wallet.send".to_string(),
                    args: vec![9, 8],
                },
            )),
        });
        let ok_bytes = expect_ok_bytes(response);
        assert_eq!(ok_bytes, b"invoke:wallet.send:2".to_vec());
    }

    #[test]
    fn router_absent_maps_to_not_ready() {
        let _guard = setup_test_env();
        let response = dispatch_ingress(IngressRequest {
            operation: Some(ingress_request::Operation::RouterQuery(pb::RouterQueryOp {
                method: "wallet.balance".to_string(),
                args: Vec::new(),
            })),
        });
        let error = expect_error(response);
        assert_eq!(error.code, ERROR_CODE_NOT_READY);
        assert!(error.message.contains("app router not installed"));
    }

    #[test]
    fn hardware_facts_success_returns_envelope_wrapped_snapshot() {
        let _guard = setup_test_env();
        let response = dispatch_ingress(IngressRequest {
            operation: Some(ingress_request::Operation::HardwareFacts(
                pb::HardwareFactsOp {
                    facts: Some(pb::SessionHardwareFactsProto {
                        app_foreground: true,
                        ble_enabled: true,
                        ble_permissions: true,
                        ble_scanning: false,
                        ble_advertising: true,
                        qr_available: true,
                        qr_active: false,
                        camera_permission: true,
                        battery_charging: false,
                        battery_level_percent: 88,
                    }),
                },
            )),
        });
        let ok_bytes = expect_ok_bytes(response);
        assert_eq!(ok_bytes.first(), Some(&0x03));
        let envelope = Envelope::decode(&ok_bytes[1..]).expect("decode snapshot envelope");
        match envelope.payload {
            Some(pb::envelope::Payload::SessionStateResponse(snapshot)) => {
                let hardware = snapshot.hardware_status.expect("hardware status");
                assert!(hardware.app_foreground);
            }
            other => panic!("expected SessionStateResponse, got {:?}", other),
        }
    }
}
