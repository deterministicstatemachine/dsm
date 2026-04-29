//! Integration tests for registry Content-Type gate.

#![allow(clippy::disallowed_methods)]

use axum::{
    body::Body,
    http::{header::CONTENT_TYPE, Request, StatusCode},
};
use tower::ServiceExt; // brings `.oneshot(..)` into scope

#[tokio::test]
#[serial_test::serial]
async fn publish_without_content_type_returns_415() {
    let app = dsm_storage_node::build_app_for_tests().await.unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/api/v2/registry/publish")
        // intentionally omit Content-Type
        .body(Body::from("deadbeef"))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
#[serial_test::serial]
async fn publish_with_octet_stream_returns_200_and_addr_header() {
    let app = dsm_storage_node::build_app_for_tests().await.unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/api/v2/registry/publish")
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(Body::from("evidence-bytes"))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let addr_hdr = resp
        .headers()
        .get(dsm_storage_node::api::registry::core::HDR_ADDR);
    assert!(
        addr_hdr.is_some(),
        "x-object-address header should be present"
    );
}
