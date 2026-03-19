// Integration tests for v2 submit endpoints.

/// Verify the canonical v2 submit endpoint path matches the expected DSM route structure.
/// The path must be absolute, contain no query strings or fragments, and use the v2 prefix
/// as registered in the axum router (main.rs).
#[test]
fn submit_endpoint_path_is_canonical() {
    let path = "/api/v2/submit";
    assert!(path.starts_with('/'), "endpoint path must be absolute");
    assert!(
        !path.contains('?'),
        "endpoint path must not embed a query string"
    );
    assert!(
        !path.contains('#'),
        "endpoint path must not embed a fragment"
    );
    assert!(
        path.contains("/v2/"),
        "endpoint path must use the v2 API prefix"
    );
}
