// SPDX-License-Identifier: Apache-2.0
//! Admin endpoints for storage node operations

use axum::{
    extract::{Extension, RawQuery},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::IntoResponse,
    routing::post,
    Router,
};
use dsm::types::proto as pb;
use prost::Message;
use std::env;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use subtle::ConstantTimeEq;

use crate::AppState;

const ADMIN_TOKEN_HEADER: &str = "x-dsm-admin-token";
const ADMIN_TOKEN_ENV: &str = "DSM_ADMIN_TOKEN";

fn token_matches(provided: &str, expected: &str) -> bool {
    provided.as_bytes().ct_eq(expected.as_bytes()).into()
}

async fn require_admin_token(headers: HeaderMap) -> Result<(), StatusCode> {
    let expected = env::var(ADMIN_TOKEN_ENV).unwrap_or_default();
    if expected.trim().is_empty() {
        // A missing admin token never authorizes an admin endpoint
        // (maintenance mutates current_tick), in any build.
        log::error!("admin auth required but {} not set", ADMIN_TOKEN_ENV);
        return Err(StatusCode::UNAUTHORIZED);
    }

    let provided = headers
        .get(ADMIN_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if token_matches(provided, &expected) {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

async fn admin_auth(
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<axum::response::Response, StatusCode> {
    require_admin_token(req.headers().clone()).await?;
    Ok(next.run(req).await)
}

/// Admin endpoint to run deterministic maintenance cycle.
/// POST /admin/maintenance?tick=12345
pub async fn maintenance_handler(
    Extension(state): Extension<Arc<AppState>>,
    RawQuery(raw): RawQuery,
) -> Result<impl IntoResponse, StatusCode> {
    let tick = parse_tick_query(raw.as_deref())?;
    state.current_tick.store(tick, Ordering::SeqCst);
    state
        .replication_manager
        .maintenance_cycle(state.clone(), tick)
        .map_err(|e| {
            log::error!("maintenance_cycle failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let resp = pb::AdminMaintenanceResponseV1 { tick, ok: true };
    let mut buf = Vec::with_capacity(resp.encoded_len());
    resp.encode(&mut buf)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        buf,
    ))
}

fn parse_tick_query(raw: Option<&str>) -> Result<i64, StatusCode> {
    let raw = raw.ok_or(StatusCode::BAD_REQUEST)?;
    for pair in raw.split('&') {
        let mut it = pair.splitn(2, '=');
        let key = it.next().unwrap_or("");
        let val = it.next().unwrap_or("");
        if key == "tick" {
            let val = decode_percent(val)?;
            return val.parse::<i64>().map_err(|_| StatusCode::BAD_REQUEST);
        }
    }
    Err(StatusCode::BAD_REQUEST)
}

fn decode_percent(input: &str) -> Result<String, StatusCode> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err(StatusCode::BAD_REQUEST);
                }
                let hi = from_hex(bytes[i + 1])?;
                let lo = from_hex(bytes[i + 2])?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| StatusCode::BAD_REQUEST)
}

fn from_hex(b: u8) -> Result<u8, StatusCode> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

/// EVERY route the node serves under `/admin`, with the token check applied
/// ONCE, to all of them.
///
/// The registry's update and seed endpoints used to be a second `/admin`
/// router assembled next door and nested separately, and it carried no auth
/// layer: `POST /admin/registry/seed` inserted a node into the registry, and
/// `POST /admin/registry/update` added and pruned registry nodes, for anyone
/// who could reach the port. The composition, not the discipline, is what
/// failed — two sibling routers, one of which happened to be layered.
///
/// So the sub-routers below contribute ROUTES ONLY. They carry no `Extension`
/// and no auth of their own, this function supplies both, and `main` mounts
/// this one value. A new admin endpoint added to any of them is authenticated
/// because there is no longer a path by which it could not be.
pub fn admin_surface(state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route("/maintenance", post(maintenance_handler))
        .layer(axum::middleware::from_fn(admin_auth))
        .layer(Extension(state))
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::db;
    use axum::http::StatusCode;

    /// EVERY `/admin` route refuses an unauthenticated caller, and lets an
    /// authenticated one through.
    ///
    /// `/registry/seed` and `/registry/update` are the reason this test
    /// exists: they were a second `/admin` router with no auth layer, so
    /// anyone who could reach the port could insert a node into the registry
    /// or trigger an add/prune pass over it. The negative half asserts the
    /// refusal; the positive half asserts the layer is a token check and not
    /// a blanket 401 — with the right token each request reaches its handler
    /// and is answered on its own merits (400 here, because each of these
    /// handlers validates its input before touching the database).
    #[tokio::test]
    #[serial_test::serial]
    async fn every_admin_route_refuses_an_unauthenticated_caller() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        std::env::set_var(ADMIN_TOKEN_ENV, "test-admin-token");

        // The auth layer refuses before any handler touches the database, and
        // every authenticated request below is rejected by its handler on
        // input validation, so this pool is never queried. It exists because
        // `AppState` requires one, and a lazy pool needs no server.
        let pool =
            db::create_pool("postgresql://127.0.0.1:5432/dsm-admin-auth-test").expect("pool");

        let rm = Arc::new(
            crate::replication::ReplicationManager::new(
                crate::replication::ReplicationConfig {
                    replication_factor: 3,
                    gossip_interval_ticks: 100,
                    failure_timeout_ticks: 300,
                    gossip_fanout: 3,
                    max_concurrent_jobs: 10,
                },
                "n1".to_string(),
                "http://localhost:8080".to_string(),
                &crate::replication::test_set_ca_pem(),
                Vec::new(),
            )
            .expect("replication manager for tests"),
        );
        let state = Arc::new(AppState::new(
            "n1".into(),
            "127.0.0.1:1",
            None,
            Arc::new(pool),
            rm,
        ));
        let app = Router::new().nest("/admin", admin_surface(state));

        // Every route this node serves under /admin, and a body each handler
        // will reject if — and only if — the request reaches it.
        let routes = [("/admin/maintenance", "")];

        for (path, body) in routes {
            let unauthenticated = app
                .clone()
                .oneshot(Request::post(path).body(Body::from(body)).expect("request"))
                .await
                .expect("response");
            assert_eq!(
                unauthenticated.status(),
                StatusCode::UNAUTHORIZED,
                "{path} must refuse a caller with no admin token"
            );

            let wrong_token = app
                .clone()
                .oneshot(
                    Request::post(path)
                        .header(ADMIN_TOKEN_HEADER, "not-the-token")
                        .body(Body::from(body))
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(
                wrong_token.status(),
                StatusCode::UNAUTHORIZED,
                "{path} must refuse a caller with the wrong admin token"
            );

            let authenticated = app
                .clone()
                .oneshot(
                    Request::post(path)
                        .header(ADMIN_TOKEN_HEADER, "test-admin-token")
                        .body(Body::from(body))
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_ne!(
                authenticated.status(),
                StatusCode::UNAUTHORIZED,
                "{path} must ADMIT the holder of the token — a layer that \
                 refuses everyone proves nothing about the one that refuses \
                 strangers"
            );
            assert_eq!(
                authenticated.status(),
                StatusCode::BAD_REQUEST,
                "{path} reached its handler and was rejected on its input"
            );
        }

        std::env::remove_var(ADMIN_TOKEN_ENV);
    }

    /// Ruling #2: with no admin token configured, the endpoint admits no one,
    /// in any build — the retired debug opt-out variable opens nothing.
    #[tokio::test]
    #[serial_test::serial]
    async fn with_no_admin_token_configured_no_one_is_admitted() {
        std::env::remove_var(ADMIN_TOKEN_ENV);
        std::env::set_var("DSM_INSECURE_ALLOW_NO_ADMIN_TOKEN", "1");
        let mut headers = HeaderMap::new();
        headers.insert(ADMIN_TOKEN_HEADER, "anything".parse().expect("header"));
        assert_eq!(
            require_admin_token(HeaderMap::new()).await,
            Err(StatusCode::UNAUTHORIZED)
        );
        assert_eq!(
            require_admin_token(headers).await,
            Err(StatusCode::UNAUTHORIZED)
        );
        std::env::remove_var("DSM_INSECURE_ALLOW_NO_ADMIN_TOKEN");
    }

    #[test]
    fn token_matches_equal() {
        assert!(token_matches("secret123", "secret123"));
    }

    #[test]
    fn token_matches_not_equal() {
        assert!(!token_matches("secret123", "wrong"));
    }

    #[test]
    fn token_matches_empty() {
        assert!(token_matches("", ""));
        assert!(!token_matches("x", ""));
        assert!(!token_matches("", "x"));
    }

    #[test]
    fn from_hex_digits() {
        assert_eq!(from_hex(b'0'), Ok(0));
        assert_eq!(from_hex(b'9'), Ok(9));
        assert_eq!(from_hex(b'a'), Ok(10));
        assert_eq!(from_hex(b'f'), Ok(15));
        assert_eq!(from_hex(b'A'), Ok(10));
        assert_eq!(from_hex(b'F'), Ok(15));
    }

    #[test]
    fn from_hex_invalid() {
        assert_eq!(from_hex(b'g'), Err(StatusCode::BAD_REQUEST));
        assert_eq!(from_hex(b'z'), Err(StatusCode::BAD_REQUEST));
        assert_eq!(from_hex(b' '), Err(StatusCode::BAD_REQUEST));
    }

    #[test]
    fn decode_percent_plain() {
        assert_eq!(decode_percent("hello"), Ok("hello".to_string()));
    }

    #[test]
    fn decode_percent_encoded_chars() {
        assert_eq!(
            decode_percent("hello%20world"),
            Ok("hello world".to_string())
        );
        assert_eq!(decode_percent("%41%42%43"), Ok("ABC".to_string()));
    }

    #[test]
    fn decode_percent_plus_is_space() {
        assert_eq!(decode_percent("a+b"), Ok("a b".to_string()));
    }

    #[test]
    fn decode_percent_truncated() {
        assert!(decode_percent("%2").is_err());
        assert!(decode_percent("%").is_err());
    }

    #[test]
    fn decode_percent_invalid_hex() {
        assert!(decode_percent("%GG").is_err());
    }

    #[test]
    fn parse_tick_query_valid() {
        assert_eq!(parse_tick_query(Some("tick=999")), Ok(999));
    }

    #[test]
    fn parse_tick_query_missing() {
        assert_eq!(parse_tick_query(None), Err(StatusCode::BAD_REQUEST));
        assert_eq!(
            parse_tick_query(Some("foo=1")),
            Err(StatusCode::BAD_REQUEST)
        );
    }

    #[test]
    fn parse_tick_query_non_numeric() {
        assert_eq!(
            parse_tick_query(Some("tick=xyz")),
            Err(StatusCode::BAD_REQUEST)
        );
    }

    #[test]
    fn parse_tick_query_negative() {
        assert_eq!(parse_tick_query(Some("tick=-5")), Ok(-5));
    }
}
