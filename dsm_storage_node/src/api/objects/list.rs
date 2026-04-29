//! Object listing API (admin/management UI helper)
//!
//! IMPORTANT:
//! - Storage nodes are "dumb" mirrors; this endpoint is for browsing/debugging.
//! - Deterministic ordering: stable sort keys only.
//! - No clock dependence.
//!
//! Endpoint:
//!   GET /api/v2/object/list?prefix=...&limit=...&cursor=...
//!
//! Cursor is the last returned key (opaque string). Listing is ordered by key ASC.

use axum::{
    extract::{Extension, RawQuery},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Router,
};
use dsm::types::proto as pb;
use prost::Message;
use std::sync::Arc;

use crate::{db, AppState};

#[derive(Debug, Default)]
pub struct ListQuery {
    /// Optional key prefix filter.
    pub prefix: Option<String>,
    /// Max number of items to return (bounded).
    pub limit: Option<u32>,
    /// Pagination cursor: return items strictly greater than this key.
    pub cursor: Option<String>,
}

pub fn create_router(state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route("/api/v2/object/list", get(list_objects))
        .layer(Extension(state))
}

pub async fn list_objects(
    Extension(state): Extension<Arc<AppState>>,
    RawQuery(raw): RawQuery,
) -> Result<impl IntoResponse, StatusCode> {
    let q = parse_query(raw.as_deref())?;
    let limit = q.limit.unwrap_or(100).clamp(1, 1000) as i64;

    // Basic input sanitation: keep prefix/cursor bounded so we don't accept multi-megabyte URLs.
    if let Some(p) = q.prefix.as_ref() {
        if p.len() > 2048 {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    if let Some(c) = q.cursor.as_ref() {
        if c.len() > 4096 {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    let rows = db::list_objects_page(
        &state.db_pool,
        q.prefix.as_deref(),
        q.cursor.as_deref(),
        limit,
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut items = Vec::with_capacity(rows.len());
    for (key, dlv_id, size_bytes) in rows {
        items.push(pb::ObjectListItemV1 {
            key,
            dlv_id_b32: dsm_sdk::util::text_id::encode_base32_crockford(&dlv_id),
            size_bytes,
        });
    }

    let next_cursor = items.last().map(|i| i.key.clone());

    let resp = pb::ObjectListResponseV1 { items, next_cursor };
    let mut buf = Vec::with_capacity(resp.encoded_len());
    resp.encode(&mut buf)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        buf,
    ))
}

fn parse_query(raw: Option<&str>) -> Result<ListQuery, StatusCode> {
    let mut out = ListQuery::default();
    let raw = match raw {
        Some(v) if !v.is_empty() => v,
        _ => return Ok(out),
    };

    for pair in raw.split('&') {
        let mut it = pair.splitn(2, '=');
        let key = it.next().unwrap_or("");
        let val = it.next().unwrap_or("");
        let val = decode_percent(val)?;
        match key {
            "prefix" => out.prefix = Some(val),
            "limit" => {
                let parsed = val.parse::<u32>().map_err(|_| StatusCode::BAD_REQUEST)?;
                out.limit = Some(parsed);
            }
            "cursor" => out.cursor = Some(val),
            _ => {}
        }
    }

    Ok(out)
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

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    #[test]
    fn parse_query_empty_or_none() {
        match parse_query(None) {
            Ok(q) => {
                assert!(q.prefix.is_none());
                assert!(q.limit.is_none());
                assert!(q.cursor.is_none());
            }
            Err(err) => panic!("expected empty query to parse, got {err:?}"),
        }

        match parse_query(Some("")) {
            Ok(q) => assert!(q.prefix.is_none()),
            Err(err) => panic!("expected blank query to parse, got {err:?}"),
        }
    }

    #[test]
    fn parse_query_all_params() {
        match parse_query(Some("prefix=abc&limit=50&cursor=xyz")) {
            Ok(q) => {
                assert_eq!(q.prefix.as_deref(), Some("abc"));
                assert_eq!(q.limit, Some(50));
                assert_eq!(q.cursor.as_deref(), Some("xyz"));
            }
            Err(err) => panic!("expected full query to parse, got {err:?}"),
        }
    }

    #[test]
    fn parse_query_prefix_only() {
        match parse_query(Some("prefix=foo")) {
            Ok(q) => {
                assert_eq!(q.prefix.as_deref(), Some("foo"));
                assert!(q.limit.is_none());
                assert!(q.cursor.is_none());
            }
            Err(err) => panic!("expected prefix-only query to parse, got {err:?}"),
        }
    }

    #[test]
    fn parse_query_unknown_keys_ignored() {
        match parse_query(Some("prefix=bar&unknown=val")) {
            Ok(q) => assert_eq!(q.prefix.as_deref(), Some("bar")),
            Err(err) => panic!("expected query with unknown keys to parse, got {err:?}"),
        }
    }

    #[test]
    fn parse_query_invalid_limit_is_error() {
        assert!(parse_query(Some("limit=abc")).is_err());
        assert!(parse_query(Some("limit=-1")).is_err());
    }

    #[test]
    fn parse_query_percent_encoded_prefix() {
        match parse_query(Some("prefix=hello%20world")) {
            Ok(q) => assert_eq!(q.prefix.as_deref(), Some("hello world")),
            Err(err) => panic!("expected percent-encoded query to parse, got {err:?}"),
        }
    }

    #[test]
    fn limit_clamping_in_handler() {
        // Simulates the clamping logic from list_objects
        let q = ListQuery {
            prefix: None,
            limit: Some(0),
            cursor: None,
        };
        let clamped = q.limit.unwrap_or(100).clamp(1, 1000) as i64;
        assert_eq!(clamped, 1, "limit=0 must clamp to 1");

        let q2 = ListQuery {
            prefix: None,
            limit: Some(5000),
            cursor: None,
        };
        let clamped2 = q2.limit.unwrap_or(100).clamp(1, 1000) as i64;
        assert_eq!(clamped2, 1000, "limit=5000 must clamp to 1000");

        let q3 = ListQuery {
            prefix: None,
            limit: None,
            cursor: None,
        };
        let clamped3 = q3.limit.unwrap_or(100).clamp(1, 1000) as i64;
        assert_eq!(clamped3, 100, "missing limit defaults to 100");
    }

    #[test]
    fn decode_percent_mixed() {
        assert_eq!(decode_percent("hello"), Ok("hello".to_string()));
        assert_eq!(decode_percent("a%2Fb"), Ok("a/b".to_string()));
        assert_eq!(decode_percent("a+b"), Ok("a b".to_string()));
        assert_eq!(decode_percent("%48%49"), Ok("HI".to_string()));
    }

    #[test]
    fn decode_percent_invalid_hex_is_error() {
        assert!(decode_percent("%GG").is_err());
        assert!(decode_percent("%0").is_err());
        assert!(decode_percent("%").is_err());
    }

    #[test]
    fn from_hex_all_valid_digits() {
        for b in b'0'..=b'9' {
            assert!(from_hex(b).is_ok());
        }
        for b in b'a'..=b'f' {
            assert!(from_hex(b).is_ok());
        }
        for b in b'A'..=b'F' {
            assert!(from_hex(b).is_ok());
        }
        assert!(from_hex(b'g').is_err());
        assert!(from_hex(b'z').is_err());
    }

    #[test]
    fn list_query_default() {
        let q = ListQuery::default();
        assert!(q.prefix.is_none());
        assert!(q.limit.is_none());
        assert!(q.cursor.is_none());
    }
}
