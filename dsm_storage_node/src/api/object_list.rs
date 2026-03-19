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
