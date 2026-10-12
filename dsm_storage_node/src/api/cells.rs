// SPDX-License-Identifier: MIT OR Apache-2.0

//! Keyed cells and indexes: bytes in, bytes out.
//!
//! A member does four things with a key. It keeps every value it is given for
//! that key, in the order the values arrive — one key at a time, or several
//! keys in one local transaction, all or none; it returns everything it
//! holds; it appends a content address under a locator; and it returns the
//! addresses under a locator in append order. It never refuses, replaces,
//! compares, decodes or decides. Which value counts at a key is the reader's
//! question, answered from the bytes and the reader's own committed state.
//!
//! Every put answers with the entry's arrival record (storage spec §6, §14):
//! this member's id, the cell, the entry's per-key arrival index, and the
//! running hash after it. A get returns every value with its record. The
//! records are bytes, not signatures; they become checkable when the
//! member's ByteCommit that commits them closes.
//!
//! Absence is asserted by shape: a read of a key nothing was put under is
//! `200` with an empty list. A `404` is a route miss, never a statement about
//! the key.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Path, RawQuery},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Extension, Router,
};
use prost::Message;

use crate::AppState;
use dsm::utils::text_id;

/// The namespace a cell or locator belongs to, as the immutable store takes
/// it: `DSM/`- or `DJTE.`-prefixed, NUL-free, bounded. It scopes the key; the
/// member does nothing else with it.
const NAMESPACE_HEADER: &str = "x-namespace";
const MAX_NAMESPACE_BYTES: usize = 128;
/// A value held at a key. Objects live in the immutable store; a cell holds
/// an object's envelope or a small claim, never a bulk payload. Writers put a
/// route entry at each seat (storage spec §9), which wraps the value with its
/// chain, so the limit is Core's largest entry, not its largest value.
const MAX_CELL_VALUE_BYTES: usize = dsm::route_chain::MAX_ENTRY_BYTES;
/// Keys one batch put may take in one transaction. A position is two.
const MAX_BATCH_ENTRIES: usize = 16;
const MAX_INDEX_PAGE: i64 = 256;

pub fn create_router(state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route("/api/v2/cell/{key}", post(put_cell).get(get_cell))
        .route("/api/v2/cells", post(put_cells))
        .route(
            "/api/v2/index/{locator}",
            post(append_index).get(read_index),
        )
        .layer(Extension(state))
}

pub(crate) fn namespace(headers: &HeaderMap) -> Result<Vec<u8>, StatusCode> {
    let raw = headers
        .get(NAMESPACE_HEADER)
        .map(|v| v.as_bytes().to_vec())
        .ok_or(StatusCode::BAD_REQUEST)?;
    namespace_bytes(raw)
}

fn namespace_bytes(raw: Vec<u8>) -> Result<Vec<u8>, StatusCode> {
    if raw.is_empty()
        || raw.len() > MAX_NAMESPACE_BYTES
        || raw.contains(&0)
        || !(raw.starts_with(b"DSM/") || raw.starts_with(b"DJTE."))
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(raw)
}

pub(crate) fn digest32(b32: &str) -> Result<Vec<u8>, StatusCode> {
    let bytes = text_id::decode_base32_crockford(b32.trim()).ok_or(StatusCode::BAD_REQUEST)?;
    if bytes.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(bytes)
}

/// This member's arrival record for an entry it holds.
fn arrival_record(
    state: &AppState,
    namespace: Vec<u8>,
    key: &[u8],
    index: u64,
    running_hash: [u8; 32],
) -> Result<dsm::storage_cell::ArrivalRecord, StatusCode> {
    Ok(dsm::storage_cell::ArrivalRecord {
        member_id: state.configured_member_id.as_bytes().to_vec(),
        namespace,
        key: key
            .try_into()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        index,
        running_hash,
    })
}

pub(crate) fn octets(body: Vec<u8>) -> Response {
    let mut r = (StatusCode::OK, body).into_response();
    r.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    r
}

/// Keep the body at the key, after anything already there, and answer with
/// the entry's arrival record.
async fn put_cell(
    Extension(state): Extension<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, StatusCode> {
    if body.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if body.len() > MAX_CELL_VALUE_BYTES {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let ns = namespace(&headers)?;
    let key = digest32(&key)?;
    let (index, running_hash) = crate::db::put_cell(&state.db_pool, &ns, &key, body.as_ref())
        .await
        .map_err(|e| {
            log::error!("cell put: DB write failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let record = arrival_record(&state, ns, &key, index, running_hash)?;
    Ok(octets(record.to_proto().encode_to_vec()))
}

/// Keep every entry's body at its key, after anything already there, in ONE
/// local transaction: all of them or none of them. The shape of each entry
/// is checked before anything is written, so a malformed batch is a `400`
/// with nothing held, never a half.
async fn put_cells(
    Extension(state): Extension<Arc<AppState>>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let batch = dsm::types::proto::CellPutsV1::decode(body.as_ref())
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if batch.entries.is_empty() || batch.entries.len() > MAX_BATCH_ENTRIES {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut entries = Vec::with_capacity(batch.entries.len());
    for entry in batch.entries {
        if entry.value.is_empty() {
            return Err(StatusCode::BAD_REQUEST);
        }
        if entry.value.len() > MAX_CELL_VALUE_BYTES {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        if entry.key.len() != 32 {
            return Err(StatusCode::BAD_REQUEST);
        }
        entries.push((namespace_bytes(entry.namespace)?, entry.key, entry.value));
    }
    let written = crate::db::put_cells(&state.db_pool, &entries)
        .await
        .map_err(|e| {
            log::error!("cells put: DB write failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let mut records = Vec::with_capacity(written.len());
    for ((ns, key, _), (index, running_hash)) in entries.into_iter().zip(written) {
        records.push(arrival_record(&state, ns, &key, index, running_hash)?.to_proto());
    }
    Ok(octets(
        dsm::types::proto::ArrivalRecordsV1 { records }.encode_to_vec(),
    ))
}

/// Everything held at the key, in arrival order.
async fn get_cell(
    Extension(state): Extension<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    let ns = namespace(&headers)?;
    let key = digest32(&key)?;
    let entries = crate::db::get_cell_entries(&state.db_pool, &ns, &key)
        .await
        .map_err(|e| {
            log::error!("cell get: DB read failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let mut page = dsm::types::proto::CellValuesV1 {
        values: Vec::with_capacity(entries.len()),
        records: Vec::with_capacity(entries.len()),
    };
    for (value, index, running_hash) in entries {
        page.values.push(value);
        page.records
            .push(arrival_record(&state, ns.clone(), &key, index, running_hash)?.to_proto());
    }
    Ok(octets(page.encode_to_vec()))
}

/// Append a 32-byte content address under the locator.
async fn append_index(
    Extension(state): Extension<Arc<AppState>>,
    Path(locator): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, StatusCode> {
    let ns = namespace(&headers)?;
    let locator = digest32(&locator)?;
    if body.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut scoped = ns;
    scoped.push(0);
    scoped.extend_from_slice(&locator);
    crate::db::append_index(&state.db_pool, &scoped, body.as_ref())
        .await
        .map_err(|e| {
            log::error!("index append: DB write failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(StatusCode::NO_CONTENT)
}

/// `after=<seq>&limit=<n>`, both optional, parsed without a serializer: the
/// node speaks no JSON and needs no query codec for two integers.
fn page_query(raw: Option<&str>) -> Result<(i64, i64), StatusCode> {
    let (mut after, mut limit) = (0i64, MAX_INDEX_PAGE);
    for pair in raw.unwrap_or("").split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').ok_or(StatusCode::BAD_REQUEST)?;
        let n: i64 = v.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
        match k {
            "after" => after = n.max(0),
            "limit" => limit = n.clamp(1, MAX_INDEX_PAGE),
            _ => return Err(StatusCode::BAD_REQUEST),
        }
    }
    Ok((after, limit))
}

/// The addresses under the locator after `after`, in append order.
async fn read_index(
    Extension(state): Extension<Arc<AppState>>,
    Path(locator): Path<String>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Result<Response, StatusCode> {
    let ns = namespace(&headers)?;
    let locator = digest32(&locator)?;
    let mut scoped = ns;
    scoped.push(0);
    scoped.extend_from_slice(&locator);
    let (after, limit) = page_query(raw.as_deref())?;
    let rows = crate::db::read_index(&state.db_pool, &scoped, after, limit)
        .await
        .map_err(|e| {
            log::error!("index read: DB read failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let page = dsm::types::proto::IndexPageV1 {
        entries: rows
            .into_iter()
            .map(|(seq, addr)| dsm::types::proto::IndexEntryV1 { seq, addr })
            .collect(),
    };
    Ok(octets(page.encode_to_vec()))
}
