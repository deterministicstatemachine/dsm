// SPDX-License-Identifier: MIT OR Apache-2.0

//! Each device's one backup slot (DSM Amendment A40; owner, 2026-11-23: "It
//! should replace it. It should be a separate thing, and yes, it needs the key
//! to do such a thing").
//!
//! - `POST /api/v2/backup/{slot}`: a start, signed by the device's cell lock
//!   (`dsm::wallet_backup::admit_start`). `200` when it is the backup being
//!   written or the whole one, `409` when its generation is not higher than
//!   one the slot already took, `403` when the lock did not sign it for this
//!   slot. Every answer that is not a refusal of the request carries the
//!   slot's state.
//! - `POST /api/v2/backup/{slot}/{generation}/{part}`: a part, taken only as
//!   the digest the start names. `200` with the slot's state, `409` when no
//!   backup of that generation is being written or whole here, `403` when its
//!   digest is not the one named, `400` when the start names no such part.
//! - `GET /api/v2/backup/{slot}`: the slot's state; the empty state when it
//!   holds nothing.
//! - `GET /api/v2/backup/{slot}/{generation}/{part}`: a part of the whole
//!   backup, when its generation is the one named; an empty body otherwise.
//!   A part is never empty, so absence is asserted by shape.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Extension, Router,
};
use prost::Message;

use crate::api::cells::{digest32, octets};
use crate::db::{PartTaken, SlotState, StartTaken};
use crate::AppState;

/// The largest start: its lock, route, generation, every part's digest and a
/// signature, with framing.
const MAX_START_BYTES: usize = 32 * dsm::wallet_backup::MAX_PARTS + 65_535 + 256;

pub fn create_router(state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route("/api/v2/backup/{slot}", post(put_start).get(get_slot))
        .route(
            "/api/v2/backup/{slot}/{generation}/{part}",
            post(put_part).get(get_part),
        )
        .layer(Extension(state))
}

fn slot_of(b32: &str) -> Result<[u8; 32], StatusCode> {
    digest32(b32)?.as_slice().try_into().map_err(|e| {
        log::info!("backup: the slot is not 32 bytes: {e}");
        StatusCode::BAD_REQUEST
    })
}

fn state_body(state: SlotState) -> Vec<u8> {
    dsm::types::proto::BackupSlotV1 {
        generation: state.generation,
        part_digests: state.part_digests,
        highest_generation: state.highest_generation,
    }
    .encode_to_vec()
}

fn answer(status: StatusCode, state: SlotState) -> Response {
    let mut r = octets(state_body(state));
    *r.status_mut() = status;
    r
}

fn db_error(what: &'static str) -> impl Fn(anyhow::Error) -> StatusCode {
    move |e| {
        log::error!("backup {what}: DB failed: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

async fn put_start(
    Extension(state): Extension<Arc<AppState>>,
    Path(slot): Path<String>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    if body.len() > MAX_START_BYTES {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let slot = slot_of(&slot)?;
    let start = dsm::wallet_backup::admit_start(&slot, body.as_ref()).map_err(|why| {
        log::info!("backup start: refused: {why}");
        StatusCode::FORBIDDEN
    })?;
    // Generations are a signed 64-bit integer in the store: a larger one is
    // a request that is not one, never a node that failed.
    i64::try_from(start.generation).map_err(|e| {
        log::info!(
            "backup start: generation {} past the store's range: {e}",
            start.generation
        );
        StatusCode::BAD_REQUEST
    })?;
    let (taken, held) = crate::db::backup_start(
        &state.db_pool,
        &slot,
        start.generation,
        &start.part_digests.concat(),
    )
    .await
    .map_err(db_error("start"))?;
    Ok(match taken {
        StartTaken::Writing | StartTaken::Whole => answer(StatusCode::OK, held),
        StartTaken::Stale => answer(StatusCode::CONFLICT, held),
    })
}

async fn put_part(
    Extension(state): Extension<Arc<AppState>>,
    Path((slot, generation, part)): Path<(String, u64, u32)>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    if body.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if body.len() > dsm::route_chain::MAX_VALUE_LEN {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let slot = slot_of(&slot)?;
    let (taken, held) =
        crate::db::backup_part(&state.db_pool, &slot, generation, part, body.as_ref())
            .await
            .map_err(db_error("part"))?;
    Ok(match taken {
        PartTaken::Writing | PartTaken::Whole => answer(StatusCode::OK, held),
        PartTaken::NotWriting => answer(StatusCode::CONFLICT, held),
        PartTaken::WrongDigest => StatusCode::FORBIDDEN.into_response(),
        PartTaken::NoSuchPart => StatusCode::BAD_REQUEST.into_response(),
    })
}

async fn get_slot(
    Extension(state): Extension<Arc<AppState>>,
    Path(slot): Path<String>,
) -> Result<Response, StatusCode> {
    let slot = slot_of(&slot)?;
    let held = crate::db::backup_slot(&state.db_pool, &slot)
        .await
        .map_err(db_error("read"))?;
    Ok(answer(StatusCode::OK, held))
}

async fn get_part(
    Extension(state): Extension<Arc<AppState>>,
    Path((slot, generation, part)): Path<(String, u64, u32)>,
) -> Result<Response, StatusCode> {
    let slot = slot_of(&slot)?;
    let held = crate::db::backup_whole_part(&state.db_pool, &slot, generation, part)
        .await
        .map_err(db_error("part read"))?;
    Ok(match held {
        Some(part) => octets(part),
        None => octets(Vec::new()),
    })
}
