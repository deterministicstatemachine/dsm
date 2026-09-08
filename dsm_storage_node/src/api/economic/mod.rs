// SPDX-License-Identifier: Apache-2.0

//! Economic write-once registers.
//!
//! Two independent one-shot registers, each following the settlement-slot
//! discipline (first-write-wins, exact bytes, attribution before storage) but
//! sharing NOTHING settlement-flavoured: their own tables, routes, headers and
//! domains. A shared domain is a shared meaning, and neither of these is a
//! settlement.
//!
//! ## Read attribution is part of the API contract
//!
//! Every response carries this node's configured member id in `x-dsm-node-id`
//! (the blanket response-header layer in `main.rs`). For these registers that
//! echo is NORMATIVE, not informational: a client establishing quorum counts
//! a response ONLY when the echoed id equals the member it queried, and a
//! response without the echo is uncountable. Nodes never sign anything here —
//! attribution under the crash-fault model is the configured member endpoint
//! answering as itself, not cryptographic node identity.
//!
//! **Attribution is TWO-AXIS, and the node id is only the first axis.** The
//! client counts an answer only when the echoed node id AND the echoed
//! register incarnation both match the member the vault committed
//! (`storage_node_sdk::answer_counts_for`). A member that lost and rebuilt its
//! register answers with its own id and can honestly report "nothing here" for
//! a cell the committed incarnation held — node identity alone cannot tell that
//! apart from the real member reporting the same thing. These read endpoints
//! previously stamped neither the incarnation nor an asserted absence, so on
//! the live path EVERY economic register read was uncountable, and the read
//! degraded to `Unavailable` for every member. See [`cell_read_response`].

use axum::{
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};

use crate::AppState;
use dsm_sdk::util::text_id;

pub mod faucet_ticket;
pub mod root_register;

/// The register incarnation this node serves. Same header the settlement-slot
/// and binding paths use — one name for one fact, so a client needs no
/// per-register special case.
pub use crate::api::storage::binding::INCARNATION_HEADER;

/// An absence must be ASSERTED. A bare 404 proves only that something in this
/// process declined to serve the path — a route miss reaches the fallback,
/// which still carries the identity echo — so a client counts emptiness only
/// when the member SAYS the cell is absent.
pub const SLOT_OUTCOME_HEADER: &str = "x-dsm-slot-outcome";

/// Build a register-cell read response carrying everything a client needs to
/// COUNT it: the incarnation echo on every branch, and an asserted absence on
/// the empty branch.
///
/// The incarnation is stamped on held and absent alike. Stamping only the held
/// case would leave the dangerous one — a rebuilt member reporting emptiness —
/// indistinguishable from the real member reporting it, which is the whole
/// reason the second axis exists.
///
/// A node with no established incarnation stamps none, and its answers are
/// therefore uncountable rather than counted-as-something. That is the correct
/// failure: it has no register history to speak for.
pub(crate) fn cell_read_response(
    state: &AppState,
    status: StatusCode,
    body: Option<Vec<u8>>,
    assert_absent: bool,
) -> Response {
    let mut resp = match body {
        Some(bytes) => {
            let mut r = (status, bytes).into_response();
            r.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            r
        }
        None => status.into_response(),
    };
    if let Some(inc) = state.own_register_incarnation {
        if let Ok(v) = HeaderValue::from_str(&text_id::encode_base32_crockford(&inc)) {
            resp.headers_mut().insert(INCARNATION_HEADER, v);
        }
    }
    if assert_absent {
        resp.headers_mut()
            .insert(SLOT_OUTCOME_HEADER, HeaderValue::from_static("absent"));
    }
    resp
}
