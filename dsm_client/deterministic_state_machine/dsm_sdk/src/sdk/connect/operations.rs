// SPDX-License-Identifier: MIT OR Apache-2.0

//! A connected application's request and the operations it commits (SA-60).
//!
//! A request is carried out inside [`carrying_out`]: every advance this device
//! commits while it runs is recorded against the request in the advance's own
//! transaction ([`bind_in_tx`]), with the spend its grant counts. A request
//! with an operation recorded is never carried out again: whatever stopped it
//! from being marked processed (a failed write, a crash), the next sync
//! reports what it committed.
//!
//! The request is its task's. An advance another task commits meanwhile (the
//! inbox poller taking in a transfer, a send the player makes) is not this
//! request's and is not bound to it. Nor is what the request's own task takes
//! in from others while it runs ([`taking_in`]): a transfer a send's sync
//! accepts is a contact's operation, never the request's (SA-126).

use dsm::types::device_state::AdvanceOutcome;
use dsm::types::error::DsmError;

/// The request being carried out in this task.
#[derive(Debug, Clone, Copy)]
struct Carrying {
    session_id: [u8; 32],
    seq: u64,
    /// What the grant counts against this request, `None` for a request the
    /// player approved by hand.
    spend: Option<([u8; 32], u64)>,
}

tokio::task_local! {
    /// The request this task is carrying out; `None` inside [`taking_in`].
    static CARRYING_OUT: Option<Carrying>;
}

/// Run `work`, which carries out request `seq` of `session_id`: each advance
/// committed while it runs is that request's.
pub(crate) async fn carrying_out<F: std::future::Future>(
    session_id: [u8; 32],
    seq: u64,
    spend: Option<([u8; 32], u64)>,
    work: F,
) -> F::Output {
    CARRYING_OUT
        .scope(
            Some(Carrying {
                session_id,
                seq,
                spend,
            }),
            work,
        )
        .await
}

/// Run `work`, which takes in what others sent this device (a storage sync
/// accepting their transfers): no advance it commits is the request this
/// task may be carrying out, which goes on being carried out once it ends
/// (SA-126).
pub(crate) async fn taking_in<F: std::future::Future>(work: F) -> F::Output {
    CARRYING_OUT.scope(None, work).await
}

/// Bind the advance `tx` commits to the request this task is carrying out,
/// if it is carrying one out. Called inside the advance's transaction.
pub(crate) fn bind_in_tx(
    tx: &rusqlite::Transaction<'_>,
    outcome: &AdvanceOutcome,
) -> Result<(), DsmError> {
    match CARRYING_OUT.try_with(|carrying| *carrying) {
        // No connected application's request is being carried out here, or
        // this advance takes in what another device sent.
        Err(..) | Ok(None) => Ok(()),
        Ok(Some(carrying)) => crate::storage::client_db::connect::bind_operation_with_conn(
            tx,
            &carrying.session_id,
            carrying.seq,
            &outcome.new_chain_state.compute_chain_tip(),
            carrying.spend,
        )
        .map_err(|e| {
            DsmError::storage(
                format!(
                    "binding the advance to request {} of its application: {e}",
                    carrying.seq
                ),
                None::<std::io::Error>,
            )
        }),
    }
}
