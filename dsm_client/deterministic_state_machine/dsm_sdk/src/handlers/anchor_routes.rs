// SPDX-License-Identifier: MIT OR Apache-2.0
//! Anchor route handlers for the app router (offline-bearer signal (c)).
//!
//! Query routes:
//! - `anchor.board.read` → a board in BOOTSEL as its own bootloader shows it, and where its one-time
//!   setup for production stands. Writes nothing.
//! - `anchor.tryRun` → an install gone through on the connected anchor with its permanent parts
//!   substituted, what it found, and what installing would make permanent. Binds nothing.
//! - `anchor.status` → read-only [`AnchorStatusResponse`] diagnostics snapshot of the sender's
//!   anchor appliance (RP2350/TROPIC01). Purely observational: no staging, no counter move, no
//!   device-state mutation. When no appliance can attach it reports `anchor_connected=false`
//!   rather than failing the route.

use dsm::types::proto as generated;
use prost::Message;

use crate::bridge::{AppInvoke, AppQuery, AppResult};

use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{err, pack_envelope_ok};

fn status_response(
    snap: crate::sdk::core_sdk::AnchorStatusSnapshot,
) -> generated::AnchorStatusResponse {
    generated::AnchorStatusResponse {
        anchor_connected: snap.connected,
        anchor_id: snap.anchor_id.to_vec(),
        pk_chip: snap.pk_chip,
        partition_pk: snap.partition_pk,
        anchor_counter: snap.anchor_counter,
        frontier_root: snap.frontier_root.to_vec(),
        enrolled_counter: snap.enrolled_counter,
        bundle: snap.bundle.to_vec(),
        status: snap.status,
        awaiting_install: snap.awaiting_install,
    }
}

/// A board's setup needs the phone's USB link to the board's bootloader, which the device layer
/// installs; a device without one says so.
const NO_BOARD_LINK: &str = "this device has no USB link to a board's bootloader";

/// `anchor.board.step`: the board's next step, on the board whose chip id the person typed back.
fn board_step(i: &AppInvoke) -> AppResult {
    let arg_pack = match generated::ArgPack::decode(&*i.args) {
        Ok(p) => p,
        Err(e) => return err(format!("anchor.board.step: decode ArgPack failed: {e}")),
    };
    let request = match generated::AnchorBoardStepRequest::decode(&*arg_pack.body) {
        Ok(r) => r,
        Err(e) => return err(format!("anchor.board.step: decode the request failed: {e}")),
    };
    match crate::bridge::anchor_board_setup() {
        Some(setup) => {
            let answer = tokio::task::block_in_place(move || setup.step(&request));
            pack_envelope_ok(generated::envelope::Payload::AnchorBoardResponse(answer))
        }
        None => err(format!("anchor.board.step: {NO_BOARD_LINK}")),
    }
}

impl AppRouterImpl {
    /// `anchor.install`: install the connected anchor for this device, for good, or as a trial on the
    /// trial image. The one route that makes an anchor permanent, and only ever on being told to: the
    /// anchor goes through its try-run again first, and refuses with nothing written unless it passes.
    pub(crate) async fn handle_anchor_invoke(&self, i: AppInvoke) -> AppResult {
        if i.method == "anchor.board.step" {
            return board_step(&i);
        }
        if i.method != "anchor.install" {
            return err(format!("unknown anchor route: {}", i.method));
        }
        let core = self.core_sdk.clone();
        match tokio::task::block_in_place(move || core.anchor_install()) {
            Ok(snap) => pack_envelope_ok(generated::envelope::Payload::AnchorStatusResponse(
                status_response(snap),
            )),
            Err(e) => err(format!("anchor.install: {e}")),
        }
    }

    /// Dispatch handler for `anchor.*` query routes.
    pub(crate) async fn handle_anchor_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            "anchor.status" => {
                pack_envelope_ok(generated::envelope::Payload::AnchorStatusResponse(
                    status_response(self.core_sdk.anchor_appliance_status()),
                ))
            }
            "anchor.board.read" => match crate::bridge::anchor_board_setup() {
                Some(setup) => {
                    let answer = tokio::task::block_in_place(move || setup.read());
                    pack_envelope_ok(generated::envelope::Payload::AnchorBoardResponse(answer))
                }
                None => err(format!("anchor.board.read: {NO_BOARD_LINK}")),
            },
            "anchor.tryRun" => {
                let core = self.core_sdk.clone();
                match tokio::task::block_in_place(move || core.anchor_try_run()) {
                    Ok(report) => {
                        pack_envelope_ok(generated::envelope::Payload::AnchorTryRunResponse(
                            generated::AnchorTryRunResponse {
                                passed: report.passed,
                                steps: report
                                    .steps
                                    .into_iter()
                                    .map(|step| generated::AnchorTryRunStep {
                                        name: step.name,
                                        passed: step.passed,
                                        detail: step.detail,
                                        production: step.requirement
                                            == anchor_core::try_run::Requirement::Production,
                                    })
                                    .collect(),
                                trial: matches!(
                                    report.install,
                                    Some(anchor_core::enrollment::Install::ForTrial)
                                ),
                                permanent: report.permanent,
                                refused: report.refused,
                            },
                        ))
                    }
                    Err(e) => err(format!("anchor.tryRun: {e}")),
                }
            }
            _ => super::response_helpers::err(format!("unknown anchor query: {}", q.path)),
        }
    }
}
