// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reaches for the counterparties this device owes offline frames.
//!
//! An offline step keeps the frame its phase owes until the counterparty
//! answers (see `BilateralBleSession::owed`). A send that did not complete,
//! a link that ended, and an app restarted with steps in flight all leave a
//! frame owed and nothing reaching for its counterparty. While any owed frame
//! has not been delivered on a live link, the driver reaches for its
//! counterparty through the same device-id-keyed send the step used, and
//! paces its attempts.
//!
//! A frame delivered on a link is not sent again while that link lives: the
//! counterparty holds it. When the link ends, its frames are undelivered
//! again. The pacing is BLE transport only — it never ends, orders or
//! validates a step.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use super::bilateral_session::{OfflineFrameKind, OwedFrame};

/// A frame owed on one step: the step's commitment and the frame's kind.
pub type FrameKey = ([u8; 32], OfflineFrameKind);

/// The first pause after an attempt that left a frame undelivered.
const FIRST_PAUSE: Duration = Duration::from_secs(15);
/// The longest pause between attempts.
const LONGEST_PAUSE: Duration = Duration::from_secs(300);

/// The pause after `failed_attempts` consecutive attempts that left a frame
/// undelivered: doubling from [`FIRST_PAUSE`], capped at [`LONGEST_PAUSE`].
pub fn pause_after(failed_attempts: u32) -> Duration {
    let doubling = 1u32
        .checked_shl(failed_attempts.saturating_sub(1))
        .unwrap_or(u32::MAX);
    FIRST_PAUSE
        .checked_mul(doubling)
        .map_or(LONGEST_PAUSE, |pause| pause.min(LONGEST_PAUSE))
}

/// Which frames have been delivered on a link that still lives.
#[derive(Debug, Default)]
pub struct Deliveries {
    delivered: HashMap<FrameKey, [u8; 32]>,
}

impl Deliveries {
    /// `frame`, owed to `counterparty`, was delivered on a live link.
    pub fn delivered(&mut self, counterparty: [u8; 32], frame: FrameKey) {
        self.delivered.insert(frame, counterparty);
    }

    /// The link to `counterparty` ended: its frames are undelivered again.
    pub fn link_down(&mut self, counterparty: &[u8; 32]) {
        self.delivered.retain(|_, owed_to| owed_to != counterparty);
    }

    /// The counterparties owed a frame not delivered on a live link, each
    /// once. Marks for frames no longer owed (answered steps) are dropped.
    pub fn undelivered(&mut self, owed: &[([u8; 32], OwedFrame)]) -> Vec<[u8; 32]> {
        let still_owed: HashSet<FrameKey> = owed
            .iter()
            .map(|(_, frame)| (frame.commitment_hash, frame.kind))
            .collect();
        self.delivered.retain(|frame, _| still_owed.contains(frame));
        let mut counterparties = Vec::new();
        for (counterparty, frame) in owed {
            let key = (frame.commitment_hash, frame.kind);
            if !self.delivered.contains_key(&key) && !counterparties.contains(counterparty) {
                counterparties.push(*counterparty);
            }
        }
        counterparties
    }
}

#[cfg(all(target_os = "android", feature = "bluetooth"))]
mod runner {
    use std::sync::{Condvar, Mutex};

    use once_cell::sync::OnceCell;

    use super::{pause_after, Deliveries, FrameKey};

    struct Driver {
        state: Mutex<State>,
        wake: Condvar,
    }

    #[derive(Default)]
    struct State {
        kicked: bool,
        deliveries: Deliveries,
    }

    static DRIVER: OnceCell<Driver> = OnceCell::new();

    fn with_state<T>(f: impl FnOnce(&mut State) -> T) -> Option<T> {
        let driver = DRIVER.get()?;
        let mut state = driver
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Some(f(&mut state))
    }

    /// Something may have left a frame undelivered: look now.
    pub fn kick() {
        if let Some(driver) = DRIVER.get() {
            let mut state = driver
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.kicked = true;
            driver.wake.notify_one();
        }
    }

    /// The link to `counterparty` ended: its frames are undelivered again.
    pub fn link_down(counterparty: &[u8; 32]) {
        with_state(|state| state.deliveries.link_down(counterparty));
        kick();
    }

    /// These frames, owed to `counterparty`, were delivered on a live link.
    pub fn delivered(counterparty: [u8; 32], frames: &[FrameKey]) {
        with_state(|state| {
            for frame in frames {
                state.deliveries.delivered(counterparty, *frame);
            }
        });
    }

    /// Start the driver once the BLE transport is up. Idempotent.
    pub fn start() {
        if DRIVER
            .set(Driver {
                state: Mutex::new(State {
                    kicked: true,
                    ..State::default()
                }),
                wake: Condvar::new(),
            })
            .is_err()
        {
            return;
        }
        if let Err(e) = std::thread::Builder::new()
            .name("dsm-owed-frames".to_string())
            .spawn(run)
        {
            log::error!("[owed frames] the driver thread did not start: {e}");
        }
    }

    fn run() {
        let Some(driver) = DRIVER.get() else { return };
        let mut failed_attempts: u32 = 0;
        loop {
            let owed = match crate::runtime::get_runtime()
                .block_on(crate::bridge::get_ble_transport_adapter())
            {
                Ok(adapter) => crate::runtime::get_runtime()
                    .block_on(adapter.bilateral_handler().frames_owed()),
                Err(e) => {
                    log::warn!("[owed frames] the BLE transport is not ready: {e}");
                    Vec::new()
                }
            };
            let pending =
                with_state(|state| state.deliveries.undelivered(&owed)).unwrap_or_default();

            let mut left_undelivered = false;
            for counterparty in pending {
                let hint = crate::bluetooth::peer_address::counterparty_address(&counterparty)
                    .ok()
                    .flatten();
                let owed_to: Vec<FrameKey> = owed
                    .iter()
                    .filter(|(owed_to, _)| *owed_to == counterparty)
                    .map(|(_, frame)| (frame.commitment_hash, frame.kind))
                    .collect();
                let delivered = crate::jni::jni_common::with_env(|env| {
                    let mut env = unsafe { jni::JNIEnv::from_raw(env.get_raw() as *mut _) }
                        .map_err(|e| format!("clone JNIEnv failed: {e}"))?;
                    Ok(crate::jni::unified_protobuf_bridge::deliver_owed_frames(
                        &mut env,
                        &counterparty,
                        hint.as_deref(),
                    ))
                })
                .unwrap_or_else(|e| {
                    log::warn!("[owed frames] no JNI environment for delivery: {e}");
                    Vec::new()
                });
                if owed_to.iter().any(|frame| !delivered.contains(frame)) {
                    left_undelivered = true;
                }
                self::delivered(counterparty, &delivered);
            }

            let mut state = driver
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if left_undelivered {
                failed_attempts = failed_attempts.saturating_add(1);
                let pause = pause_after(failed_attempts);
                log::info!(
                    "[owed frames] a frame is still undelivered; reaching again in {}s",
                    pause.as_secs()
                );
                let (next, _) = driver
                    .wake
                    .wait_timeout_while(state, pause, |state| !state.kicked)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                state = next;
            } else {
                failed_attempts = 0;
                state = driver
                    .wake
                    .wait_while(state, |state| !state.kicked)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
            state.kicked = false;
        }
    }
}

#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub use runner::{delivered, kick, link_down, start};

#[cfg(test)]
mod tests {
    use super::{pause_after, Deliveries, OfflineFrameKind, OwedFrame};
    use std::time::Duration;

    fn owed(counterparty: u8, step: u8, kind: OfflineFrameKind) -> ([u8; 32], OwedFrame) {
        (
            [counterparty; 32],
            OwedFrame {
                commitment_hash: [step; 32],
                kind,
                bytes: vec![step],
            },
        )
    }

    #[test]
    fn pacing_doubles_from_fifteen_seconds_to_five_minutes() {
        assert_eq!(pause_after(1), Duration::from_secs(15));
        assert_eq!(pause_after(2), Duration::from_secs(30));
        assert_eq!(pause_after(3), Duration::from_secs(60));
        assert_eq!(pause_after(5), Duration::from_secs(240));
        assert_eq!(pause_after(6), Duration::from_secs(300));
        assert_eq!(pause_after(u32::MAX), Duration::from_secs(300));
    }

    /// A frame nobody has delivered is reached for; once delivered on a live
    /// link it is not sent again until that link ends.
    #[test]
    fn a_delivered_frame_waits_for_its_link_to_end() {
        let mut deliveries = Deliveries::default();
        let frames = vec![owed(0x5a, 1, OfflineFrameKind::Prepare)];
        assert_eq!(deliveries.undelivered(&frames), vec![[0x5a; 32]]);

        deliveries.delivered([0x5a; 32], ([1; 32], OfflineFrameKind::Prepare));
        assert!(deliveries.undelivered(&frames).is_empty());

        deliveries.link_down(&[0x5a; 32]);
        assert_eq!(deliveries.undelivered(&frames), vec![[0x5a; 32]]);
    }

    /// A link ending to one counterparty leaves another's deliveries alone,
    /// and a new frame on a delivered step (its confirm) is undelivered.
    #[test]
    fn deliveries_are_per_frame_and_per_counterparty() {
        let mut deliveries = Deliveries::default();
        deliveries.delivered([0x5a; 32], ([1; 32], OfflineFrameKind::Prepare));
        deliveries.delivered([0x16; 32], ([2; 32], OfflineFrameKind::PrepareResponse));
        deliveries.link_down(&[0x5a; 32]);

        let frames = vec![
            owed(0x5a, 1, OfflineFrameKind::Confirm),
            owed(0x16, 2, OfflineFrameKind::PrepareResponse),
        ];
        assert_eq!(deliveries.undelivered(&frames), vec![[0x5a; 32]]);
    }

    /// Each counterparty is reached for once, however many frames it is owed.
    #[test]
    fn each_counterparty_is_reached_for_once() {
        let mut deliveries = Deliveries::default();
        let frames = vec![
            owed(0x5a, 1, OfflineFrameKind::Prepare),
            owed(0x5a, 3, OfflineFrameKind::Confirm),
            owed(0x16, 2, OfflineFrameKind::PrepareResponse),
        ];
        assert_eq!(
            deliveries.undelivered(&frames),
            vec![[0x5a; 32], [0x16; 32]]
        );
    }
}
