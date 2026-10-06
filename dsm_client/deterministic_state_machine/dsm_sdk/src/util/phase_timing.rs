// SPDX-License-Identifier: MIT OR Apache-2.0

//! How long each phase of an operation took, logged one line per phase and
//! one for the whole, so a device's log (logcat) can be read for where an
//! operation spends its time: `[timing] <operation> <phase> <ms>`.
//!
//! Observation only. Nothing reads these times: no validity, ordering or
//! decision in DSM depends on them, and an operation runs the same with the
//! log off.

use std::time::{Duration, Instant};

/// The phases of one operation as they pass. The whole is logged when the
/// timer is dropped, on every way out of the operation, its errors included.
pub(crate) struct PhaseTimer {
    operation: &'static str,
    started: Instant,
    phase_started: Instant,
}

impl PhaseTimer {
    pub(crate) fn start(operation: &'static str) -> Self {
        let now = Instant::now();
        Self {
            operation,
            started: now,
            phase_started: now,
        }
    }

    /// The phase that ends now, timed from the end of the one before it.
    pub(crate) fn phase(&mut self, phase: &str) {
        let now = Instant::now();
        log::info!(
            "{}",
            line(
                self.operation,
                phase,
                now.duration_since(self.phase_started)
            )
        );
        self.phase_started = now;
    }
}

impl Drop for PhaseTimer {
    fn drop(&mut self) {
        log::info!("{}", line(self.operation, "total", self.started.elapsed()));
    }
}

/// One timing line: what a log reader greps for.
fn line(operation: &str, phase: &str, elapsed: Duration) -> String {
    format!("[timing] {operation} {phase} {}", elapsed.as_millis())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A line names the operation and the phase, and the elapsed time in
    /// whole milliseconds, in the order a grep of the log reads them.
    #[test]
    fn a_timing_line_names_the_operation_the_phase_and_its_milliseconds() {
        assert_eq!(
            line("wallet.send", "delivery", Duration::from_micros(1_234_567)),
            "[timing] wallet.send delivery 1234"
        );
    }
}
