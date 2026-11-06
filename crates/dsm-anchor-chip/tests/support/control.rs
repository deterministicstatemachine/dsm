// SPDX-License-Identifier: MIT OR Apache-2.0
//! What the tests of the chip itself do to the model, beyond serving from it: cut its power, choose its
//! part, watch what it stores.

use anchor_chip::bring_up::{bring_up, identify_chip, prepare_chip, BoardAnchor};
use anchor_chip::session::ChipFacts;
use anchor_chip::Board;
use anchor_core::identify::ChipSurvey;

use super::support::{call, BringUpError, Garble, HostBoard, ModelServer, Power, SEALED};

const TAG_RESET_TARGET: u8 = 0x10;

/// A part Tropic Square programs differently from a production one (catalog list v2.0, section 5).
#[derive(Clone, Copy, PartialEq)]
pub enum Part {
    /// T1XX: sensors on in R-config, and I-config empty, so the PTRNG is never configured.
    TestPart,
    /// T0XX: R-config and I-config both empty.
    Sample,
}

/// A board with an RP2350 of this stepping.
pub struct SteppedBoard(pub u8);

impl Board for SteppedBoard {
    fn random_key(&self) -> Option<[u8; 32]> {
        HostBoard.random_key()
    }
    fn wait_100ms(&self) {}
    fn alive(&self) {}
    fn silicon_revision(&self) -> u8 {
        self.0
    }
}

impl Power {
    pub fn cut_after(&self, transactions: u64) {
        self.budget.set(Some(transactions));
    }

    pub fn steady(&self) {
        self.budget.set(None);
    }

    /// Whether the budget has run out.
    pub fn was_cut(&self) -> bool {
        matches!(self.budget.get(), Some(0))
    }

    /// The transactions that have gone through, to measure what a run takes.
    pub fn spent(&self) -> u64 {
        self.spent.get()
    }

    /// Corrupt the second CRC byte of every reboot's answer, from now on.
    pub fn garble_reboot_crc(&self) {
        self.garble_reboot_crc.set(Garble::YES);
    }

    /// The transactions so far that changed what the chip stores, on a server that keeps a log.
    pub fn stores(&self) -> Vec<u64> {
        self.stores.borrow().clone()
    }
}

impl ModelServer {
    /// A chip of this part, as it leaves the factory.
    pub fn start_as(part: Part) -> Self {
        Self::launch(
            match part {
                Part::TestPart => "r_config:\n  cfg_sensors: 0xFFFC0000\n",
                Part::Sample => "",
            },
            None,
        )
    }

    /// A production chip whose server logs every command, which is slower: for finding out where a
    /// run changes what the chip stores ([`Power::stores`]).
    pub fn start_watched() -> Self {
        Self::launch(super::support::PRODUCTION_FACTORY, Some("model.log"))
    }

    /// A new chip from the factory.
    pub fn factory_reset(&self) {
        let mut stream = self.connect();
        call(&mut stream, TAG_RESET_TARGET, &[]);
    }

    /// Boot the anchor on a board of this stepping.
    pub fn boot_stepped(&self, stepping: u8) -> Result<BoardAnchor, BringUpError> {
        bring_up(self.power_cycle(), &SEALED, SteppedBoard(stepping))
    }

    /// What the `prepare_chip` image does at reset, on the same code.
    pub fn prepare(&self) -> Result<ChipFacts, BringUpError> {
        prepare_chip(self.power_cycle(), SEALED, HostBoard)
    }

    /// What the `identify_chip` image does at reset, on the same code.
    pub fn identify(&self) -> Result<ChipSurvey, BringUpError> {
        identify_chip(self.power_cycle(), HostBoard)
    }
}
