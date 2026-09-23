// SPDX-License-Identifier: MIT OR Apache-2.0

//! Peer discovery. A node decides no registry: succession is a keyed cell on
//! the pinned set, evaluated by verifiers (storage spec §13), and beta runs on
//! the network's pinned set (DSM Amendment A5).

pub mod discovery;
