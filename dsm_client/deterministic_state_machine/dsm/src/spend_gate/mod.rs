// SPDX-License-Identifier: MIT OR Apache-2.0

//! PaidK spend-gate for storage node operations.
//!
//! Implements the spend-gate mechanism: certain operations (e.g., state
//! anchoring, DLV slot creation) require spending `K` tokens as proof-of-stake.

pub mod gate;
