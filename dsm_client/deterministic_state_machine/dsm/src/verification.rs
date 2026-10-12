// SPDX-License-Identifier: MIT OR Apache-2.0

//! Production verification namespace for DSM.
//!
//! Issue #162 cleanup: this module is the single home for **runtime**
//! verification used by the protocol — receipt verification, over the step's
//! write set folded by `merkle::batch_fold`.
//!
//! Quick map:
//!
//! | Submodule                  | Purpose                                          |
//! |----------------------------|--------------------------------------------------|
//! | [`receipt_verification`]   | Stitched-receipt acceptance (§4.3, §11.1)        |

pub mod receipt_verification;
