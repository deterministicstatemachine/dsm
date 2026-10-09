// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: what a wallet does outside the protocol (DSM
//! Amendment A17).

use crate::crypto::domain::TaggedHashDomain;

/// The sender device's signature over an email receipt request: the receipt
/// service emails only what a device's AK signed.
pub const TAG_DSM_RECEIPT_EMAIL: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/receipt-email");
