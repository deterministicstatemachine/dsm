// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: addressing and routing

use crate::crypto::domain::TaggedHashDomain;

pub const TAG_DSM_ADDR_D: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/addr-D");
pub const TAG_DSM_ADDR_G: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/addr-G");
pub const TAG_DSM_ADDR_T: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/addr-T");
pub const TAG_DSM_CONTACT_ADD: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/contact/add");
pub const TAG_DSM_COUNTERPARTY_ID: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/counterparty-id");
