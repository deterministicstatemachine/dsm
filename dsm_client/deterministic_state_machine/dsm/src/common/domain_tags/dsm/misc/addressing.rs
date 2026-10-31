// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: addressing and routing

use crate::crypto::domain::TaggedHashDomain;

/// The namespace an authored object is put under (`authored_object`).
pub const TAG_DSM_AUTHORED_OBJECT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/object/authored/v1");
/// The domain of an author's signature over an authored object's body.
pub const TAG_DSM_AUTHORED_STATEMENT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/object/authored-statement/v1");
/// The domain of an author's locator for a topic, and the index namespace.
pub const TAG_DSM_AUTHORED_LOCATOR: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/object/authored-locator/v1");
pub const TAG_DSM_CONTACT_ADD: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/contact/add");
pub const TAG_DSM_COUNTERPARTY_ID: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/counterparty-id");
