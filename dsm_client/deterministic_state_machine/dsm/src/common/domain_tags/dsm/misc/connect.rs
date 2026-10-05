// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: a Web2 application connected to a wallet (DSM
//! Amendment A11).

use crate::crypto::domain::TaggedHashDomain;

/// The application's signature over a connection offer's body.
pub const TAG_DSM_CONNECT_OFFER: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/connect/offer");
/// The digest a connect code names its offer by.
pub const TAG_DSM_CONNECT_OFFER_DIGEST: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/connect/offer-digest");
/// The wallet's signature over its answer to an offer.
pub const TAG_DSM_CONNECT_ACCEPT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/connect/accept");
/// A session's id: the offer it answered and the wallet that answered it.
pub const TAG_DSM_CONNECT_SESSION: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/connect/session");
/// The application's signature over a request.
pub const TAG_DSM_CONNECT_REQUEST: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/connect/request");
/// The wallet's signature over its answer to a request.
pub const TAG_DSM_CONNECT_RESPONSE: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/connect/response");
