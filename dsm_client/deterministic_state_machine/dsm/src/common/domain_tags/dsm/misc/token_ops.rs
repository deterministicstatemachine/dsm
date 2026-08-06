// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: token and external operation domains

use crate::crypto::domain::TaggedHashDomain;

pub const TAG_DSM_BTC_DEPOSIT_ID: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/btc-deposit-id");
pub const TAG_DSM_BTC_KEY_ENC: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/btc-key-enc");
pub const TAG_DSM_EXTERNAL_EVIDENCE: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/external-evidence");
pub const TAG_DSM_EXTERNAL_SOURCE_ID: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/external-source-id");
pub const TAG_DSM_FAUCET_CLAIM: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/faucet-claim");
pub const TAG_DSM_MOMENT: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/moment");
pub const TAG_DSM_MOMENT_NODE: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/moment-node");
pub const TAG_DSM_SYSTEM_OWNER: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/system-owner");
pub const TAG_DSM_TOKEN_FACTORY: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/token-factory");
pub const TAG_DSM_TOKEN_ID: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/token-id");
pub const TAG_DSM_TOKEN_METADATA: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/token-metadata");
pub const TAG_DSM_TOKEN_MPC_PARTICIPANT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/token-mpc/participant");
pub const TAG_DSM_TOKEN_OP: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/token-op");
