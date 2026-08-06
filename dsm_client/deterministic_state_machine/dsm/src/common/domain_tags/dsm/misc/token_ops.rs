// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: token and external operation domains

use crate::crypto::domain::TaggedHashDomain;

pub const TAG_DSM_BTC_DEPOSIT_ID: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/btc-deposit-id");
pub const TAG_DSM_BTC_KEY_ENC: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/btc-key-enc");
pub const TAG_DSM_EXTERNAL_EVIDENCE: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/external-evidence");
pub const TAG_DSM_EXTERNAL_SOURCE_ID: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/external-source-id");
pub const TAG_DSM_FAUCET_CLAIM: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/faucet-claim");
pub const TAG_DSM_MOMENT: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/moment");
pub const TAG_DSM_MOMENT_NODE: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/moment-node");
pub const TAG_DSM_SYSTEM_OWNER: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/system-owner");
pub const TAG_DSM_TOKEN_FACTORY: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/token-factory");
pub const TAG_DSM_TOKEN_ID: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/token-id");
pub const TAG_DSM_TOKEN_METADATA: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/token-metadata");
pub const TAG_DSM_TOKEN_MPC_PARTICIPANT: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/token-mpc/participant");
pub const TAG_DSM_TOKEN_OP: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/token-op");
