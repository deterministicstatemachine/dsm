// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: genesis lifecycle domains

use crate::crypto::domain::TaggedHashDomain;

pub const TAG_DSM_GENESIS: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/genesis");
pub const TAG_DSM_GENESIS_COMMIT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/genesis-commit");
pub const TAG_DSM_GENESIS_CONTRIB_V2: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/GENESIS/CONTRIB/v2");
pub const TAG_DSM_GENESIS_ENTROPY: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/genesis-entropy");
pub const TAG_DSM_GENESIS_ENTROPY_PAD: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/genesis-entropy-pad");
pub const TAG_DSM_GENESIS_HASH: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/genesis-hash");
pub const TAG_DSM_GENESIS_INITIAL_ENTROPY: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/genesis-initial-entropy");
pub const TAG_DSM_GENESIS_MERKLE: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/genesis-merkle");
pub const TAG_DSM_GENESIS_VERIFY: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/genesis-verify");

// --- Genesis v2 (mnemonic-rooted, canonical). The public genesis nonce makes G
// deterministically recoverable from the BIP39 wallet seed without exposing it. ---
/// `genesis_nonce = keyed-BLAKE3(wallet_seed, "DSM/genesis-public-nonce/v2" || network_id || wallet_index)`.
/// PUBLIC; stored in GenesisRecord; NOT a secret.
pub const TAG_DSM_GENESIS_NONCE_V2: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/genesis-public-nonce/v2");
/// `G = BLAKE3("DSM/genesis/v2" || genesis_nonce || network_id || genesis_version)`.
pub const TAG_DSM_GENESIS_V2: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/genesis/v2");
