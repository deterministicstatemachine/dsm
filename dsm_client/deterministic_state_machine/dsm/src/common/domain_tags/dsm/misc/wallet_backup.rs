// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: a wallet's backup on storage nodes (DSM Amendment A40).
//!
//! The derivations live in `crate::wallet_backup`; this file only allocates the
//! domains. Every one of them is keyed by the wallet seed, which only the 24
//! words give.

use crate::crypto::domain::TaggedHashDomain;

/// `k = H(tag ‖ wallet_seed)` — the key a wallet's backups are sealed under.
pub const TAG_DSM_WALLET_BACKUP_KEY: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/wallet-backup/key/v1");
/// `l = H(tag ‖ wallet_seed)` — the secret a wallet's backup cells are found by.
pub const TAG_DSM_WALLET_BACKUP_LOCATOR: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/wallet-backup/locator/v1");
/// `K_n = H(tag ‖ l ‖ n)` — the cell of a wallet's `n`-th backup.
pub const TAG_DSM_WALLET_BACKUP_CELL: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/wallet-backup/v1");
/// `s = H(tag ‖ K_n)` — the seed of a backup cell's route.
pub const TAG_DSM_WALLET_BACKUP_SEED: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/wallet-backup/seed/v1");

#[cfg(test)]
pub(crate) const WALLET_BACKUP_TAGS: &[TaggedHashDomain<'static>] = &[
    TAG_DSM_WALLET_BACKUP_KEY,
    TAG_DSM_WALLET_BACKUP_LOCATOR,
    TAG_DSM_WALLET_BACKUP_CELL,
    TAG_DSM_WALLET_BACKUP_SEED,
];
