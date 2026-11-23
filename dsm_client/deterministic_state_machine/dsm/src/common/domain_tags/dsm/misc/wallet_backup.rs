// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: a wallet's backup on storage nodes (DSM Amendment A40).
//!
//! The derivations live in `crate::wallet_backup`; this file only allocates the
//! domains. The key and the locator are keyed by the wallet seed, which only
//! the 24 words give.

use crate::crypto::domain::TaggedHashDomain;

/// `k = H(tag ‖ wallet_seed)` — the key a wallet's backups are sealed under.
pub const TAG_DSM_WALLET_BACKUP_KEY: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/wallet-backup/key/v1");
/// `l = H(tag ‖ wallet_seed)` — the secret route of a wallet's backup slot.
pub const TAG_DSM_WALLET_BACKUP_LOCATOR: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/wallet-backup/locator/v1");
/// `S = H(tag ‖ l ‖ lock)` — a device's one backup slot.
pub const TAG_DSM_WALLET_BACKUP_SLOT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/wallet-backup/slot/v1");
/// What a device's cell lock signs to start a write of its backup slot.
pub const TAG_DSM_WALLET_BACKUP_SLOT_WRITE: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/wallet-backup/slot-write/v1");
/// `d = H(tag ‖ sealed part)` — a part's digest, as the start names it.
pub const TAG_DSM_WALLET_BACKUP_PART: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/wallet-backup/part/v1");

/// The namespace the backup cells of before 2026-11-23 were written in. No
/// member keeps a write there any more (owner, 2026-11-23: "adjust the code
/// after that so that there's no longer that spot").
pub const RETIRED_WALLET_BACKUP_CELLS: &[u8] = b"DSM/wallet-backup/v1";

#[cfg(test)]
pub(crate) const WALLET_BACKUP_TAGS: &[TaggedHashDomain<'static>] = &[
    TAG_DSM_WALLET_BACKUP_KEY,
    TAG_DSM_WALLET_BACKUP_LOCATOR,
    TAG_DSM_WALLET_BACKUP_SLOT,
    TAG_DSM_WALLET_BACKUP_SLOT_WRITE,
    TAG_DSM_WALLET_BACKUP_PART,
];
