// SPDX-License-Identifier: MIT OR Apache-2.0

//! Where each recovery object lives on the committed storage set (storage spec
//! §8.3: bytes under derived keys, held in keyed cells, §6).
//!
//! A member stores every entry it is sent at a key and refuses nothing, so a
//! cell can hold many entries, including ones no honest device wrote. Every
//! recovery object is self-verifying, and the reader keeps only what verifies;
//! nothing here is authority. This module fixes the one derivation of each
//! object's key, so the writer and every reader address the same cell.

use crate::common::domain_tags::{TAG_DSM_RECOVERY_CELL, TAG_DSM_RECOVERY_CELL_KEY};
use crate::crypto::blake3::dsm_domain_hasher;

type D32 = [u8; 32];

/// One recovery object's cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryCell {
    /// The recovery-authority anchor a genesis binds (§0.5 step 5).
    AuthorityAnchor { genesis: D32 },
    /// A device's posted PDSMT heads (§0.5 gap 13).
    PdsmtHead { device_id: D32 },
    /// A device's posted PDSMT leaf set at one head.
    PdsmtLeaves {
        genesis: D32,
        device_id: D32,
        head_number: u64,
    },
    /// A relationship's ancestry segment, by the pair's relationship key.
    RelChainSegment { rel_key: D32 },
    /// A new relationship's establishment receipt, by its relationship key.
    EstablishmentReceipt { new_rel_key: D32 },
    /// A device's posted dBTC vault index.
    DbtcVaultIndex { genesis: D32, device_id: D32 },
    /// A successor device's succession proof.
    SuccessionProof { genesis: D32, a_new: D32 },
    /// Tombstones posted for a contact to find.
    TombstoneNotice { contact_device_id: D32 },
    /// A contact's acknowledgement of a device's tombstone.
    TombstoneAck {
        tombstoned_device_id: D32,
        acknowledging_device_id: D32,
    },
}

impl RecoveryCell {
    /// The keyed-cell namespace every recovery object lives under.
    pub fn namespace() -> &'static [u8] {
        TAG_DSM_RECOVERY_CELL.source_bytes()
    }

    /// The cell's key: the object's kind and coordinates under one domain.
    pub fn key(&self) -> D32 {
        let mut hasher = dsm_domain_hasher(TAG_DSM_RECOVERY_CELL_KEY);
        match self {
            Self::AuthorityAnchor { genesis } => {
                hasher.update(&[1]);
                hasher.update(genesis);
            }
            Self::PdsmtHead { device_id } => {
                hasher.update(&[2]);
                hasher.update(device_id);
            }
            Self::PdsmtLeaves {
                genesis,
                device_id,
                head_number,
            } => {
                hasher.update(&[3]);
                hasher.update(genesis);
                hasher.update(device_id);
                hasher.update(&head_number.to_le_bytes());
            }
            Self::RelChainSegment { rel_key } => {
                hasher.update(&[4]);
                hasher.update(rel_key);
            }
            Self::EstablishmentReceipt { new_rel_key } => {
                hasher.update(&[5]);
                hasher.update(new_rel_key);
            }
            Self::DbtcVaultIndex { genesis, device_id } => {
                hasher.update(&[6]);
                hasher.update(genesis);
                hasher.update(device_id);
            }
            Self::SuccessionProof { genesis, a_new } => {
                hasher.update(&[7]);
                hasher.update(genesis);
                hasher.update(a_new);
            }
            Self::TombstoneNotice { contact_device_id } => {
                hasher.update(&[8]);
                hasher.update(contact_device_id);
            }
            Self::TombstoneAck {
                tombstoned_device_id,
                acknowledging_device_id,
            } => {
                hasher.update(&[9]);
                hasher.update(tombstoned_device_id);
                hasher.update(acknowledging_device_id);
            }
        }
        *hasher.finalize().as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every kind addresses its own cell: the same coordinates under two
    /// kinds, or two coordinates under one kind, never share a key.
    #[test]
    fn every_object_has_its_own_cell() {
        let a = [0x0A; 32];
        let b = [0x0B; 32];
        let cells = [
            RecoveryCell::AuthorityAnchor { genesis: a },
            RecoveryCell::PdsmtHead { device_id: a },
            RecoveryCell::PdsmtLeaves {
                genesis: a,
                device_id: b,
                head_number: 0,
            },
            RecoveryCell::PdsmtLeaves {
                genesis: a,
                device_id: b,
                head_number: 1,
            },
            RecoveryCell::RelChainSegment { rel_key: a },
            RecoveryCell::EstablishmentReceipt { new_rel_key: a },
            RecoveryCell::DbtcVaultIndex {
                genesis: a,
                device_id: b,
            },
            RecoveryCell::SuccessionProof {
                genesis: a,
                a_new: b,
            },
            RecoveryCell::TombstoneNotice {
                contact_device_id: a,
            },
            RecoveryCell::TombstoneAck {
                tombstoned_device_id: a,
                acknowledging_device_id: b,
            },
            RecoveryCell::TombstoneAck {
                tombstoned_device_id: b,
                acknowledging_device_id: a,
            },
        ];
        let keys: std::collections::BTreeSet<D32> = cells.iter().map(RecoveryCell::key).collect();
        assert_eq!(keys.len(), cells.len());
    }
}
