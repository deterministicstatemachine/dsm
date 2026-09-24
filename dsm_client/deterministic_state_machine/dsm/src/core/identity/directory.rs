// SPDX-License-Identifier: MIT OR Apache-2.0

//! The device directory: each device's own, self-signed entry (owner,
//! 2026-09-23).
//!
//! A device writes its own entry — its genesis, its device id, its authority
//! key AK, its birth attestation AttA, its Kyber key and a counter — signed
//! with AK, to a keyed cell every member of the set holds. A node stores every
//! entry it is given and checks nothing: it has no authority over whose entry
//! is whose. A sender reads the cell and keeps the entry that proves itself:
//!
//! 1. `DevID = H("DSM/devid" ‖ AK ‖ AttA)` equals the device id the entry names,
//!    so the AK is the one the device id commits;
//! 2. the signature verifies under that AK;
//! 3. among entries that pass, the highest counter wins, so a device can
//!    update its own entry.
//!
//! Knowing a device id is not enough to write a valid entry for it: that takes
//! an AK hashing to the id and a signature by it. A squatter's junk fails the
//! check and is ignored, and no one can lock a device out.

use prost::Message;

use crate::common::domain_tags::{TAG_DSM_DEVICE_DIRECTORY_ENTRY, TAG_DSM_DEVICE_DIRECTORY_KEY};
use crate::core::identity::genesis_v2::derive_devid;
use crate::crypto::blake3::dsm_domain_hasher;
use crate::crypto::sphincs;
use crate::types::proto;

/// The cell namespace every directory entry is written under.
pub const DIRECTORY_NAMESPACE: &[u8] = b"DSM/device-directory/v1";

/// An AK public key (SPHINCS+ SPX256f).
pub const AK_PUBLIC_KEY_LEN: usize = 64;

/// A Kyber (ML-KEM-768) public key.
pub const KYBER_PUBLIC_KEY_LEN: usize = 1184;

/// The cell a device's entries live in: one per (genesis, device).
pub fn directory_cell_key(genesis: &[u8; 32], device_id: &[u8; 32]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_DEVICE_DIRECTORY_KEY);
    h.update(genesis);
    h.update(device_id);
    *h.finalize().as_bytes()
}

/// What an entry states about its device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEntryBody {
    pub genesis: [u8; 32],
    pub device_id: [u8; 32],
    pub ak_public_key: Vec<u8>,
    pub att_a: [u8; 32],
    pub kyber_public_key: Vec<u8>,
    /// Higher replaces lower. Only the device can sign one.
    pub counter: u64,
}

impl DirectoryEntryBody {
    pub fn to_proto(&self) -> proto::DeviceDirectoryEntryBodyV1 {
        proto::DeviceDirectoryEntryBodyV1 {
            genesis: self.genesis.to_vec(),
            device_id: self.device_id.to_vec(),
            ak_public_key: self.ak_public_key.clone(),
            att_a: self.att_a.to_vec(),
            kyber_public_key: self.kyber_public_key.clone(),
            counter: self.counter,
        }
    }

    /// The digest AK signs: `H(DSM/device-directory-entry/v1 ‖ 0x00 ‖ body bytes)`.
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut h = dsm_domain_hasher(TAG_DSM_DEVICE_DIRECTORY_ENTRY);
        h.update(&self.to_proto().encode_to_vec());
        *h.finalize().as_bytes()
    }
}

/// A body and its AK signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEntry {
    pub body: DirectoryEntryBody,
    pub signature: Vec<u8>,
}

/// Why an entry does not prove itself. None of these is a node's decision:
/// every reader reaches the same one from the same bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryError {
    /// Not the one canonical encoding of an entry: why.
    Malformed(String),
    /// A key has the wrong length.
    KeyLength,
    /// `H(AK ‖ AttA)` is not the device id the entry names.
    NotThisDevicesKey,
    /// The signature does not verify under the entry's AK.
    SignatureDoesNotVerify,
}

impl core::fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "directory entry is malformed: {why}"),
            Self::KeyLength => write!(f, "directory entry key has the wrong length"),
            Self::NotThisDevicesKey => write!(f, "directory entry's AK is not the device's"),
            Self::SignatureDoesNotVerify => write!(f, "directory entry signature does not verify"),
        }
    }
}

impl std::error::Error for DirectoryError {}

impl DirectoryEntry {
    /// Sign `body` with the device's AK secret key.
    pub fn sign(
        body: DirectoryEntryBody,
        ak_secret_key: &[u8],
    ) -> Result<Self, crate::types::error::DsmError> {
        let signature = sphincs::sphincs_sign(ak_secret_key, &body.signing_digest())?;
        Ok(Self { body, signature })
    }

    /// The exact bytes written to the cell.
    pub fn encode(&self) -> Vec<u8> {
        proto::DeviceDirectoryEntryV1 {
            body: Some(self.body.to_proto()),
            signature: self.signature.clone(),
        }
        .encode_to_vec()
    }

    /// Decode cell bytes: only the one canonical encoding of an entry.
    pub fn decode(bytes: &[u8]) -> Result<Self, DirectoryError> {
        let p = proto::DeviceDirectoryEntryV1::decode(bytes)
            .map_err(|e| DirectoryError::Malformed(e.to_string()))?;
        if p.encode_to_vec() != bytes {
            return Err(DirectoryError::Malformed(
                "not the canonical encoding".to_string(),
            ));
        }
        let b = p
            .body
            .ok_or_else(|| DirectoryError::Malformed("no body".to_string()))?;
        let d32 = |v: &[u8]| {
            <[u8; 32]>::try_from(v).map_err(|e| DirectoryError::Malformed(e.to_string()))
        };
        Ok(Self {
            body: DirectoryEntryBody {
                genesis: d32(&b.genesis)?,
                device_id: d32(&b.device_id)?,
                ak_public_key: b.ak_public_key,
                att_a: d32(&b.att_a)?,
                kyber_public_key: b.kyber_public_key,
                counter: b.counter,
            },
            signature: p.signature,
        })
    }

    /// Whether the entry proves itself: its AK is the one its device id
    /// commits, and its signature verifies under that AK.
    pub fn verify(&self) -> Result<(), DirectoryError> {
        let b = &self.body;
        if b.ak_public_key.len() != AK_PUBLIC_KEY_LEN
            || b.kyber_public_key.len() != KYBER_PUBLIC_KEY_LEN
        {
            return Err(DirectoryError::KeyLength);
        }
        if derive_devid(&b.ak_public_key, &b.att_a) != b.device_id {
            return Err(DirectoryError::NotThisDevicesKey);
        }
        match sphincs::sphincs_verify(&b.ak_public_key, &b.signing_digest(), &self.signature) {
            Ok(true) => Ok(()),
            Ok(false) | Err(..) => Err(DirectoryError::SignatureDoesNotVerify),
        }
    }
}

/// From everything read at a device's cell, across every member, the entry to
/// use: one that names this genesis and device and proves itself, with the
/// highest counter. Ties (only the device itself could sign two) go to the
/// smallest encoding, so every reader picks the same one. `None` when nothing
/// proves itself.
pub fn select_entry<'a>(
    genesis: &[u8; 32],
    device_id: &[u8; 32],
    values: impl IntoIterator<Item = &'a [u8]>,
) -> Option<DirectoryEntry> {
    let mut best: Option<(DirectoryEntry, Vec<u8>)> = None;
    for bytes in values {
        let Ok(entry) = DirectoryEntry::decode(bytes) else {
            continue;
        };
        if &entry.body.genesis != genesis || &entry.body.device_id != device_id {
            continue;
        }
        if entry.verify().is_err() {
            continue;
        }
        let better = match &best {
            None => true,
            Some((b, b_bytes)) => {
                entry.body.counter > b.body.counter
                    || (entry.body.counter == b.body.counter && bytes < b_bytes.as_slice())
            }
        };
        if better {
            best = Some((entry, bytes.to_vec()));
        }
    }
    best.map(|(entry, ..)| entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(seed: u8) -> (Vec<u8>, Vec<u8>, [u8; 32], [u8; 32]) {
        let (pk, sk) =
            sphincs::generate_keypair_from_seed(sphincs::SphincsVariant::SPX256f, &[seed; 32])
                .map(|kp| (kp.public_key.clone(), kp.secret_key.clone()))
                .expect("keypair");
        let att_a = [seed.wrapping_add(1); 32];
        let device_id = derive_devid(&pk, &att_a);
        (pk, sk, att_a, device_id)
    }

    fn body(pk: &[u8], att_a: [u8; 32], device_id: [u8; 32], counter: u64) -> DirectoryEntryBody {
        DirectoryEntryBody {
            genesis: [9u8; 32],
            device_id,
            ak_public_key: pk.to_vec(),
            att_a,
            kyber_public_key: vec![counter as u8; KYBER_PUBLIC_KEY_LEN],
            counter,
        }
    }

    #[test]
    fn the_devices_own_entry_is_chosen_and_a_squatters_is_ignored() {
        let (pk, sk, att_a, id) = device(1);
        let own = DirectoryEntry::sign(body(&pk, att_a, id, 1), &sk).unwrap();
        assert_eq!(own.verify(), Ok(()));

        // A squatter knows the device id, and even the AK and AttA, but signs
        // with its own key: the signature does not verify.
        let squatter = device(2);
        let squat = DirectoryEntry::sign(body(&pk, att_a, id, 99), &squatter.1).unwrap();
        assert_eq!(squat.verify(), Err(DirectoryError::SignatureDoesNotVerify));

        // A squatter with its own AK cannot make it hash to this device id.
        let (spk, ssk, satt, ..) = device(3);
        let foreign = DirectoryEntry::sign(body(&spk, satt, id, 99), &ssk).unwrap();
        assert_eq!(foreign.verify(), Err(DirectoryError::NotThisDevicesKey));

        let values = [
            squat.encode(),
            foreign.encode(),
            b"junk".to_vec(),
            own.encode(),
        ];
        let chosen = select_entry(&[9u8; 32], &id, values.iter().map(Vec::as_slice));
        assert_eq!(chosen, Some(own));
    }

    #[test]
    fn a_higher_counter_replaces_a_lower_one() {
        let (pk, sk, att_a, id) = device(4);
        let first = DirectoryEntry::sign(body(&pk, att_a, id, 1), &sk).unwrap();
        let second = DirectoryEntry::sign(body(&pk, att_a, id, 2), &sk).unwrap();
        let values = [second.encode(), first.encode()];
        let chosen = select_entry(&[9u8; 32], &id, values.iter().map(Vec::as_slice)).unwrap();
        assert_eq!(chosen.body.counter, 2);
    }

    #[test]
    fn an_entry_for_another_device_or_genesis_is_not_chosen() {
        let (pk, sk, att_a, id) = device(5);
        let entry = DirectoryEntry::sign(body(&pk, att_a, id, 1), &sk).unwrap();
        let bytes = [entry.encode()];
        assert!(select_entry(&[8u8; 32], &id, bytes.iter().map(Vec::as_slice)).is_none());
        assert!(select_entry(&[9u8; 32], &[0u8; 32], bytes.iter().map(Vec::as_slice)).is_none());
    }

    #[test]
    fn only_the_canonical_encoding_decodes() {
        let (pk, sk, att_a, id) = device(6);
        let mut bytes = DirectoryEntry::sign(body(&pk, att_a, id, 1), &sk)
            .unwrap()
            .encode();
        bytes.extend_from_slice(&[0x10, 0x01]); // a repeated field appended
        assert!(matches!(
            DirectoryEntry::decode(&bytes),
            Err(DirectoryError::Malformed(..))
        ));
    }
}
