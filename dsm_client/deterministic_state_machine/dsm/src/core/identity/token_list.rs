// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tokens a device has added, as the device states them (owner,
//! 2026-11-21).
//!
//! A device credits a token only once it has added it (adoption precedes
//! receipt), so a contact that sends it a token it has not added is debited
//! for a transfer the device refuses, and the relationship waits on it. The
//! device therefore states which tokens it has added, in a list its AK signs
//! and keeps in its own directory cell, beside its entry. A contact reads
//! the cell, keeps every list that verifies under the AK it pinned for the
//! device, and offers the device only those tokens.
//!
//! Adding a token is permanent, so a list never takes a token back: every
//! list that verifies still holds, and what a device has added is the union
//! of them. A member that serves an older list hides a token the device added
//! since; it cannot name one the device has not added.
//!
//! The protocol's own assets are in no list: every device holds them.

use std::collections::BTreeSet;

use prost::Message;

use crate::common::domain_tags::TAG_DSM_DEVICE_TOKEN_LIST;
use crate::crypto::blake3::dsm_domain_hasher;
use crate::crypto::sphincs;
use crate::types::proto;

/// The tokens a device has added, by policy commit, and its AK's signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceTokenList {
    pub genesis: [u8; 32],
    pub device_id: [u8; 32],
    /// Distinct and ascending.
    pub policy_commits: Vec<[u8; 32]>,
    pub signature: Vec<u8>,
}

/// Why bytes are not a list of a device's tokens. Every reader reaches the
/// same answer from the same bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenListError {
    /// Not the one canonical encoding of a list: why.
    Malformed(String),
    /// The list names another device than the one read.
    AnotherDevice,
    /// The signature does not verify under the device's AK.
    SignatureDoesNotVerify,
}

impl core::fmt::Display for TokenListError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "token list is malformed: {why}"),
            Self::AnotherDevice => write!(f, "token list names another device"),
            Self::SignatureDoesNotVerify => write!(f, "token list signature does not verify"),
        }
    }
}

impl std::error::Error for TokenListError {}

impl DeviceTokenList {
    fn to_proto(&self, signature: Vec<u8>) -> proto::DeviceTokenListV1 {
        proto::DeviceTokenListV1 {
            genesis: self.genesis.to_vec(),
            device_id: self.device_id.to_vec(),
            policy_commits: self.policy_commits.iter().map(|c| c.to_vec()).collect(),
            signature,
        }
    }

    /// The digest AK signs: `H(DSM/device-token-list/v1 ‖ 0x00 ‖ the list's
    /// bytes with no signature)`.
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut h = dsm_domain_hasher(TAG_DSM_DEVICE_TOKEN_LIST);
        h.update(&self.to_proto(Vec::new()).encode_to_vec());
        *h.finalize().as_bytes()
    }

    /// The list of `policy_commits`, in whatever order they are given, signed
    /// with the device's AK secret key.
    pub fn sign(
        genesis: [u8; 32],
        device_id: [u8; 32],
        policy_commits: impl IntoIterator<Item = [u8; 32]>,
        ak_secret_key: &[u8],
    ) -> Result<Self, crate::types::error::DsmError> {
        let ordered: BTreeSet<[u8; 32]> = policy_commits.into_iter().collect();
        let mut list = Self {
            genesis,
            device_id,
            policy_commits: ordered.into_iter().collect(),
            signature: Vec::new(),
        };
        list.signature = sphincs::sphincs_sign(ak_secret_key, &list.signing_digest())?;
        Ok(list)
    }

    /// The exact bytes written to the cell.
    pub fn encode(&self) -> Vec<u8> {
        self.to_proto(self.signature.clone()).encode_to_vec()
    }

    /// Decode cell bytes: only the one canonical encoding of a list, its
    /// commits 32 bytes each, distinct and ascending.
    pub fn decode(bytes: &[u8]) -> Result<Self, TokenListError> {
        let p = proto::DeviceTokenListV1::decode(bytes)
            .map_err(|e| TokenListError::Malformed(e.to_string()))?;
        if p.encode_to_vec() != bytes {
            return Err(TokenListError::Malformed(
                "not the canonical encoding".to_string(),
            ));
        }
        let d32 = |v: &[u8]| {
            <[u8; 32]>::try_from(v).map_err(|e| TokenListError::Malformed(e.to_string()))
        };
        let policy_commits = p
            .policy_commits
            .iter()
            .map(|c| d32(c))
            .collect::<Result<Vec<[u8; 32]>, TokenListError>>()?;
        if policy_commits.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(TokenListError::Malformed(
                "the commits are not distinct and ascending".to_string(),
            ));
        }
        Ok(Self {
            genesis: d32(&p.genesis)?,
            device_id: d32(&p.device_id)?,
            policy_commits,
            signature: p.signature,
        })
    }

    /// Whether the list is `device_id`'s under `genesis`, signed by
    /// `ak_public_key`: the AK the reader pinned for the device.
    pub fn verify(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        ak_public_key: &[u8],
    ) -> Result<(), TokenListError> {
        if &self.genesis != genesis || &self.device_id != device_id {
            return Err(TokenListError::AnotherDevice);
        }
        match sphincs::sphincs_verify(ak_public_key, &self.signing_digest(), &self.signature) {
            Ok(verified) if verified => Ok(()),
            Ok(_) | Err(..) => Err(TokenListError::SignatureDoesNotVerify),
        }
    }
}

/// The tokens `device_id` has added, from the values its directory cell
/// holds: the union of every list among them that verifies under
/// `ak_public_key`. `None` when no list verifies: the device has stated
/// none, which is not the same as a device that has added nothing. Each
/// distinct value is checked once; a value that is no list of this device
/// (the device's directory entries are in the same cell) costs its decoding.
pub fn tokens_added<'a>(
    genesis: &[u8; 32],
    device_id: &[u8; 32],
    ak_public_key: &[u8],
    values: impl IntoIterator<Item = &'a [u8]>,
) -> Option<BTreeSet<[u8; 32]>> {
    let mut checked: BTreeSet<&'a [u8]> = BTreeSet::new();
    let mut added: Option<BTreeSet<[u8; 32]>> = None;
    for bytes in values {
        if !checked.insert(bytes) {
            continue;
        }
        let Ok(list) = DeviceTokenList::decode(bytes) else {
            continue;
        };
        if let Ok(()) = list.verify(genesis, device_id, ak_public_key) {
            added
                .get_or_insert_with(BTreeSet::new)
                .extend(list.policy_commits);
        }
    }
    added
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sphincs::generate_keypair_from_seed;
    use crate::crypto::sphincs::SphincsVariant;

    const GENESIS: [u8; 32] = [0x11; 32];
    const DEVICE: [u8; 32] = [0x22; 32];

    fn ak(seed: u8) -> crate::crypto::sphincs::SphincsKeyPair {
        generate_keypair_from_seed(SphincsVariant::SPX256f, &[seed; 32]).expect("an AK")
    }

    fn signed(commits: &[[u8; 32]], key: &crate::crypto::sphincs::SphincsKeyPair) -> Vec<u8> {
        DeviceTokenList::sign(GENESIS, DEVICE, commits.iter().copied(), &key.secret_key)
            .expect("a signed list")
            .encode()
    }

    /// A device's list round-trips, in order whatever order it was given in,
    /// and verifies only for its device and under its AK.
    /// MUTATION CONTROL: `verify` without its signature check reads the
    /// other key's list as the device's; without its device check, another
    /// device's.
    #[test]
    fn a_list_verifies_only_for_its_device_under_its_ak() {
        let key = ak(1);
        let bytes = signed(&[[0xBB; 32], [0xAA; 32], [0xBB; 32]], &key);
        let list = DeviceTokenList::decode(&bytes).expect("the canonical bytes");
        assert_eq!(list.policy_commits, vec![[0xAA; 32], [0xBB; 32]]);
        assert_eq!(list.encode(), bytes);
        assert_eq!(list.verify(&GENESIS, &DEVICE, &key.public_key), Ok(()));
        assert_eq!(
            list.verify(&GENESIS, &DEVICE, &ak(2).public_key),
            Err(TokenListError::SignatureDoesNotVerify)
        );
        assert_eq!(
            list.verify(&GENESIS, &[0x33; 32], &key.public_key),
            Err(TokenListError::AnotherDevice)
        );
        assert_eq!(
            list.verify(&[0x44; 32], &DEVICE, &key.public_key),
            Err(TokenListError::AnotherDevice)
        );
    }

    /// A list whose commits were changed after signing, or that is not the
    /// canonical encoding, is no list of the device's.
    #[test]
    fn a_changed_or_uncanonical_list_is_refused() {
        let key = ak(1);
        let mut changed = DeviceTokenList::decode(&signed(&[[0xAA; 32]], &key)).expect("a list");
        changed.policy_commits.push([0xCC; 32]);
        assert_eq!(
            changed.verify(&GENESIS, &DEVICE, &key.public_key),
            Err(TokenListError::SignatureDoesNotVerify)
        );
        let unordered = proto::DeviceTokenListV1 {
            genesis: GENESIS.to_vec(),
            device_id: DEVICE.to_vec(),
            policy_commits: vec![vec![0xBB; 32], vec![0xAA; 32]],
            signature: Vec::new(),
        }
        .encode_to_vec();
        assert!(matches!(
            DeviceTokenList::decode(&unordered),
            Err(TokenListError::Malformed(..))
        ));
        let mut trailing = signed(&[[0xAA; 32]], &key);
        trailing.extend_from_slice(&[0x28, 0x01]);
        assert!(matches!(
            DeviceTokenList::decode(&trailing),
            Err(TokenListError::Malformed(..))
        ));
    }

    /// What a device has added is the union of its lists that verify; bytes
    /// that are no list of its own, and another key's list, add nothing; and
    /// a cell with no list of the device's says so.
    /// MUTATION CONTROL: taking only the last list read turns this red (the
    /// older list's token is lost); answering an empty set for no list turns
    /// it red at "has stated none".
    #[test]
    fn the_tokens_added_are_the_union_of_the_lists_that_verify() {
        let key = ak(1);
        let older = signed(&[[0xAA; 32]], &key);
        let newer = signed(&[[0xBB; 32], [0xCC; 32]], &key);
        let forged = signed(&[[0xEE; 32]], &ak(2));
        let junk = vec![0x0A, 0x03, 0x01, 0x02, 0x03];
        let values = [
            older.as_slice(),
            junk.as_slice(),
            forged.as_slice(),
            newer.as_slice(),
            older.as_slice(),
        ];
        assert_eq!(
            tokens_added(&GENESIS, &DEVICE, &key.public_key, values),
            Some(BTreeSet::from([[0xAA; 32], [0xBB; 32], [0xCC; 32]]))
        );
        assert_eq!(
            tokens_added(
                &GENESIS,
                &DEVICE,
                &key.public_key,
                [junk.as_slice(), forged.as_slice()]
            ),
            None,
            "a device with no list of its own has stated none"
        );
        let nothing = signed(&[], &key);
        assert_eq!(
            tokens_added(&GENESIS, &DEVICE, &key.public_key, [nothing.as_slice()]),
            Some(BTreeSet::new()),
            "a device that states it has added nothing"
        );
    }
}
