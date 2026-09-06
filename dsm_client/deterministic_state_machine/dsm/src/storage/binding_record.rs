// SPDX-License-Identifier: MIT OR Apache-2.0

//! The generic binding record and its digests — SoFi Rev 15 Def 6.20 and
//! §15.5, the storage-engine half of `QuorumBind`.
//!
//! A storage member holds at most one opaque record per resource key and
//! replaces a whole strictly-sorted key set atomically or not at all. What a
//! member may INSPECT is exactly what this module makes inspectable — the
//! schema, the lexicographic round, the key-set digest, and the digest of the
//! exact prior record set — and nothing else. The value a record points at is
//! never decoded here; Class K assigns meaning to `status` and `value_*`, and
//! a member that attached SoFi meaning to any field would be violating §22
//! #12, not implementing it.
//!
//! Everything here is pure and deterministic so the node, the SDK driver and
//! the in-process fleet double all hash the same bytes: the node hashes what
//! it STORES (the canonical protobuf bytes), never a decoded view of it.

use crate::crypto::blake3::dsm_domain_hasher;
use crate::common::domain_tags::{
    TAG_DSM_BINDING_RECORD, TAG_DSM_BINDING_RECORD_SET, TAG_DSM_BINDING_RECORD_SET_KEYS,
};
use crate::types::proto as generated;
use prost::Message;

/// The one live schema of the generic binding record.
pub const BINDING_RECORD_SCHEMA_V1: u32 = 1;

/// Why a byte string is not a generic binding record, or a request is not a
/// well-formed conditional exchange. Every variant is the storage-domain
/// refusal `INVALID_STORAGE_ENCODING` (§15.5): the member did not get far
/// enough to compare anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingEncodingError {
    /// Protobuf decoding failed, or the bytes are not the canonical encoding
    /// of what they decode to. Non-canonical bytes are refused rather than
    /// normalised, because two encodings of one record would be two digests
    /// of one fact.
    Noncanonical,
    /// `schema` is not the live schema.
    UnknownSchema(u32),
    /// A fixed-width field had the wrong width.
    Width { field: &'static str, got: usize },
    /// The key set was empty.
    EmptyKeySet,
    /// The key set was not strictly ascending — unsorted or with duplicates.
    /// A duplicate key would let one cell count twice in a set digest.
    KeysNotStrictlyAscending { at: usize },
    /// The record's `keyset_digest` does not equal the digest of the request's
    /// own keys (Req 15.7 key-set equality).
    KeySetMismatch,
}

impl core::fmt::Display for BindingEncodingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Noncanonical => write!(f, "binding record bytes are not a canonical encoding"),
            Self::UnknownSchema(s) => write!(f, "binding record schema {s} is not live"),
            Self::Width { field, got } => {
                write!(
                    f,
                    "binding record field {field} has width {got}, expected 32"
                )
            }
            Self::EmptyKeySet => write!(f, "a binding key set must name at least one key"),
            Self::KeysNotStrictlyAscending { at } => write!(
                f,
                "binding keys must be strictly ascending; violated at index {at}"
            ),
            Self::KeySetMismatch => write!(
                f,
                "the record's keyset_digest is not the digest of the request's own keys"
            ),
        }
    }
}

impl std::error::Error for BindingEncodingError {}

/// A transaction round: `(counter, proposer_id)`, ordered lexicographically.
///
/// `counter` is a proposer-local persisted monotonic integer — never a
/// timestamp. The derived `Ord` compares `counter` first and `proposer_id`
/// second, which IS the lexicographic order Def 6.20 specifies; the field
/// order of this struct is therefore load-bearing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Round {
    pub counter: u64,
    pub proposer_id: [u8; 32],
}

/// One decoded generic binding record. Constructible only through
/// [`BindingRecord::decode_canonical`] or by a Class K driver that owns every
/// field; a member never fabricates one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingRecord {
    pub schema: u32,
    pub round: Round,
    pub tx_id: [u8; 32],
    pub keyset_digest: [u8; 32],
    pub value_digest: [u8; 32],
    pub value_addr: [u8; 32],
    pub status: u32,
}

fn fixed32(field: &'static str, v: &[u8]) -> Result<[u8; 32], BindingEncodingError> {
    <[u8; 32]>::try_from(v).map_err(|_| BindingEncodingError::Width {
        field,
        got: v.len(),
    })
}

impl BindingRecord {
    fn to_proto(&self) -> generated::GenericBindingRecordV1 {
        generated::GenericBindingRecordV1 {
            schema: self.schema,
            round_counter: self.round.counter,
            proposer_id: self.round.proposer_id.to_vec(),
            tx_id: self.tx_id.to_vec(),
            keyset_digest: self.keyset_digest.to_vec(),
            value_digest: self.value_digest.to_vec(),
            value_addr: self.value_addr.to_vec(),
            status: self.status,
        }
    }

    fn from_proto(p: &generated::GenericBindingRecordV1) -> Result<Self, BindingEncodingError> {
        if p.schema != BINDING_RECORD_SCHEMA_V1 {
            return Err(BindingEncodingError::UnknownSchema(p.schema));
        }
        Ok(Self {
            schema: p.schema,
            round: Round {
                counter: p.round_counter,
                proposer_id: fixed32("proposer_id", &p.proposer_id)?,
            },
            tx_id: fixed32("tx_id", &p.tx_id)?,
            keyset_digest: fixed32("keyset_digest", &p.keyset_digest)?,
            value_digest: fixed32("value_digest", &p.value_digest)?,
            value_addr: fixed32("value_addr", &p.value_addr)?,
            status: p.status,
        })
    }

    /// The canonical bytes: the protobuf encoding of the record. This is what
    /// a member stores and hashes.
    pub fn encode(&self) -> Vec<u8> {
        self.to_proto().encode_to_vec()
    }

    /// Decode bytes that must be the canonical encoding of a live-schema
    /// record with every fixed-width field at width 32. Bytes that decode but
    /// do not re-encode to themselves are refused.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, BindingEncodingError> {
        let p = generated::GenericBindingRecordV1::decode(bytes)
            .map_err(|_| BindingEncodingError::Noncanonical)?;
        let record = Self::from_proto(&p)?;
        if record.encode() != bytes {
            return Err(BindingEncodingError::Noncanonical);
        }
        Ok(record)
    }

    /// `H_dom(DSM/binding-record, canonical bytes)`.
    pub fn digest(&self) -> [u8; 32] {
        record_digest_of_bytes(&self.encode())
    }
}

/// The digest of ALREADY-canonical record bytes, for a member that stores
/// bytes and must not decode more than it inspects.
pub fn record_digest_of_bytes(canonical_bytes: &[u8]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_BINDING_RECORD);
    h.update(canonical_bytes);
    *h.finalize().as_bytes()
}

/// A key set is valid when it is non-empty and strictly ascending — sorted
/// and free of duplicates. The order is what makes a set digest and a
/// deadlock-free lock order the same thing.
pub fn validate_key_set(keys: &[[u8; 32]]) -> Result<(), BindingEncodingError> {
    if keys.is_empty() {
        return Err(BindingEncodingError::EmptyKeySet);
    }
    for (i, w) in keys.windows(2).enumerate() {
        if w[0] >= w[1] {
            return Err(BindingEncodingError::KeysNotStrictlyAscending { at: i + 1 });
        }
    }
    Ok(())
}

/// `H_dom(DSM/binding-record-set-keys, u32_be(count) ‖ keys…)` over a valid
/// key set. Carried inside every record as `keyset_digest`; the member
/// requires it to equal the digest of the request's own keys.
pub fn keyset_digest(keys: &[[u8; 32]]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_BINDING_RECORD_SET_KEYS);
    h.update(&(keys.len() as u32).to_be_bytes());
    for k in keys {
        h.update(k);
    }
    *h.finalize().as_bytes()
}

/// One cell of a record set: a key and, if the member holds one, the digest
/// of its canonical record bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetCell {
    pub key: [u8; 32],
    pub record_digest: Option<[u8; 32]>,
}

/// `H_dom(DSM/binding-record-set, u32_be(count) ‖ for each cell in key
/// order: key ‖ 0x00 | 0x01 ‖ record digest)`.
///
/// Absent cells are IN the preimage, marked `0x00` with no digest, so the
/// digest names the exact prior set including what was empty: a first writer
/// exchanges from the digest of all-absent, and a member that lost a row
/// produces a different set digest rather than a coincidentally matching one.
/// Cells must be in strictly ascending key order.
pub fn record_set_digest(cells: &[SetCell]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_BINDING_RECORD_SET);
    h.update(&(cells.len() as u32).to_be_bytes());
    for c in cells {
        h.update(&c.key);
        match &c.record_digest {
            None => {
                h.update(&[0x00]);
            }
            Some(d) => {
                h.update(&[0x01]);
                h.update(d);
            }
        }
    }
    *h.finalize().as_bytes()
}

/// The digest of a key set holding nothing — what a first writer presents as
/// `expected_digest`.
pub fn empty_set_digest(keys: &[[u8; 32]]) -> [u8; 32] {
    let cells: Vec<SetCell> = keys
        .iter()
        .map(|k| SetCell {
            key: *k,
            record_digest: None,
        })
        .collect();
    record_set_digest(&cells)
}

/// A decoded, validated `CompareExchangeMany` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareExchange {
    pub keys: Vec<[u8; 32]>,
    pub expected_digest: [u8; 32],
    pub replacement: BindingRecord,
    /// The canonical bytes of `replacement`, exactly as received — what a
    /// member stores. Kept beside the decoded form so the member never
    /// re-encodes what it stores.
    pub replacement_bytes: Vec<u8>,
}

/// Decode a `CompareExchangeManyRequestV1`, refusing non-canonical bytes,
/// an invalid key set, and a replacement whose `keyset_digest` is not the
/// digest of these keys.
pub fn decode_compare_exchange(bytes: &[u8]) -> Result<CompareExchange, BindingEncodingError> {
    let req = generated::CompareExchangeManyRequestV1::decode(bytes)
        .map_err(|_| BindingEncodingError::Noncanonical)?;
    if req.encode_to_vec() != bytes {
        return Err(BindingEncodingError::Noncanonical);
    }
    let keys = decode_keys(&req.keys)?;
    let expected_digest = fixed32("expected_digest", &req.expected_digest)?;
    let rp = req
        .replacement
        .as_ref()
        .ok_or(BindingEncodingError::Noncanonical)?;
    let replacement = BindingRecord::from_proto(rp)?;
    if replacement.keyset_digest != keyset_digest(&keys) {
        return Err(BindingEncodingError::KeySetMismatch);
    }
    let replacement_bytes = rp.encode_to_vec();
    Ok(CompareExchange {
        keys,
        expected_digest,
        replacement,
        replacement_bytes,
    })
}

/// Decode a `ReadBindingRequestV1`, refusing non-canonical bytes and an
/// invalid key set.
pub fn decode_read_binding(bytes: &[u8]) -> Result<Vec<[u8; 32]>, BindingEncodingError> {
    let req = generated::ReadBindingRequestV1::decode(bytes)
        .map_err(|_| BindingEncodingError::Noncanonical)?;
    if req.encode_to_vec() != bytes {
        return Err(BindingEncodingError::Noncanonical);
    }
    decode_keys(&req.keys)
}

fn decode_keys(raw: &[Vec<u8>]) -> Result<Vec<[u8; 32]>, BindingEncodingError> {
    let keys = raw
        .iter()
        .map(|k| fixed32("key", k))
        .collect::<Result<Vec<_>, _>>()?;
    validate_key_set(&keys)?;
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(counter: u64, proposer: u8, keys: &[[u8; 32]]) -> BindingRecord {
        BindingRecord {
            schema: BINDING_RECORD_SCHEMA_V1,
            round: Round {
                counter,
                proposer_id: [proposer; 32],
            },
            tx_id: [0xAA; 32],
            keyset_digest: keyset_digest(keys),
            value_digest: [0xBB; 32],
            value_addr: [0xCC; 32],
            status: 1,
        }
    }

    #[test]
    fn a_round_orders_by_counter_then_proposer_lexicographically() {
        let lo_lo = Round {
            counter: 1,
            proposer_id: [0x01; 32],
        };
        let lo_hi = Round {
            counter: 1,
            proposer_id: [0xFF; 32],
        };
        let hi_lo = Round {
            counter: 2,
            proposer_id: [0x00; 32],
        };
        assert!(lo_lo < lo_hi, "same counter: proposer id breaks the tie");
        assert!(lo_hi < hi_lo, "a higher counter beats any proposer id");
        assert_eq!(lo_lo, lo_lo);
    }

    #[test]
    fn a_record_round_trips_canonically_and_noncanonical_bytes_are_refused() {
        let keys = [[1u8; 32], [2u8; 32]];
        let r = rec(3, 0x07, &keys);
        let bytes = r.encode();
        assert_eq!(BindingRecord::decode_canonical(&bytes).unwrap(), r);
        // A trailing byte still decodes under protobuf's lenient reader but
        // is not canonical.
        let mut padded = bytes.clone();
        padded.push(0);
        assert_eq!(
            BindingRecord::decode_canonical(&padded),
            Err(BindingEncodingError::Noncanonical)
        );
        // A wrong-width fixed field is refused by name.
        let mut p = generated::GenericBindingRecordV1::decode(&bytes[..]).unwrap();
        p.tx_id = vec![1, 2, 3];
        assert_eq!(
            BindingRecord::decode_canonical(&p.encode_to_vec()),
            Err(BindingEncodingError::Width {
                field: "tx_id",
                got: 3
            })
        );
        // A dead schema is refused.
        let mut p = generated::GenericBindingRecordV1::decode(&bytes[..]).unwrap();
        p.schema = 2;
        assert_eq!(
            BindingRecord::decode_canonical(&p.encode_to_vec()),
            Err(BindingEncodingError::UnknownSchema(2))
        );
    }

    #[test]
    fn a_key_set_must_be_non_empty_and_strictly_ascending() {
        assert_eq!(
            validate_key_set(&[]),
            Err(BindingEncodingError::EmptyKeySet)
        );
        assert_eq!(
            validate_key_set(&[[2; 32], [1; 32]]),
            Err(BindingEncodingError::KeysNotStrictlyAscending { at: 1 })
        );
        assert_eq!(
            validate_key_set(&[[1; 32], [1; 32]]),
            Err(BindingEncodingError::KeysNotStrictlyAscending { at: 1 }),
            "a duplicate would count one cell twice"
        );
        assert!(validate_key_set(&[[1; 32], [2; 32], [3; 32]]).is_ok());
    }

    #[test]
    fn set_digests_name_absences_and_change_with_any_cell() {
        let keys = [[1u8; 32], [2u8; 32]];
        let empty = empty_set_digest(&keys);
        let r = rec(1, 1, &keys);
        let one = record_set_digest(&[
            SetCell {
                key: keys[0],
                record_digest: Some(r.digest()),
            },
            SetCell {
                key: keys[1],
                record_digest: None,
            },
        ]);
        let both = record_set_digest(&[
            SetCell {
                key: keys[0],
                record_digest: Some(r.digest()),
            },
            SetCell {
                key: keys[1],
                record_digest: Some(r.digest()),
            },
        ]);
        assert_ne!(empty, one);
        assert_ne!(one, both);
        assert_ne!(
            empty,
            empty_set_digest(&[[1u8; 32]]),
            "the key set is part of the preimage"
        );
        assert_eq!(empty, empty_set_digest(&keys), "deterministic");
    }

    #[test]
    fn a_compare_exchange_request_binds_its_own_key_set() {
        let keys = vec![[1u8; 32], [2u8; 32]];
        let r = rec(1, 1, &keys);
        let req = generated::CompareExchangeManyRequestV1 {
            keys: keys.iter().map(|k| k.to_vec()).collect(),
            expected_digest: empty_set_digest(&keys).to_vec(),
            replacement: Some(generated::GenericBindingRecordV1::decode(&r.encode()[..]).unwrap()),
        };
        let bytes = req.encode_to_vec();
        let cx = decode_compare_exchange(&bytes).expect("well-formed");
        assert_eq!(cx.keys, keys);
        assert_eq!(cx.replacement, r);
        assert_eq!(cx.replacement_bytes, r.encode());

        // The same record presented over a DIFFERENT key set is refused: its
        // keyset_digest names the keys it was built for.
        let mut other = req.clone();
        other.keys = vec![[1u8; 32].to_vec(), [3u8; 32].to_vec()];
        assert_eq!(
            decode_compare_exchange(&other.encode_to_vec()),
            Err(BindingEncodingError::KeySetMismatch)
        );
        // Unsorted keys are refused before anything is compared.
        let mut unsorted = req.clone();
        unsorted.keys.reverse();
        assert_eq!(
            decode_compare_exchange(&unsorted.encode_to_vec()),
            Err(BindingEncodingError::KeysNotStrictlyAscending { at: 1 })
        );
    }
}
