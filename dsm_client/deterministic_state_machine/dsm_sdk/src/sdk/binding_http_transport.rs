// SPDX-License-Identifier: Apache-2.0

//! THE CONCRETE HTTP `BindingTransport` (Rev 15 §15.5, Req 15.8).
//!
//! [`crate::sdk::quorum_bind_runner`] drives the sans-IO engine over a
//! [`BindingTransport`]; this is its production implementation over the two
//! generic endpoints Class N exposes:
//!
//! - `POST /api/v2/storage/binding/read`  — `ReadBinding`, public.
//! - `POST /api/v2/storage/binding/cas`   — `CompareExchangeMany`, device auth.
//!
//! The wire messages are the single canonical protobuf definitions
//! (`dsm::types::proto`), the same the node decodes, so the two sides cannot
//! drift. Every answer carries the member's `member_id` and
//! `register_incarnation`; this transport reports both, and the runner
//! authenticates them against the committed member before counting (Req 15.8).
//! The node is application-blind: this transport sends only opaque keys, an
//! expected digest, and a canonical record — never a claim, vault, or route.

use dsm::types::proto::{self as pb, Message as _};

use super::quorum_bind_runner::{BindingTransport, CasOutcome, TransportCas, TransportRead};
use super::storage_node_sdk::{build_ca_aware_client, one_shot_claim_headers, StorageAuthContext};
use async_trait::async_trait;
use dsm::storage::binding_record::BindingRecord;

/// One committed member's reachable endpoint and (for writes) its device auth.
#[derive(Debug, Clone)]
pub struct MemberEndpoint {
    pub endpoint: String,
    pub auth: Option<StorageAuthContext>,
}

/// The HTTP transport over one committed storage set. `members` is indexed like
/// the engine's `BindingTransaction.members`, so `member_ix` selects the same
/// member on both sides.
pub struct HttpBindingTransport {
    members: Vec<MemberEndpoint>,
    client: reqwest::Client,
}

impl HttpBindingTransport {
    pub fn new(members: Vec<MemberEndpoint>) -> Self {
        HttpBindingTransport {
            members,
            client: build_ca_aware_client(),
        }
    }

    fn url(&self, member_ix: usize, suffix: &str) -> Option<String> {
        let base = self.members.get(member_ix)?.endpoint.trim_end_matches('/');
        Some(format!("{base}{suffix}"))
    }
}

// ───────────────────────── pure codec ─────────────────────────

/// `ReadBindingRequestV1` bytes for a key set.
pub fn encode_read_request(keys: &[[u8; 32]]) -> Vec<u8> {
    pb::ReadBindingRequestV1 {
        keys: keys.iter().map(|k| k.to_vec()).collect(),
    }
    .encode_to_vec()
}

/// `CompareExchangeManyRequestV1` bytes. `replacement_bytes` are the engine's
/// canonical `GenericBindingRecordV1` bytes; a caller that hands non-canonical
/// bytes gets `None` and must not send them.
pub fn encode_cas_request(
    keys: &[[u8; 32]],
    expected_digest: [u8; 32],
    replacement_bytes: &[u8],
) -> Option<Vec<u8>> {
    // Re-decode the engine's record so the request carries the structured
    // message the node expects, and refuse anything that is not canonical.
    let record = BindingRecord::decode_canonical(replacement_bytes).ok()?;
    let replacement = pb::GenericBindingRecordV1 {
        schema: record.schema,
        round_counter: record.round.counter,
        proposer_id: record.round.proposer_id.to_vec(),
        tx_id: record.tx_id.to_vec(),
        keyset_digest: record.keyset_digest.to_vec(),
        value_digest: record.value_digest.to_vec(),
        value_addr: record.value_addr.to_vec(),
        status: record.status,
    };
    Some(
        pb::CompareExchangeManyRequestV1 {
            keys: keys.iter().map(|k| k.to_vec()).collect(),
            expected_digest: expected_digest.to_vec(),
            replacement: Some(replacement),
        }
        .encode_to_vec(),
    )
}

fn as_32(v: &[u8]) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(v).ok()
}

/// Parse a `ReadBinding` answer into an attributed [`TransportRead`].
/// `ok` is whether the HTTP status was 200; anything else (503, transport
/// failure) is unavailable. Records are returned in `keys` order, mapping each
/// returned cell back to its key so a member that reorders or omits cells
/// cannot shift a record onto the wrong key.
pub fn parse_read_response(ok: bool, body: &[u8], keys: &[[u8; 32]]) -> TransportRead {
    let unavailable = || TransportRead {
        echoed_member_id: None,
        echoed_incarnation: None,
        records: None,
    };
    if !ok {
        return unavailable();
    }
    let Ok(msg) = pb::ReadBindingResponseV1::decode(body) else {
        return unavailable();
    };
    // Index the returned cells by key.
    let mut by_key: std::collections::BTreeMap<[u8; 32], Option<BindingRecord>> =
        std::collections::BTreeMap::new();
    for cell in &msg.cells {
        let Some(k) = as_32(&cell.key) else {
            return unavailable();
        };
        let record = match &cell.record {
            None => None,
            Some(r) => match decode_record(r) {
                Some(rec) => Some(rec),
                None => return unavailable(),
            },
        };
        by_key.insert(k, record);
    }
    // Every requested key must be present exactly once (Req 15.13 exhaustive).
    let mut records = Vec::with_capacity(keys.len());
    for k in keys {
        match by_key.get(k) {
            Some(r) => records.push(r.clone()),
            None => return unavailable(),
        }
    }
    TransportRead {
        echoed_member_id: Some(msg.member_id),
        echoed_incarnation: as_32(&msg.register_incarnation),
        records: Some(records),
    }
}

/// Parse a `CompareExchangeMany` answer into an attributed [`TransportCas`].
/// The node returns 200 with the outcome in the body (including
/// `INVALID_STORAGE_ENCODING`); a 503 or transport failure is unavailable.
pub fn parse_cas_response(ok: bool, body: &[u8]) -> TransportCas {
    let unavailable = || TransportCas {
        echoed_member_id: None,
        echoed_incarnation: None,
        outcome: None,
    };
    if !ok {
        return unavailable();
    }
    let Ok(msg) = pb::CompareExchangeManyResponseV1::decode(body) else {
        return unavailable();
    };
    use pb::compare_exchange_many_response_v1::Outcome;
    let outcome = match Outcome::try_from(msg.outcome) {
        Ok(Outcome::Applied) => Some(CasOutcome::Applied),
        Ok(Outcome::ExpectationMismatch) => Some(CasOutcome::ExpectationMismatch),
        Ok(Outcome::InvalidStorageEncoding) => Some(CasOutcome::InvalidStorageEncoding),
        // UNAVAILABLE, or an unknown code, is not a countable answer.
        _ => None,
    };
    TransportCas {
        echoed_member_id: Some(msg.member_id),
        echoed_incarnation: as_32(&msg.register_incarnation),
        outcome,
    }
}

fn decode_record(r: &pb::GenericBindingRecordV1) -> Option<BindingRecord> {
    Some(BindingRecord {
        schema: r.schema,
        round: dsm::storage::binding_record::Round {
            counter: r.round_counter,
            proposer_id: as_32(&r.proposer_id)?,
        },
        tx_id: as_32(&r.tx_id)?,
        keyset_digest: as_32(&r.keyset_digest)?,
        value_digest: as_32(&r.value_digest)?,
        value_addr: as_32(&r.value_addr)?,
        status: r.status,
    })
}

fn fresh_message_id() -> String {
    use rand::RngCore;
    let mut nonce = [0u8; 32];
    rand::rng().fill_bytes(&mut nonce);
    crate::util::text_id::encode_base32_crockford(&nonce)
}

#[async_trait]
impl BindingTransport for HttpBindingTransport {
    async fn read_binding(&self, member_ix: usize, keys: &[[u8; 32]]) -> TransportRead {
        let unavailable = TransportRead {
            echoed_member_id: None,
            echoed_incarnation: None,
            records: None,
        };
        let Some(url) = self.url(member_ix, "/api/v2/storage/binding/read") else {
            return unavailable;
        };
        let body = encode_read_request(keys);
        match self
            .client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .body(body)
            .send()
            .await
        {
            Ok(resp) => {
                let ok = resp.status().is_success();
                let bytes = resp.bytes().await.map(|b| b.to_vec()).unwrap_or_default();
                parse_read_response(ok, &bytes, keys)
            }
            Err(_) => unavailable,
        }
    }

    async fn compare_exchange(
        &self,
        member_ix: usize,
        keys: &[[u8; 32]],
        expected_digest: [u8; 32],
        replacement_bytes: &[u8],
    ) -> TransportCas {
        let unavailable = TransportCas {
            echoed_member_id: None,
            echoed_incarnation: None,
            outcome: None,
        };
        let (Some(url), Some(member)) = (
            self.url(member_ix, "/api/v2/storage/binding/cas"),
            self.members.get(member_ix),
        ) else {
            return unavailable;
        };
        let Some(body) = encode_cas_request(keys, expected_digest, replacement_bytes) else {
            // Our own record failed to canonicalize — never send it.
            return unavailable;
        };
        let mut req = self.client.post(&url).body(body);
        for (k, v) in one_shot_claim_headers(member.auth.as_ref(), &fresh_message_id()) {
            req = req.header(k, v);
        }
        match req.send().await {
            Ok(resp) => {
                let ok = resp.status().is_success();
                let bytes = resp.bytes().await.map(|b| b.to_vec()).unwrap_or_default();
                parse_cas_response(ok, &bytes)
            }
            Err(_) => unavailable,
        }
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use dsm::dlv::quorum_bind::{BINDING_STATUS_ACCEPTED, BINDING_STATUS_PROMISED};
    use dsm::storage::binding_record::{BindingRecord, Round};

    fn key(n: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = n;
        k
    }

    fn record(status: u32, value: u8) -> BindingRecord {
        BindingRecord {
            schema: 1,
            round: Round {
                counter: 7,
                proposer_id: [3; 32],
            },
            tx_id: [9; 32],
            keyset_digest: [4; 32],
            value_digest: [value; 32],
            value_addr: [value; 32],
            status,
        }
    }

    #[test]
    fn a_cas_request_round_trips_through_the_node_message() {
        let rec = record(BINDING_STATUS_PROMISED, 10);
        let bytes = encode_cas_request(&[key(1), key(2)], [5; 32], &rec.encode()).unwrap();
        let msg = pb::CompareExchangeManyRequestV1::decode(bytes.as_slice()).unwrap();
        assert_eq!(msg.keys.len(), 2);
        assert_eq!(msg.expected_digest, vec![5u8; 32]);
        let r = msg.replacement.unwrap();
        assert_eq!(r.round_counter, 7);
        assert_eq!(r.status, BINDING_STATUS_PROMISED);
        assert_eq!(r.value_digest, vec![10u8; 32]);
        // Non-canonical replacement bytes are refused.
        assert!(encode_cas_request(&[key(1)], [5; 32], b"not a record").is_none());
    }

    #[test]
    fn a_read_answer_maps_records_back_to_their_keys_and_carries_attribution() {
        let held = record(BINDING_STATUS_ACCEPTED, 20);
        let msg = pb::ReadBindingResponseV1 {
            // Deliberately return the cells in REVERSE key order.
            cells: vec![
                pb::BindingCellV1 {
                    key: key(2).to_vec(),
                    record: None,
                },
                pb::BindingCellV1 {
                    key: key(1).to_vec(),
                    record: Some(
                        pb::GenericBindingRecordV1::decode(held.encode().as_slice()).unwrap(),
                    ),
                },
            ],
            set_digest: vec![0; 32],
            member_id: b"n1".to_vec(),
            register_incarnation: vec![0xAB; 32],
        };
        let read = parse_read_response(true, &msg.encode_to_vec(), &[key(1), key(2)]);
        assert_eq!(read.echoed_member_id.as_deref(), Some(b"n1".as_slice()));
        assert_eq!(read.echoed_incarnation, Some([0xAB; 32]));
        let recs = read.records.unwrap();
        // key(1) holds the record, key(2) is absent — order follows the request,
        // not the response.
        assert_eq!(recs[0].as_ref().unwrap().value_digest, [20u8; 32]);
        assert!(recs[1].is_none());
    }

    #[test]
    fn a_read_missing_a_requested_key_is_unavailable_not_a_partial_answer() {
        let msg = pb::ReadBindingResponseV1 {
            cells: vec![pb::BindingCellV1 {
                key: key(1).to_vec(),
                record: None,
            }],
            set_digest: vec![0; 32],
            member_id: b"n1".to_vec(),
            register_incarnation: vec![0xAB; 32],
        };
        // Requested {1,2}, member answered only about 1.
        let read = parse_read_response(true, &msg.encode_to_vec(), &[key(1), key(2)]);
        assert!(
            read.records.is_none(),
            "an incomplete set is not a countable read"
        );
    }

    #[test]
    fn cas_outcomes_map_and_unavailable_or_non_200_do_not_count() {
        use pb::compare_exchange_many_response_v1::Outcome;
        for (o, want) in [
            (Outcome::Applied, Some(CasOutcome::Applied)),
            (
                Outcome::ExpectationMismatch,
                Some(CasOutcome::ExpectationMismatch),
            ),
            (
                Outcome::InvalidStorageEncoding,
                Some(CasOutcome::InvalidStorageEncoding),
            ),
            (Outcome::Unavailable, None),
        ] {
            let msg = pb::CompareExchangeManyResponseV1 {
                outcome: o as i32,
                resulting_digest: vec![0; 32],
                member_id: b"n1".to_vec(),
                register_incarnation: vec![0xAB; 32],
            };
            let cas = parse_cas_response(true, &msg.encode_to_vec());
            assert_eq!(cas.outcome, want);
            if want.is_some() {
                assert_eq!(cas.echoed_member_id.as_deref(), Some(b"n1".as_slice()));
                assert_eq!(cas.echoed_incarnation, Some([0xAB; 32]));
            }
        }
        // A 503 is unavailable regardless of body.
        assert!(parse_cas_response(false, &[]).outcome.is_none());
    }
}
