// SPDX-License-Identifier: MIT OR Apache-2.0

//! Another party's answer, read within a bound fixed before it arrives.
//!
//! A storage member, an application's relay endpoint and the receipt service
//! each answer from software this device did not compile, and a member may be
//! hostile (storage spec §4). Every answer body is read within a bound that
//! is enforced while the body streams: an answer announced or found to be
//! longer is refused at once, and the rest of it is never read or held.
//!
//! Two kinds of bound, kept apart:
//!
//! - **A protocol limit** ([`Bound::Limit`]): the largest answer of its kind
//!   the protocol allows, derived from that kind's own constants. No honest
//!   answer is longer, so a longer one is not an answer.
//! - **A local budget** ([`Bound::Budget`]): what this device spends on one
//!   answer of a kind the protocol does not bound. Passing it is a resource
//!   limit, never evidence about the answer: an honest answer that large is
//!   not read here, a liveness limit that lasts until the kind is paged.
//!
//! A refused answer is refused whole. Nothing is truncated, and nothing read
//! before the refusal is returned or taken for the answer.

use std::collections::BTreeMap;

use prost::Message;

/// The bound one answer is read within.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bound {
    /// The protocol's own limit for the kind, in bytes: no honest answer is
    /// longer.
    Limit(usize),
    /// This device's budget for a kind the protocol does not bound.
    Budget(Budget),
}

impl Bound {
    fn bytes(self) -> usize {
        match self {
            Bound::Limit(limit) => limit,
            Bound::Budget(budget) => budget.bytes,
        }
    }

    fn passed(self) -> Refused {
        match self {
            Bound::Limit(limit) => Refused::OverLimit { limit },
            Bound::Budget(budget) => Refused::OverByteBudget {
                budget: budget.bytes,
            },
        }
    }
}

/// What this device spends on one answer of a kind the protocol does not
/// bound: the bytes it reads, and what decoding them may allocate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    pub bytes: usize,
    pub allocation: usize,
}

/// Why an answer was not taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// Longer than the protocol allows any answer of its kind: not an honest
    /// answer.
    OverLimit { limit: usize },
    /// More elements than the protocol allows an answer of its kind: not an
    /// honest answer.
    TooManyElements { limit: usize },
    /// Longer than this device's byte budget for its kind. A resource limit,
    /// not evidence about the answer.
    OverByteBudget { budget: usize },
    /// Decoding would allocate more than this device's allocation budget for
    /// its kind. A resource limit, not evidence about the answer.
    OverAllocationBudget { needed: usize, budget: usize },
    /// Not a protobuf message.
    Malformed(String),
    /// The transport failed while the answer was read.
    Transport(String),
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::OverLimit { limit } => write!(
                f,
                "longer than the {limit} bytes the protocol allows an answer of its kind"
            ),
            Refused::TooManyElements { limit } => write!(
                f,
                "more than the {limit} elements the protocol allows an answer of its kind"
            ),
            Refused::OverByteBudget { budget } => write!(
                f,
                "longer than this device's {budget}-byte budget for an answer of its kind \
                 (a resource limit, not a verdict on the answer)"
            ),
            Refused::OverAllocationBudget { needed, budget } => write!(
                f,
                "decoding would allocate {needed} bytes, over this device's {budget}-byte \
                 budget for an answer of its kind (a resource limit, not a verdict on the \
                 answer)"
            ),
            Refused::Malformed(why) => write!(f, "not a protobuf message: {why}"),
            Refused::Transport(why) => write!(f, "the transport failed: {why}"),
        }
    }
}

impl std::error::Error for Refused {}

/// The body of `response`, read within `bound`: refused when its announced
/// length passes the bound, before any of it is read, and otherwise as soon
/// as what arrived passes it.
pub async fn read(mut response: reqwest::Response, bound: Bound) -> Result<Vec<u8>, Refused> {
    let most = bound.bytes();
    if response
        .content_length()
        .is_some_and(|announced| announced > most as u64)
    {
        return Err(bound.passed());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| Refused::Transport(e.to_string()))?
    {
        if chunk.len() > most - body.len() {
            return Err(bound.passed());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// How many length-delimited elements `body` holds in each top-level field,
/// read off the wire without decoding it.
pub fn element_counts(body: &[u8]) -> Result<BTreeMap<u32, usize>, Refused> {
    let malformed = |e: prost::DecodeError| Refused::Malformed(e.to_string());
    let mut counts = BTreeMap::new();
    let mut rest = body;
    while !rest.is_empty() {
        let key = prost::encoding::decode_varint(&mut rest).map_err(malformed)?;
        let field = u32::try_from(key >> 3)
            .map_err(|e| Refused::Malformed(format!("field number: {e}")))?;
        let skip = match key & 0b111 {
            0 => {
                prost::encoding::decode_varint(&mut rest).map_err(malformed)?;
                0
            }
            1 => 8,
            2 => {
                let len = prost::encoding::decode_varint(&mut rest).map_err(malformed)?;
                *counts.entry(field).or_insert(0usize) += 1;
                usize::try_from(len).map_err(|e| Refused::Malformed(format!("length: {e}")))?
            }
            5 => 4,
            wire => {
                return Err(Refused::Malformed(format!(
                    "field {field} has wire type {wire}"
                )))
            }
        };
        if skip > rest.len() {
            return Err(Refused::Malformed(format!(
                "field {field} runs past the end of the answer"
            )));
        }
        rest = &rest[skip..];
    }
    Ok(counts)
}

/// Refuse `body` when its field `field` holds more than `limit` elements, the
/// most the protocol allows an answer of its kind: checked before decoding,
/// so the structures of a longer list are never allocated.
pub fn at_most(body: &[u8], field: u32, limit: usize) -> Result<(), Refused> {
    match element_counts(body)?.get(&field) {
        Some(count) if *count > limit => Err(Refused::TooManyElements { limit }),
        Some(..) | None => Ok(()),
    }
}

/// Decode `M`, an answer of a kind the protocol does not bound, once what
/// decoding allocates fits `budget`. `elements` names each repeated field of
/// `M` and the size of the structure decoding gives one of its elements.
///
/// What decoding allocates is at most the bytes the elements carry, which are
/// no more than `body`, and each element's structure, counted twice for the
/// vector that holds them as it grows. An answer packing empty elements costs
/// the decoder many times its bytes, and is refused before it is decoded.
pub fn decode_within<M: Message + Default>(
    body: &[u8],
    elements: &[(u32, usize)],
    budget: Budget,
) -> Result<M, Refused> {
    let counts = element_counts(body)?;
    let mut needed = body.len();
    for (field, size) in elements {
        if let Some(count) = counts.get(field) {
            needed = needed.saturating_add(count.saturating_mul(size.saturating_mul(2)));
        }
    }
    if needed > budget.allocation {
        return Err(Refused::OverAllocationBudget {
            needed,
            budget: budget.allocation,
        });
    }
    M::decode(body).map_err(|e| Refused::Malformed(e.to_string()))
}

/// The origin of a plain-HTTP party that answers its first request, at any
/// path, with `status` and `body`: the bound is the reader's, whoever
/// answers.
#[cfg(test)]
pub(crate) async fn answering_once(status: u16, body: axum::body::Body) -> String {
    use std::sync::{Arc, Mutex};
    let held = Arc::new(Mutex::new(Some(body)));
    let app = axum::Router::new().fallback(move || {
        let held = held.clone();
        async move {
            let body = match held.lock() {
                Ok(mut held) => held.take().expect("one request"),
                Err(poisoned) => poisoned.into_inner().take().expect("one request"),
            };
            axum::response::Response::builder()
                .status(status)
                .body(body)
                .expect("an answer")
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a port");
    let port = listener.local_addr().expect("its address").port();
    tokio::spawn(async move { axum::serve(listener, app).await });
    format!("http://127.0.0.1:{port}")
}

/// Chunks of `0x6f` without end, with no announced length.
#[cfg(test)]
pub(crate) fn endless() -> axum::body::Body {
    axum::body::Body::from_stream(futures::stream::repeat_with(|| {
        Ok::<_, std::io::Error>(bytes::Bytes::from(vec![0x6f; 16 * 1024]))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsm::types::proto;

    /// Longer than a refused read takes: a read that runs past it was waiting
    /// on the answer.
    const PATIENCE: std::time::Duration = std::time::Duration::from_secs(20);

    /// `body`, as answered to a read.
    async fn answered(body: axum::body::Body) -> reqwest::Response {
        crate::sdk::tls_transport_sdk::ensure_rustls_crypto_provider();
        reqwest::Client::new()
            .get(answering_once(200, body).await)
            .send()
            .await
            .expect("an answer")
    }

    const BUDGET: Budget = Budget {
        bytes: 1000,
        allocation: 4000,
    };

    /// An answer of exactly its bound is the answer, byte for byte.
    #[tokio::test]
    async fn an_answer_at_its_bound_is_read_whole() {
        let body = vec![0x61; 1000];
        let read = read(answered(body.clone().into()).await, Bound::Limit(1000)).await;
        assert_eq!(read, Ok(body.clone()));
        let read = read_budget(answered(body.clone().into()).await).await;
        assert_eq!(read, Ok(body));
    }

    async fn read_budget(response: reqwest::Response) -> Result<Vec<u8>, Refused> {
        read(response, Bound::Budget(BUDGET)).await
    }

    /// An answer announced longer than its bound is refused, and the refusal
    /// says which bound: past a protocol limit it is not an answer of its
    /// kind; past a budget it is a resource limit.
    #[tokio::test]
    async fn an_answer_announced_past_its_bound_is_refused() {
        let body = vec![0x61; 1001];
        assert_eq!(
            read(answered(body.clone().into()).await, Bound::Limit(1000)).await,
            Err(Refused::OverLimit { limit: 1000 })
        );
        assert_eq!(
            read_budget(answered(body.into()).await).await,
            Err(Refused::OverByteBudget { budget: 1000 })
        );
    }

    /// The announced length is refused before any of the body is read: an
    /// answer that announces more than its bound, sends a few bytes and then
    /// holds the connection is refused at once, not waited on.
    #[tokio::test]
    async fn an_announced_length_past_the_bound_is_refused_before_the_body() {
        let held = axum::body::Body::from_stream(futures::StreamExt::chain(
            futures::stream::once(async {
                Ok::<_, std::io::Error>(bytes::Bytes::from(vec![0x61; 10]))
            }),
            futures::stream::pending(),
        ));
        crate::sdk::tls_transport_sdk::ensure_rustls_crypto_provider();
        let held = answering_announced(1_000_000, held).await;
        let refused = tokio::time::timeout(PATIENCE, read(held, Bound::Limit(1000)))
            .await
            .expect("the announced length is refused without waiting on the body");
        assert_eq!(refused, Err(Refused::OverLimit { limit: 1000 }));
    }

    /// `body`, answered to a read with `announced` as its length.
    async fn answering_announced(announced: u64, body: axum::body::Body) -> reqwest::Response {
        use std::sync::{Arc, Mutex};
        let held = Arc::new(Mutex::new(Some(body)));
        let app = axum::Router::new().fallback(move || {
            let held = held.clone();
            async move {
                let body = match held.lock() {
                    Ok(mut held) => held.take().expect("one request"),
                    Err(poisoned) => poisoned.into_inner().take().expect("one request"),
                };
                axum::response::Response::builder()
                    .header(axum::http::header::CONTENT_LENGTH, announced)
                    .body(body)
                    .expect("an answer")
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a port");
        let port = listener.local_addr().expect("its address").port();
        tokio::spawn(async move { axum::serve(listener, app).await });
        reqwest::Client::new()
            .get(format!("http://127.0.0.1:{port}/"))
            .send()
            .await
            .expect("an answer")
    }

    /// An answer that announces no length and never ends is refused once it
    /// passes its bound, not read until the transport gives up.
    #[tokio::test]
    async fn a_streamed_answer_is_refused_once_it_passes_its_bound() {
        let refused = tokio::time::timeout(
            PATIENCE,
            read(answered(endless()).await, Bound::Limit(100_000)),
        )
        .await
        .expect("the read ends at the bound");
        assert_eq!(refused, Err(Refused::OverLimit { limit: 100_000 }));
        let refused = tokio::time::timeout(PATIENCE, read_budget(answered(endless()).await))
            .await
            .expect("the read ends at the budget");
        assert_eq!(refused, Err(Refused::OverByteBudget { budget: 1000 }));
    }

    /// The counts are read off the wire field by field, so each caller's
    /// field numbers are checked here against the messages they name.
    #[test]
    fn element_counts_read_each_repeated_field() {
        let cell = proto::CellValuesV1 {
            values: vec![vec![0x76]; 3],
            records: vec![proto::ArrivalRecordV1::default(); 2],
        };
        let counts = element_counts(&cell.encode_to_vec()).expect("counts");
        assert_eq!(counts.into_iter().collect::<Vec<_>>(), vec![(1, 3), (2, 2)]);

        let page = proto::SequencedBatchEnvelope {
            envelopes: vec![proto::SequencedEnvelope::default(); 4],
            next_seq: 9,
        };
        let counts = element_counts(&page.encode_to_vec()).expect("counts");
        assert_eq!(counts.into_iter().collect::<Vec<_>>(), vec![(1, 4)]);

        let mirror = proto::ByteCommitsV4 {
            commits: vec![proto::ByteCommitV4::default(); 5],
        };
        let counts = element_counts(&mirror.encode_to_vec()).expect("counts");
        assert_eq!(counts.into_iter().collect::<Vec<_>>(), vec![(1, 5)]);

        let batch = proto::AppRequestBatchV1 {
            requests: vec![proto::AppRequestV1::default(); 6],
        };
        let counts = element_counts(&batch.encode_to_vec()).expect("counts");
        assert_eq!(counts.into_iter().collect::<Vec<_>>(), vec![(1, 6)]);
    }

    /// Bytes that are not a protobuf message, or end inside a field, are
    /// refused rather than counted.
    #[test]
    fn a_malformed_answer_is_refused() {
        let mut cut = proto::CellValuesV1 {
            values: vec![vec![0x76; 10]],
            records: Vec::new(),
        }
        .encode_to_vec();
        cut.truncate(5);
        assert!(matches!(element_counts(&cut), Err(Refused::Malformed(..))));
        assert!(matches!(
            element_counts(&[0x0b]),
            Err(Refused::Malformed(..))
        ));
    }

    /// A list longer than its kind allows is refused before it is decoded.
    #[test]
    fn more_elements_than_the_kind_allows_are_refused() {
        let page = proto::SequencedBatchEnvelope {
            envelopes: vec![proto::SequencedEnvelope::default(); 5],
            next_seq: 9,
        }
        .encode_to_vec();
        assert_eq!(at_most(&page, 1, 5), Ok(()));
        assert_eq!(
            at_most(&page, 1, 4),
            Err(Refused::TooManyElements { limit: 4 })
        );
    }

    /// An answer whose elements are empty costs the decoder a structure for
    /// each and no bytes: within its byte budget, it is refused for what
    /// decoding it would allocate. The same number of bytes in elements that
    /// carry them decodes.
    #[test]
    fn an_answer_of_empty_elements_is_refused_before_it_is_decoded() {
        let elements = [(1, std::mem::size_of::<Vec<u8>>())];
        let empties = proto::CellValuesV1 {
            values: vec![Vec::new(); 400],
            records: Vec::new(),
        }
        .encode_to_vec();
        assert!(empties.len() <= BUDGET.bytes);
        assert!(matches!(
            decode_within::<proto::CellValuesV1>(&empties, &elements, BUDGET),
            Err(Refused::OverAllocationBudget { budget: 4000, .. })
        ));
        let carried = proto::CellValuesV1 {
            values: vec![vec![0x76; 98]; 8],
            records: Vec::new(),
        }
        .encode_to_vec();
        assert!(carried.len() <= BUDGET.bytes);
        let decoded = decode_within::<proto::CellValuesV1>(&carried, &elements, BUDGET)
            .expect("an answer that carries its bytes decodes");
        assert_eq!(decoded.values.len(), 8);
    }
}
