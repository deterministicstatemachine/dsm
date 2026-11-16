// SPDX-License-Identifier: MIT OR Apache-2.0

//! A created token's ticker against the protocol assets' own (SA-104,
//! SA-145), on storage nodes.
//!
//! No token a device creates or adopts may carry a protocol asset's ticker.
//! A person reads a ticker; a wallet lists every token it holds by one.
//! These are the tickers a person reads as ERA that are not the three ASCII
//! letters, each asked of the production `token.check` and `token.create`
//! routes.

use dsm::types::proto as generated;
use generated::envelope::Payload;
use serial_test::serial;

use super::connect_e2e_tests::query;
use super::node_e2e_tests::{args, create_token, payload};
use crate::test_support::two_device::{Pair, TestDevice};

/// Tickers that read as ERA, and what makes each another string.
const READ_AS_ERA: [(&str, &str); 5] = [
    ("\u{0415}RA", "a Cyrillic capital IE for the E"),
    ("ER\u{0410}", "a Cyrillic capital A for the A"),
    ("\u{0395}RA", "a Greek capital epsilon for the E"),
    ("ERA\u{200B}", "a zero-width space after the A"),
    ("\u{FF25}\u{FF32}\u{FF21}", "three full-width letters"),
];

/// What `token.check` refuses of a token with this ticker, field by field.
async fn refused_fields(d: &TestDevice, ticker: &str) -> Vec<String> {
    let checked = query(
        d,
        "token.check",
        args(&generated::TokenCreateRequest {
            ticker: ticker.to_string(),
            alias: "Era".to_string(),
            decimals: 2,
            genesis_supply_entered: "1000000".to_string(),
            threshold: 1,
            ..Default::default()
        }),
    )
    .await;
    match payload(&checked) {
        Payload::TokenCheckResponse(answer) => answer
            .refusals
            .into_iter()
            .map(|refusal| format!("{}: {}", refusal.field, refusal.reason))
            .collect(),
        other => panic!("token.check answered {other:?}"),
    }
}

/// A device asks to create a token under each ticker that reads as ERA.
/// Every one must be refused: none may be created, registered and listed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn no_created_token_carries_a_ticker_that_reads_as_era() {
    let p = Pair::boot(100, 0).await;
    assert_eq!(
        refused_fields(&p.a, "ERA").await,
        vec!["ticker: ERA is a protocol asset's ticker".to_string()],
        "the three ASCII letters are refused"
    );

    let mut created = Vec::new();
    for (ticker, how) in READ_AS_ERA {
        let refused = refused_fields(&p.a, ticker).await;
        if !refused.is_empty() {
            continue;
        }
        let policy_commit = create_token(&p.a, ticker, 1_000_000).await;
        let listed =
            dsm::core::token::token_state_manager::resolve_ticker_for_policy_commit(&policy_commit);
        created.push(format!(
            "{:?} ({how}; code points {}), created and listed as {listed:?}",
            ticker,
            ticker
                .chars()
                .map(|c| format!("U+{:04X}", c as u32))
                .collect::<Vec<_>>()
                .join(" ")
        ));
    }
    assert!(
        created.is_empty(),
        "{} of {} tickers that read as ERA were created: {}",
        created.len(),
        READ_AS_ERA.len(),
        created.join("; ")
    );
}
