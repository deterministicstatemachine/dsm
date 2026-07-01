// SPDX-License-Identifier: MIT OR Apache-2.0
//! Drives the SYNC libtropic verifier session over the async relay bridge to read the sender chip's
//! live counter. This is the only place the sync libtropic stack ([`read_live_counter`]) is joined
//! to a caller-supplied async transport round-trip — hence it lives in the excluded hardware crate
//! (it depends on `tropic01`), not in the CI-built SDK.

use dsm_anchor_verifier::{relay_bridge, RelayError};

use crate::session::{read_live_counter, VerifierError, VerifierSessionCredential};

/// Read the sender chip's live counter `H` over a relay: run the SYNC libtropic verifier session on
/// a blocking task while driving each SPI transaction through `round_trip` (the async transport
/// send/recv). Returns `H_attested`, or a fail-closed error.
///
/// `round_trip(mosi) -> miso` performs one relay round-trip (e.g. send a `TropicSpiRelayPacket` to
/// Phone A and await the reply). Any error fails the read closed.
pub async fn read_counter_over_relay<F, Fut>(
    cred: VerifierSessionCredential,
    ephemeral_secret: [u8; 32],
    mut round_trip: F,
) -> Result<u32, VerifierError>
where
    F: FnMut(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>, RelayError>>,
{
    let (channel, mut pump) = relay_bridge();
    let read =
        tokio::task::spawn_blocking(move || read_live_counter(channel, &cred, ephemeral_secret));

    // Drive relay exchanges until the blocking read finishes (dropping the channel ends the pump).
    while let Some(ex) = pump.next().await {
        let mosi = ex.mosi.clone();
        match round_trip(mosi).await {
            Ok(miso) => ex.respond(miso),
            Err(e) => ex.fail(e.to_string()),
        }
    }

    read.await
        .map_err(|e| VerifierError::CounterRead(format!("relay read task failed to join: {e}")))?
}
