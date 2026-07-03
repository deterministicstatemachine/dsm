// SPDX-License-Identifier: MIT OR Apache-2.0
//! H3 on-device composition self-test: ONE real attested counter read from a TROPIC01 through the
//! phone, using the production stack end to end — the REAL [`RelayCounterReader`] (full libtropic
//! session: cert-store stpub check -> authenticated L3 handshake on the verifier slot ->
//! `mcounter_get`), driven through the REAL [`TropicRelayRouter`] in the H0 loopback topology, over
//! the REAL Phone->Pico USB transport proven in H2. The ONLY substitutions vs production are the
//! loopback `round_trip` (in-process instead of BLE — the H4 seam) and the demo pin below.
//!
//! Bench-only wiring: the reader authenticates with the FIXED DSM verifier key, so the bench chip's
//! verifier slot must hold `dsm_verifier_pairing_pubkey()` (a fresh chip/slot provisioned with the
//! fixed key — see `usb_provision_verifier_slot`). `KNOWN_BENCH_STPUB` is that chip's pinned Noise
//! static key (anti-substitution). A full production pin comes from the first-transfer enroll/
//! disclosure flow instead. Expected result on a provisioned bench chip: `H = 1000`.

use std::sync::Arc;

use dsm_anchor_hw_verifier::{RelayCounterReader, RelayRoundTrip};
use dsm_anchor_verifier::RelayError;
use dsm_sdk::bluetooth::tropic_relay::{
    AnchorCounterReader, LocalPicoTransport, TropicRelayRouter,
};

/// A dummy peer device id — for the loopback it only labels the relay round-trip (the verifier
/// pairing key is the fixed DSM constant, independent of the peer).
const A_DEMO_PEER: [u8; 32] = [0xA0; 32];

/// The bench chip's pinned Noise static key (captured at provisioning; asserted by
/// `usb_verify_verifier_slot`). The reader refuses to trust a counter from any other chip.
const KNOWN_BENCH_STPUB: [u8; 32] = [
    0xd1, 0x87, 0xbc, 0xf1, 0x08, 0x9e, 0x9d, 0xaa, 0xb6, 0x4e, 0x5c, 0x0b, 0x96, 0xfd, 0x3a, 0x26,
    0x91, 0xe0, 0xd3, 0x70, 0x91, 0x0a, 0x07, 0xdb, 0x82, 0x1a, 0x32, 0x25, 0x83, 0x0f, 0xbe, 0x7d,
];

/// The dev chip's read-only verifier slot INDEX. On this bench chip slot 1 is spent on the old
/// per-relationship demo key, so the fixed DSM verifier role is provisioned at slot 2. Must match the
/// index the `usb_verifier_slot` bench CLI actually burned (`commit --slot 2`).
const VERIFIER_SLOT: u8 = 2;

/// Synthetic-but-complete demo pin: exactly the fields `read_counter` gates on (verifier slot,
/// pinned chip static key, uncompromised); the acceptance-predicate fields are placeholders.
fn demo_pin() -> dsm::crypto::anchor_enrollment::FusedAnchorPin {
    dsm::crypto::anchor_enrollment::FusedAnchorPin {
        bundle: [0u8; 32],
        anchor_id: [0u8; 32],
        enrolled_counter: 1000,
        partition_pk: Vec::new(),
        uncompromised: true,
        verifier_slot: Some(VERIFIER_SLOT),
        chip_static_pubkey: Some(KNOWN_BENCH_STPUB),
    }
}

/// Loopback `round_trip`: the H0 topology with the real transport — the SAME router plays receiver
/// (round_trip) and sender (handle_inbound -> local Pico), no BLE in between. H4 replaces this with
/// the real phone-to-phone send (`queue_relay_frame`).
fn loopback_round_trip(router: Arc<TropicRelayRouter>) -> RelayRoundTrip {
    Arc::new(move |_peer, commitment, mosi| {
        let router = Arc::clone(&router);
        Box::pin(async move {
            let send_router = Arc::clone(&router);
            router
                .round_trip(commitment, mosi, move |frame: Vec<u8>| async move {
                    // "Phone A" side: forward to the local Pico, then feed the reply back in.
                    if let Some(reply) = send_router.handle_inbound(&frame).await? {
                        send_router.handle_inbound(&reply).await?;
                    }
                    Ok(())
                })
                .await
                .map_err(|e| RelayError::Transport(format!("loopback relay: {e}")))
        })
    })
}

/// Drive one attested counter read through the full production reader stack over `pico`.
/// Returns the live counter `H` (expect 1000 on the bench chip) or `None` fail-closed.
pub async fn demo_counter_read_via_local_pico(pico: Arc<dyn LocalPicoTransport>) -> Option<u32> {
    let router = Arc::new(TropicRelayRouter::new());
    router.set_local_pico(pico);
    let reader = RelayCounterReader::new(loopback_round_trip(router));
    // Any 32-byte correlation id works for the single in-process exchange.
    let commitment = [0x5Eu8; 32];
    reader
        .read_counter(A_DEMO_PEER, commitment, demo_pin())
        .await
}

/// JNI trigger for the bench: called from the debug `PicoSelfTestActivity` AFTER the H2 opaque
/// round-trip passes. Builds the real USB transport + a multi-thread runtime (the relay bridge uses
/// `spawn_blocking`), runs one attested read, and returns `H` (or -1 fail-closed / -2 no runtime).
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_Unified_anchorCounterSelfTest(
    _env: jni::JNIEnv,
    _class: jni::objects::JClass,
) -> jni::sys::jlong {
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            log::error!("[anchor-selftest] tokio runtime: {e}");
            return -2;
        }
    };
    let pico: Arc<dyn LocalPicoTransport> = Arc::new(crate::usb_pico::android_usb_pico_transport());
    match rt.block_on(demo_counter_read_via_local_pico(pico)) {
        Some(h) => {
            log::info!("[anchor-selftest] ATTESTED COUNTER READ OK: H = {h}");
            i64::from(h)
        }
        None => {
            log::error!("[anchor-selftest] counter read failed (fail-closed)");
            -1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsm_sdk::bluetooth::tropic_relay::PicoFuture;
    use dsm_sdk::types::error::DsmError;

    /// A Pico stand-in that answers garbage: the full reader stack must fail CLOSED (None), never
    /// panic or hang, when the chip end is nonsense. (The positive path needs real silicon — it is
    /// the bench run this module exists for.)
    struct GarbagePico;
    impl LocalPicoTransport for GarbagePico {
        fn spi_passthrough(&self, spi: Vec<u8>) -> PicoFuture<Result<Vec<u8>, DsmError>> {
            Box::pin(async move { Ok(vec![0u8; spi.len()]) })
        }
    }

    /// A Pico stand-in whose transport errors outright.
    struct DeadPico;
    impl LocalPicoTransport for DeadPico {
        fn spi_passthrough(&self, _spi: Vec<u8>) -> PicoFuture<Result<Vec<u8>, DsmError>> {
            Box::pin(async { Err(DsmError::invalid_operation("no chip")) })
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn garbage_chip_fails_closed() {
        assert_eq!(
            demo_counter_read_via_local_pico(Arc::new(GarbagePico)).await,
            None
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dead_transport_fails_closed() {
        assert_eq!(
            demo_counter_read_via_local_pico(Arc::new(DeadPico)).await,
            None
        );
    }
}
