// SPDX-License-Identifier: MIT OR Apache-2.0
//! H3 device-flow installs: wire the on-device Path-B transport into the running SDK so an
//! offline-bearer RECEIVER can read the sender's TROPIC01 counter over the live BLE relay, and a
//! SENDER can service that read from its own Pico.
//!
//! Two installs, both onto the process-global bilateral stack:
//!   1. SENDER side — `set_local_pico(android_usb_pico_transport())` on the bilateral adapter's
//!      `TropicRelayRouter`, so an inbound `from_receiver` relay frame is forwarded to A's Pico and
//!      the MISO replied. (Being READABLE is not acceptance.)
//!   2. RECEIVER side — `install_receiver_anchor(round_trip)`: the reader + verifier-pairing deriver
//!      (fixed DSM verifier key — no seed). The `round_trip` closure resolves the peer's BLE address,
//!      then drives ONE relay round-trip through the adapter's router (`round_trip` registers the
//!      pending reply + sends via `queue_relay_frame`). This is the ACCEPT-ENABLING install: with the
//!      reader present AND a COMPLETE pin (verifier slot + pinned stpub, from the sender's
//!      SeSlotWriter disclosure) AND a matching counter, the canonical predicate accepts. It stays
//!      fail-closed while any is absent — in particular the SeSlotWriter is a separate install, so no
//!      pin completes yet.
//!
//! NOT auto-called from `initDsmSdk`: the reader install is gated behind an explicit device-layer
//! trigger (bench for the 2-phone test; the production flip is the owner's call).

// The entire module body is Android + accept-enabling-opt-in only; on the host cfg it compiles to
// nothing, so gate the imports the same way to avoid unused-import warnings.
#[cfg(all(target_os = "android", feature = "on_device_installs"))]
use std::sync::Arc;

#[cfg(all(target_os = "android", feature = "on_device_installs"))]
use dsm_anchor_hw_verifier::RelayRoundTrip;
#[cfg(all(target_os = "android", feature = "on_device_installs"))]
use dsm_anchor_verifier::RelayError;

/// Build the receiver `round_trip`: for each raw-SPI transaction, resolve the sender's BLE address
/// and drive it through the global bilateral adapter's `TropicRelayRouter` over `queue_relay_frame`.
/// Any missing piece (no manager, unknown address, send/timeout) is a fail-closed `RelayError`.
#[cfg(all(target_os = "android", feature = "on_device_installs"))]
fn adapter_round_trip() -> RelayRoundTrip {
    use dsm_sdk::bluetooth::bilateral_transport_adapter::BilateralTransportAdapter;
    use dsm_sdk::bluetooth::get_global_bluetooth_manager;

    Arc::new(move |peer_device_id, commitment, mosi| {
        Box::pin(async move {
            let address =
                dsm_sdk::jni::state::resolve_ble_address(&peer_device_id).ok_or_else(|| {
                    RelayError::Transport("no BLE address for relay peer (fail-closed)".into())
                })?;
            let manager = get_global_bluetooth_manager().ok_or_else(|| {
                RelayError::Transport("BluetoothManager not registered (fail-closed)".into())
            })?;
            let router = Arc::clone(manager.transport_adapter().tropic_relay());
            router
                .round_trip(commitment, mosi, move |frame: Vec<u8>| async move {
                    BilateralTransportAdapter::queue_relay_frame(&address, &frame).await
                })
                .await
        })
    })
}

/// Install BOTH Path-B transports onto the global bilateral stack (see module docs). Idempotent-ish:
/// installing again just replaces the seams. Returns `false` fail-closed if the BluetoothManager is
/// not yet registered — nothing is installed in that case.
///
/// Android + explicit `on_device_installs` opt-in only. The reader is accept-enabling, so it never
/// compiles into a default build; the device layer (bench / the owner's flip) enables the feature
/// and calls this.
#[cfg(all(target_os = "android", feature = "on_device_installs"))]
pub fn install_path_b_transports() -> bool {
    use dsm_sdk::bluetooth::get_global_bluetooth_manager;

    // Sender side: service relay reads from A's local Pico.
    let Some(manager) = get_global_bluetooth_manager() else {
        log::warn!("[anchor-install] no BluetoothManager — Path-B not installed");
        return false;
    };
    manager
        .transport_adapter()
        .tropic_relay()
        .set_local_pico(Arc::new(crate::usb_pico::android_usb_pico_transport()));
    log::info!("[anchor-install] local Pico transport set on the bilateral relay router");

    // Receiver side: the ACCEPT-ENABLING reader + verifier-pairing deriver (fixed key, no seed).
    crate::install_receiver_anchor(adapter_round_trip());
    log::info!("[anchor-install] RelayCounterReader + verifier deriver installed (Path-B active)");

    // Sender side: the READ-ONLY SE slot writer — discloses (slot, stpub) iff the verifier slot is
    // already provisioned + caged. It NEVER burns; the burn is the separate explicit setup trigger
    // (`provisionVerifierSlotCommit`). Until the slot is provisioned, the disclosure stays empty and
    // the receiver's pin is incomplete -> fail-closed.
    crate::install_sender_slot_writer(std::sync::Arc::new(crate::se_slot::SeVerifierSlotWriter));
    log::info!(
        "[anchor-install] read-only SeSlotWriter installed (disclosure fail-closed until setup)"
    );
    true
}

/// JNI trigger for the receiver-side + sender-side Path-B install. Returns JNI_TRUE iff both
/// transports were installed. Present only in `on_device_installs` builds (accept-enabling).
#[cfg(all(target_os = "android", feature = "on_device_installs"))]
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_Unified_installPathBTransports(
    _env: jni::JNIEnv,
    _class: jni::objects::JClass,
) -> jni::sys::jboolean {
    u8::from(install_path_b_transports())
}
