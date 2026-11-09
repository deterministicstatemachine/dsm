// SPDX-License-Identifier: MIT OR Apache-2.0
//! The ONE v2 device-flow install: the phone's anchor appliance factory, for both sides of an offline
//! payment. Wires [`crate::usb_appliance::UsbAnchorAppliance`] (the phone's USB link to its own
//! RP2350/TROPIC01) into `dsm_sdk::bridge::install_anchor_appliance_factory`, so the payer's
//! `CoreSDK::stage_offline_bearer_transition` / `release_offline_bearer` and the receiver's
//! `draw_receive_challenge` / `receive_offline_bearer` drive REAL silicon: `σ^chip` from the resident
//! non-exportable Ed25519 key, `σ^host` from the RP2350 partition, the receiver's challenge from the
//! board's TRNG and the chip's, and a real monotonic-counter step at each COMMIT.
//!
//! An offline payment needs a board on both sides (owner, 2026-11-07: "you have to have the board,
//! man, for it to work offline. You can't receive either."): the payer's releases the payment, and
//! the receiver's draws the challenge, checks the payer's release itself and commits the receive,
//! its certificate the acknowledgement. The same factory serves both, so this is the ENTIRE
//! device-layer install story.
//!
//! Registered once at app start by the Kotlin `DsmInitProvider`, in every .so that carries it
//! (feature `on_device_installs`; the production flip of that feature is the owner's call).
//! Registering opens nothing. The factory is called once per session and fails CLOSED if the
//! Pico/chip is absent — an uninstalled factory or an unreachable chip means every offline-bearer
//! send and every offline receive errors ("offline = chips"); nothing takes the chip's place.

#[cfg(all(target_os = "android", feature = "on_device_installs"))]
pub fn install_anchor_transport() {
    use std::sync::Arc;
    dsm_sdk::bridge::install_anchor_appliance_factory(Arc::new(|| {
        let app = crate::usb_appliance::UsbAnchorAppliance::connect(Arc::new(
            crate::usb_pico::jni_usb_transceive,
        ))?;
        Ok(Box::new(app) as Box<dyn dsm_sdk::anchor::AnchorAppliance + Send>)
    }));
    log::info!(
        "[anchor-install] USB anchor appliance factory installed (offline release and receive = physical chip)"
    );
}

/// JNI trigger: install the sender anchor transport. Returns `true` on success. Absent from the
/// default .so (gated `on_device_installs`); Kotlin catches `UnsatisfiedLinkError` and treats the
/// capability as unavailable (fail-closed).
#[cfg(all(target_os = "android", feature = "on_device_installs"))]
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_Unified_installAnchorTransport(
    _env: jni::JNIEnv,
    _class: jni::objects::JClass,
) -> jni::sys::jboolean {
    install_anchor_transport();
    jni::sys::JNI_TRUE
}
