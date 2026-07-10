// SPDX-License-Identifier: MIT OR Apache-2.0
//! The ONE v2 device-flow install: the SENDER's anchor appliance factory. Wires
//! [`crate::usb_appliance::UsbAnchorAppliance`] (the phone's USB link to its own RP2350/TROPIC01)
//! into `dsm_sdk::bridge::install_anchor_appliance_factory`, so
//! `CoreSDK::stage_offline_bearer_transition` / `release_offline_bearer` drive REAL silicon:
//! `σ^chip` from the resident non-exportable Ed25519 key, `σ^host` from the RP2350 partition, and
//! a real monotonic-counter step at COMMIT.
//!
//! v2 needs NOTHING receiver-side (no relay, no counter reader, no verifier slot) — the receiver
//! accepts from the release alone. So this is the ENTIRE device-layer install story.
//!
//! NOT auto-called from `initDsmSdk`: the install is gated behind an explicit device-layer trigger
//! (feature `on_device_installs`, bench builds; the production flip is the owner's call). The
//! factory is called once per send-session and fails CLOSED if the Pico/chip is absent — an
//! uninstalled factory or an unreachable chip means every offline-bearer send errors
//! ("offline = chips"); nothing falls back to a mock.

#[cfg(all(target_os = "android", feature = "on_device_installs"))]
pub fn install_anchor_transport() {
    use std::sync::Arc;
    dsm_sdk::bridge::install_anchor_appliance_factory(Arc::new(|| {
        let app = crate::usb_appliance::UsbAnchorAppliance::connect(Arc::new(
            crate::usb_pico::jni_usb_transceive,
        ))?;
        Ok(Box::new(app) as Box<dyn dsm_sdk::anchor::AnchorAppliance + Send>)
    }));
    log::info!("[anchor-install] USB anchor appliance factory installed (sender release = physical chip)");
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
