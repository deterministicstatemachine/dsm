<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# dsm-android-anchor — on-device glue for the v2 anchor (Software-Authority / Hardware-Identity)

The SENDER phone's USB link to its own RP2350/TROPIC01 appliance, plus gated device-setup ops.
v2 needs **nothing receiver-side** (no relay, no counter reader, no verifier slot) — the one
device install is the sender's appliance factory.

Workspace-EXCLUDED (pulls `tropic01`); built via cargo-ndk for Android. Its host tests (the board
setup against a model of the RP2350 bootloader, the USB appliance client) run from this directory
with `cargo test --release --locked --lib`, as CI's `phone-anchor` job runs them.

## Build flavors

Default (read-only diagnostics only — cannot produce releases or touch hardware state):

```sh
export ANDROID_NDK_HOME=~/Library/Android/sdk/ndk/27.0.12077973
cargo ndk -t arm64-v8a build --release
```

Bench (adds `installAnchorTransport`, the sender appliance install):

```sh
cargo ndk -t arm64-v8a build --release --features on_device_installs
```

## Packaging

The app's Gradle build packages a prebuilt `libdsm_sdk.so` from `jniLibs/`. This crate's cdylib
links `dsm_sdk` statically, so its `.so` carries ALL of `dsm_sdk`'s JNI exports plus the glue's —
rename it into place:

```sh
cp target/aarch64-linux-android/release/libdsm_android_anchor.so \
   ../../dsm_client/android/app/src/main/jniLibs/arm64-v8a/libdsm_sdk.so
```

## Device setup order

1. A new board is set up from this phone, plugged in with BOOTSEL held (Appliance → Production
   setup): a test part's chip prepared, its try-run on the trial image, then the one-time burns, each
   step read back (`crates/dsm-anchor-secure-monitor/scripts/anchor-secure-boot/RUNBOOK.md`, "From the
   phone").
2. Attach the appliance over USB-OTG. Android asks to allow it. Attaching changes nothing: a status
   read of a new anchor reports it as awaiting its install.
3. In the wallet's Appliance screen, try the install, read what it makes permanent, and install it.
   The anchor goes through the try-run again itself and refuses, with nothing written, unless it passes.

Every path fails closed: absent factory ⇒ offline-bearer sends error ("offline = chips"); any
USB/chip failure inside an op ⇒ `DsmError` ⇒ no release.
