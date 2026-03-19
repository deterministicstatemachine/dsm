# Chapter 18 -- In-App Developer Walkthroughs

This chapter covers the developer-only app flows that are easy to miss if you only read the
architecture docs.

These are the current in-app paths for:

- unlocking developer options
- checking C-DBRW / silicon-binding status
- creating and publishing token policies and tokens
- using the DLV debug tools
- enabling offline BLE mode for bilateral testing

## Hidden Developer Options

The app hides its developer tools behind the version row in Settings.

### Unlock path

1. Open the app.
2. Go to `Settings`.
3. Tap the `VERSION` row 7 times.
4. Wait for `Developer options enabled`.
5. The `DEVELOPER OPTIONS` section appears.

This behavior is implemented in the settings screen itself. The current UI path is:

`Settings -> VERSION (tap 7x) -> Developer Options`

The developer menu currently exposes:

- `DLV TOOLS`
- `C-DBRW TOOLS`
- `POLICY TOOLS`

## C-DBRW / Silicon Monitoring

The silicon-binding diagnostics live under:

`Settings -> VERSION (tap 7x) -> C-DBRW TOOLS`

This screen is the practical developer entry point for monitoring device binding and runtime drift.
It is the right place to inspect what you described as the silicon-key or silicon-fingerprint
monitoring path.

### What the screen shows

- whether the device is enrolled
- whether the app is in observe-only or active mode
- whether the binding key is present
- whether the verifier keypair is present
- enrollment revision and runtime metrics
- trust score, match score, W1 distance, and threshold
- a diagnostics log export path

### Useful developer actions

- `Refresh` reloads the live C-DBRW status.
- `Pull Logs` collects the diagnostics report input.
- `Report` tab prepares a copyable text report.
- `Copy`, save, and GitHub issue actions are available from the screen.

### Important note

Initial silicon enrollment happens during genesis / device securing. The monitor screen is for
inspection and diagnostics after that setup, not for replacing genesis bootstrap.

## Token Policy and Token Creation

Token creation is currently a developer-tools flow, not a normal end-user flow from the token list.

The correct path is:

`Settings -> VERSION (tap 7x) -> POLICY TOOLS -> Create Token Policy + Token`

### What happens there

The interactive dialog is a 3-step wizard:

1. `Identity`
2. `Supply & Rules`
3. `Access & Review`

The wizard defines the CPTA policy parameters, publishes the policy anchor, and creates a token
bound to that policy.

### What the wizard configures

- token kind: `FUNGIBLE`, `NFT`, or `SBT`
- ticker and display name
- description and icon URL
- decimals
- fixed or unlimited supply
- initial allocation
- whether mint/burn stays enabled
- mint/burn threshold
- transferability
- allowlist mode

### Important distinction

The main `Tokens` screen is primarily for:

- viewing imported token policies
- scanning/importing token policy QR payloads
- using the faucet flow

It is not the primary documented creation path. The creation path lives in `POLICY TOOLS`.

### Advanced path

`POLICY TOOLS` also supports pasting Base32 Crockford encodings of `CanonicalPolicy` protobuf
bytes and publishing them directly. That path is intended for developers who are generating policy
payloads manually or through tooling.

If you are generating typed policy specs instead of hand-building protobuf payloads, also read
[Chapter 16 -- Code Generation](16-code-generation.md).

## DLV Tools

The DLV debug surface lives under:

`Settings -> VERSION (tap 7x) -> DLV TOOLS`

This is a developer/debug screen, not a polished end-user vault workflow.

### What it currently supports

- loading contacts
- selecting a contact
- computing a `b0x` address from the contact's genesis, device ID, and chain tip
- pasting Base32 Crockford encodings of `DlvCreateV3` payload bytes
- pasting optional unlock / condition payload bytes
- attempting DLV creation through the debug bridge if that function is available in the build

### Important note

This screen assumes protobuf-first developer input. It expects serialized bytes represented as
Base32 Crockford, not JSON, YAML, or hex.

## Offline BLE Mode

For normal in-app BLE development, the active settings path is:

`Settings -> OFFLINE MODE`

Enabling `OFFLINE MODE` starts BLE advertising and scanning for offline bilateral transfers.

### What it is for

- testing live offline bilateral transfers
- verifying the BLE advertising/scanning path
- preparing two devices for manual offline transfer testing

### What it is not

It is not the same thing as the older manual `BLE TRANSFER TEST` screen referenced in some legacy
comments and docs. That older component still exists in the frontend tree, but it is not part of
the active routed app flow.

For current developers, the supported BLE paths are:

- `Settings -> OFFLINE MODE` for device-side testing
- the automation and test tooling documented in [Chapter 9 -- BLE Testing](09-ble-testing.md)

## NFC Backup and Recovery

The settings screen also exposes an NFC recovery workflow:

`Settings -> NFC RING BACKUP`

Current developer-facing actions include:

- importing an NFC recovery capsule
- entering the mnemonic key
- decrypting the imported capsule

This is useful for recovery-path validation and debugging NFC capsule handling.

## Practical First Read for a New App Developer

If you are new to the app and want the shortest practical onboarding path, read the docs in this
order:

1. [Chapter 2 -- Quickstart](02-quickstart.md)
2. [Chapter 3 -- Development Setup](03-development-setup.md)
3. [Chapter 4 -- Architecture](04-architecture.md)
4. [This chapter](18-in-app-developer-walkthroughs.md)
5. [Chapter 9 -- BLE Testing](09-ble-testing.md)
6. [Chapter 16 -- Code Generation](16-code-generation.md)

Back to [Table of Contents](README.md)
