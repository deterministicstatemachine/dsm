# DSM New Frontend

This frontend is wired for deterministic, protobuf-only integration with the DSM core.

- Screens must call the single client entrypoint `src/dsm/index.ts` (exported as `dsmClient`).
- Never call the bridge directly from screens; only `dsmClient` talks to the binary bridge.
- No JSON/hex/Base32 at the transport boundary—protobuf bytes only.

## Start here

The bridge contract is `../android/app/src/main/java/com/dsm/wallet/bridge/SinglePathWebViewBridge.kt`; the wire format is `../../proto/dsm_app.proto`.

