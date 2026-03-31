# DSM New Frontend

This frontend is wired for deterministic, protobuf-only integration with the DSM core.

- Screens must call the single client entrypoint `src/dsm/index.ts` (exported as `dsmClient`).
- Never call the bridge directly from screens; only `dsmClient` talks to the binary bridge.
- No JSON/hex/Base32 at the transport boundary—protobuf bytes only.

## Start here

Read the canonical guide for patterns, examples, and invariants:

- ../../docs/book/11-integration-guide.md

