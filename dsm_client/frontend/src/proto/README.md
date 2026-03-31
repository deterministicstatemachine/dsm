# TypeScript Protobuf Bindings (canonical)

Source of truth: `proto/dsm_app.proto` at repo root.

This folder hosts generated TS types for the WebView UI. Do not hand-edit generated files.

## Generate (using ts-proto)

Requirements:
- Node.js (>=18)
- `protoc` installed (e.g., via Homebrew: `brew install protobuf`)

One-time install (optional, local):
- `pnpm add -w -D ts-proto`

Run (preferred):

```bash
# From repo root
./scripts/generate_ts_protos.sh
```

This will output to `dsm_client/frontend/src/proto/gen`.

## Importing in UI

```ts
import * as pb from '../../proto/gen/dsm_app';
```

All canonical encodings and acceptance logic still live in Rust (dsm_core). TS types are for transport only.
