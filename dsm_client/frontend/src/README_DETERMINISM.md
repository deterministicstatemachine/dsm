# DSM Frontend Determinism Notes

- Bridge calls **must** use bytes-only MessagePort, encoded as Base32 Crockford only for transport.
- No JS interface shims, no string-encoded protobufs on protocol paths.
- Contacts, balances, history, inbox, and QR flows must route through strict bridge helpers in `src/dsm/index.ts` / `src/dsm/WebViewBridge.ts`.
- `DsmClient` must delegate to the strict helpers; never call `window.DsmBridge.getContacts`/`addContact`/`handleContactQrV3`.
- QR/contact add flows must use `ContactQrV3` protobuf bytes; UI may only base32-encode for transport, never JSON.
- Tests should mock the strict bridge helpers, not extra methods.
