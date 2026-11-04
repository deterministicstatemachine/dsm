# BLE link session (SA-35, DSM Amendment A27)

Owner rulings, 2026-11-01: per-link session, authenticated, unique nonces, safe reconnection; a
passive BLE observer must not learn permanent identifiers, transfer amounts, salts or other
private transfer data. (a) non-reach discovery tries each contact; (b) the handshake replaces the
three-phase pairing and the public identity characteristic, keeping pairing's completion
guarantees; (c) Rust chooses the link, Kotlin only moves bytes on the link it is told, a vanished
link fails closed, reconnection re-runs the handshake. Prepare/PrepareResponse unchanged.

## Wire (radio bytes, both GATT directions, TX_REQUEST / TX_RESPONSE)

- `0x05 ‖ kind ‖ index ‖ total ‖ data` — a plaintext handshake fragment. kind 1 Hello, 2 Reply,
  3 Confirm, 4 Decline. Fragments of at most 400 data bytes; reassembled per link in memory.
- `0x06 ‖ record` — `dsm::crypto::ble_link::LinkSession` record, always 500 bytes
  (counter ‖ XChaCha20-Poly1305 of 476 padded bytes), 501 with the tag: one notification
  at the negotiated 512 MTU (509 bytes of value). Plaintext is one radio unit as before
  (a `BleChunk` of a bilateral frame, or a `0x03` envelope), or `0x07` = link ready.
- Nothing else is taken from the radio. 0x05/0x06 cannot start a `BleChunk` (protobuf field 0).

## Roles

- GATT client = initiator. It opens a link with an optional target contact: target first, then
  every other contact with a pinned Kyber key, one Hello each; a Decline moves to the next.
- GATT server = responder. A Hello not sealed for it, or from a non-contact, is Declined.
- Responder completes pairing on a valid Confirm and sends a sealed `0x07` ready record.
  Initiator completes pairing when it opens the responder's first record (the ready).
  Completion = `update_contact_ble_status(peer, None, Some(address))` + orchestrator Complete +
  frontend notification, exactly as the old Phase 3 did.
- Sessions live in memory, per `(address, role)`, dropped (zeroized) on link close; every
  connection runs a fresh handshake. Owed frames are re-sealed on each new link.

## Layers

- Core `dsm/src/crypto/ble_link.rs` (+ `ble_link/tests.rs`): handshake + records. DONE.
- SDK `bluetooth/link_session.rs`: link table, fragments, `opened`, `inbound`, `seal_on`,
  `link_of(device_id)`, `closed`; `LinkKeys` from AppState + own Kyber secret + contacts.
- JNI: `processIncomingBleData(address, role, bytes)` opens through link_session first;
  `bleLinkOpened(address, role, target) -> frames`; `bleLinkClosed(address, role)`;
  `send_ble_chunks_via_unified` seals on Rust's chosen link and calls
  `dispatchRustBleFollowUp(address, role, chunks, reliable)`, or `requestGattConnect(hint)` and
  returns not-delivered when no link is established (owed frames go at establishment).
- Delete: GATT identity characteristic, PAIRING / PAIRING_ACK characteristics, identity read,
  `processGattIdentityRead`, `processBleIdentityEnvelope`, `finalizeScannerPairing`,
  `gatt_identity.rs`, the pairing orchestrator's identity/propose/confirm/ack/finalize phases,
  their proto messages (BleIdentityCharValue, BleIdentityObserved, BlePairingAccept,
  BlePairingConfirm) and Kotlin BleSessionEvents IdentityReadCompleted, PairingAckReceived,
  PairingConfirmWritten.
- Kotlin: GattServerHost, GattClientSession, BleCoordinator, BleConstants, BleSessionEvent,
  Unified, UnifiedNativeApi.

## Tests

- Core: handshake both ways, records once/in order/one direction, wrong-key / non-contact /
  other-genesis refused. DONE.
- SDK: two-device harness runs the handshake over recorded radio bytes; no device id, genesis,
  salt or amount appears in any radio byte; replayed record refused; Hello from a non-contact
  declined; records of a previous link do not open after reconnect; pairing completes on both
  sides only after Confirm / ready.
- Mutation: genesis comparison in respond; counter check in open; the Confirm's opening (the nonce comparison it replaced could never refuse on its own); clear bytes on an established link; the closing of a link; the turn of a handshake; the ready; a record before the ready.
