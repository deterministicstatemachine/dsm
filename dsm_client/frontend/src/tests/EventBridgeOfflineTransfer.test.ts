/// <reference types="jest" />
/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// Unit test: parseBleEnvelope should detect offline bilateral transfer (wallet.receive invoke)

import { parseBleEnvelope } from '../dsm/EventBridge';
import * as pb from '../proto/dsm_app_pb';

function zeroHash32(): pb.Hash32 { return new pb.Hash32({ v: new Uint8Array(32) as any }); }

describe('parseBleEnvelope offline transfer detection', () => {
  test('detects wallet.receive with BilateralTransferRequest body', () => {
    // 1. Build BilateralTransferRequest payload
    const bilateral = new pb.BilateralTransferRequest({
      counterpartyDeviceId: new Uint8Array(32),
      commitmentHash: zeroHash32(),
      counterpartySig: new Uint8Array(64),
      operationData: new Uint8Array([1,2,3]),
      expectedGenesisHash: zeroHash32(),
      expectedCounterpartyStateHash: zeroHash32(),
      expectedLocalStateHash: zeroHash32(),
    });
    const bilateralBytes = bilateral.toBinary();

    // 2. ArgPack wrapping (codec=PROTO, schemaHash zero)
    const argPack = new pb.ArgPack({
      schemaHash: zeroHash32(),
      codec: (pb as any).Codec?.PROTO ?? 0,
      body: bilateralBytes as any,
    });

    // 3. Invoke op
    const invoke = new pb.Invoke({
      method: 'wallet.receive',
      args: argPack,
      preStateHash: zeroHash32(),
      postStateHash: zeroHash32(),
    });

    const uop = new pb.UniversalOp({
      opId: zeroHash32(),
      actor: new Uint8Array(32) as any,
      genesisHash: new Uint8Array(32) as any,
      kind: { case: 'invoke', value: invoke },
    });

    const utx = new pb.UniversalTx({ ops: [uop], atomic: true });

    const env = new pb.Envelope({
      version: 3,
      payload: { case: 'universalTx', value: utx },
    });

    const rawEnvBytes = env.toBinary();
    const bytes = new Uint8Array(1 + rawEnvBytes.length);
    bytes[0] = 0x03;
    bytes.set(rawEnvBytes, 1);

  // Sanity: envelope decodes (strip framing byte for raw check)
  const env2 = pb.Envelope.fromBinary(bytes.slice(1));
  expect((env2 as any).payload?.case).toBe('universalTx');

  const parsed = parseBleEnvelope(bytes);
    expect(parsed).toBeTruthy();
    expect((parsed as any).offlineTransferPayload).toBeInstanceOf(Uint8Array);
    const raw = (parsed as any).offlineTransferPayload as Uint8Array;
    expect(raw.length).toBe(bilateralBytes.length);
    // Quick sanity: first three bytes match operationData first bytes embedded inside request serialization (not strict but heuristic)
    // (This depends on protobuf field ordering; we only assert payload length equivalence above.)
  });

  test('returns null for malformed bytes', () => {
    const parsed = parseBleEnvelope(new Uint8Array([0,1,2]));
    // Malformed envelope parse should catch and return null
    expect(parsed).toBeNull();
  });

  test('BLE envelope with BilateralPrepareResponse triggers wallet refresh', () => {
    // Ensure the global event bridge is installed
    // initializeEventBridge attaches a DOM listener; safe to call multiple times
    const { initializeEventBridge } = require('../dsm/EventBridge');
    initializeEventBridge();

    const handler = jest.fn();
    const { bridgeEvents } = require('../bridge/bridgeEvents');
    const unsubscribe = bridgeEvents.on('wallet.refresh', handler as any);

    // Build a minimal BilateralPrepareResponse
    const zeroHash32 = () => new pb.Hash32({ v: new Uint8Array(32) as any });
    const resp = new pb.BilateralPrepareResponse({
      commitmentHash: zeroHash32(),
      localSignature: new Uint8Array(64),
    });

    const env = new pb.Envelope({ version: 3, payload: { case: 'bilateralPrepareResponse', value: resp } });
    const rawBleBytes = env.toBinary();
    const bytes = new Uint8Array(1 + rawBleBytes.length);
    bytes[0] = 0x03;
    bytes.set(rawBleBytes, 1);

    // Emit through the real DOM ingress path that EventBridge listens to.
    window.dispatchEvent(new CustomEvent('dsm-event-bin', {
      detail: { topic: 'ble.envelope.bin', payload: bytes },
    }));

    expect(handler).toHaveBeenCalled();
    // Validate detail.source contains 'bilateral' (robust against minor string variants)
    const ev = handler.mock.calls.find(c => c && c[0] && typeof c[0].source === 'string' && c[0].source.indexOf('bilateral') >= 0);
    expect(Boolean(ev)).toBe(true);
    unsubscribe();
  });
});
