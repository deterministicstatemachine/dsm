// SPDX-License-Identifier: MIT OR Apache-2.0

/* eslint-disable @typescript-eslint/no-explicit-any */
import { decodeBalancesListResponseStrict, decodeFramedEnvelopeV3 } from '../decoding';
import { routerQueryBin } from '../WebViewBridge';

function makeInvalidResponse(): Uint8Array {
  return new Uint8Array([0x01, 0x02, 0x03, 0x04]);
}



/** A BridgeRpcResponse error, built by the harness helper setupTests installs. */
function makeErrorResponse(msg: string): Uint8Array {
  return (global as any).createDsmBridgeErrorResponse(msg);
}

describe('bridge decoding boundary (integration)', () => {
  beforeEach(() => {
    (global as any).window = (global as any).window || {};
    (global as any).window.DsmBridge = (global as any).window.DsmBridge || {};
  });

  // Bytes the port answered that are not a BridgeRpcResponse: index.html's
  // wrapper answers `invalid bridge response for <method>`.
  it('rejects invalid BridgeRpcResponse bytes', async () => {
    (global as any).window.DsmBridge.sendMessageBin = async () => makeInvalidResponse();
    await expect(routerQueryBin('balance.list', new Uint8Array([1, 2, 3]))).rejects.toThrow(/invalid bridge response for nativeBoundaryIngress/);
  });

  it('propagates bridge error payloads', async () => {
    (global as any).window.DsmBridge.sendMessageBin = async () => makeErrorResponse('native exploded');
    await expect(routerQueryBin('balance.list')).rejects.toThrow(/native exploded/i);
  });

  // A boundary failure reaches the diagnostics bus as its message. The port
  // wrappers in index.html reduce Kotlin's ErrorResponse to that message, so
  // no code or debug bytes travel with it (recorded as Open in §6.29).
  it('a boundary failure reaches bridge.error as its message', async () => {
    (global as any).window.DsmBridge.sendMessageBin = async () => makeErrorResponse('native exploded');
    const { bridgeEvents } = require('../../bridge/bridgeEvents');
    const seen: any[] = [];
    const off = bridgeEvents.on('bridge.error', (detail: any) => { seen.push(detail); });
    try {
      await expect(routerQueryBin('balance.list')).rejects.toThrow(/native exploded/);
    } finally {
      off();
    }
    expect(seen).toHaveLength(1);
    expect(seen[0].message).toMatch(/native exploded/);
  });

  it('decodeFramedEnvelopeV3 rejects non-framed garbage bytes', () => {
    const raw = new Uint8Array([0, 1, 2, 3, 4]);
    expect(() => decodeFramedEnvelopeV3(raw)).toThrow();
  });

  it('decodeFramedEnvelopeV3 rejects empty bytes', () => {
    expect(() => decodeFramedEnvelopeV3(new Uint8Array(0))).toThrow();
  });

  it('decodeBalancesListResponseStrict rejects garbage bytes', () => {
    const raw = new Uint8Array([9, 9, 9, 9, 9, 9]);
    expect(() => decodeBalancesListResponseStrict(raw, { label: 'test' })).toThrow(/invalid framing byte/i);
  });
});
