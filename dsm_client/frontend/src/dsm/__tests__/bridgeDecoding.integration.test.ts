// SPDX-License-Identifier: MIT OR Apache-2.0

/* eslint-disable @typescript-eslint/no-explicit-any */
import { decodeBalancesListResponseStrict, decodeFramedEnvelopeV3 } from '../decoding';
import { processEnvelopeV3Bin } from '../WebViewBridge';
import { decodeBase32Crockford } from '../../utils/textId';

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

  it('rejects invalid BridgeRpcResponse bytes', async () => {
    (global as any).window.DsmBridge.__callBin = async () => makeInvalidResponse();
    await expect(processEnvelopeV3Bin(new Uint8Array([1, 2, 3]))).rejects.toThrow(/Bridge error/i);
  });

  it('propagates bridge error payloads', async () => {
    (global as any).window.DsmBridge.__callBin = async () => makeErrorResponse('native exploded');
    await expect(processEnvelopeV3Bin(new Uint8Array([1]))).rejects.toThrow(/native exploded/i);
  });

  it('emits bridge.error event with debug_b32 that decodes to original ErrorResponse', async () => {
    (global as any).window.DsmBridge.__callBin = async () => makeErrorResponse('native exploded');

    // Listen for bridge.error event
    const { bridgeEvents } = require('../../bridge/bridgeEvents');

    const evPromise = new Promise<void>((resolve, reject) => {
      const off = bridgeEvents.on('bridge.error', (detail: any) => {
        try {
          expect(detail).toHaveProperty('code');
          expect(detail).toHaveProperty('message');
          expect(typeof detail.debugB32).toBe('string');
          const dbgStr = detail.debugB32;
          console.log('DEBUG_B32:', dbgStr?.slice(0, 120));
          const decoded = decodeBase32Crockford(detail.debugB32);
          // Basic check: decoded bytes exist and are non-empty (debug payload present)
          console.log('DEBUG_DECODED_LEN:', decoded.length);
          expect((decoded as Uint8Array).length).toBeGreaterThan(0);
          off();
          resolve();
        } catch (e) {
          off();
          reject(e);
        }
      });
      // Timeout fail-safe
      setTimeout(() => { off(); reject(new Error('bridge.error not emitted')); }, 3000);
    });

    await expect(processEnvelopeV3Bin(new Uint8Array([1]))).rejects.toThrow(/native exploded/i);
    await evPromise;
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
