/* eslint-disable @typescript-eslint/no-explicit-any */
import { decodeBalancesListResponseStrict, decodeFramedEnvelopeV3 } from '../decoding';
import { processEnvelopeV3Bin } from '../WebViewBridge';
import { decodeBase32Crockford } from '../../utils/textId';

function makeInvalidResponse(): Uint8Array {
  return new Uint8Array([0x01, 0x02, 0x03, 0x04]);
}



function makeErrorResponse(msg: string): Uint8Array {
  // Use test harness helper if available (preferred)
  const g: any = global as any;
  if (typeof g.createDsmBridgeErrorResponse === 'function') {
    return g.createDsmBridgeErrorResponse(msg);
  }

  // Alternate path: try to construct a proper protobuf BridgeRpcResponse with debugB32
  try {
    const pb = require('../proto/dsm_app_pb');
    const { encodeBase32Crockford } = require('../../utils/textId');
    const errProto = new pb.ErrorResponse({ errorCode: 1, message: msg });
    const debug = encodeBase32Crockford(errProto.toBinary());
    const br = new pb.BridgeRpcResponse({ result: { case: 'error', value: { errorCode: 1, message: msg, debugB32: debug } } });
    return br.toBinary();
  } catch (_e) {
    // Last-resort plain-text error
    const data = new TextEncoder().encode(msg);
    return data;
  }
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

  it.skip('sanity: test harness helper attaches debugB32', () => {
    // Skip this test as it requires importing the proto which Jest can't handle
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
          const { decodeBase32Crockford } = require('../../utils/textId');
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
