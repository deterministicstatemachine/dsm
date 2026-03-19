import { appRouterQueryBin } from '../WebViewBridge';

import { Envelope, Error as PbError } from '../../proto/dsm_app_pb';

// Helper to wrap response in DSM_BRIDGE format
function wrapSuccessEnvelope(data: Uint8Array): Uint8Array {
  return (global as any).createDsmBridgeSuccessResponse(data);
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

describe('MessagePort requestId prefix symmetry', () => {
  beforeEach(() => {
    (globalThis as any).window = (globalThis as any).window ?? {};
  });

  test('router query: JS strips 8-byte requestId prefix before returning protobuf bytes', async () => {
    // This simulates the *real* Android MessagePort behavior:
    // - request has an 8-byte correlation id prefixed on the wire
    // - response echoes the same 8 bytes prefixed
    // - JS/WebViewBridge strips those 8 bytes for router methods

    const env = new Envelope({
      payload: {
        case: 'error',
        value: new PbError({ code: 123, message: 'boom-port' }),
      } as any,
    });
    const bin = env.toBinary();

    const reqId = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]);
    const respPrefixed = concatBytes(reqId, bin);

    (globalThis as any).window.DsmBridge = {
      __binary: true,
      sendMessageBin: async (reqBytes: Uint8Array) => {
        const pb = require('../../proto/dsm_app_pb');
        const req = pb.BridgeRpcRequest.fromBinary(reqBytes);
        const method = req.method || '';
        const payload = req.payload?.case === 'bytes' ? req.payload.value.data : new Uint8Array(0);
        // Android only uses the requestId convention for router methods.
        if (method === 'appRouterInvoke' || method === 'appRouterQuery') {
          expect(payload).toBeInstanceOf(Uint8Array);
          // Return the prefixed response wrapped in BridgeRpcResponse
          return wrapSuccessEnvelope(respPrefixed);
        }
        return wrapSuccessEnvelope(bin);
      },
    };

    const out = await appRouterQueryBin('/transport/headersV3', new Uint8Array([9, 9, 9]));
    // The JS side must strip the 8B prefix before returning to the caller.
    expect(out).toEqual(bin);
  });
});
