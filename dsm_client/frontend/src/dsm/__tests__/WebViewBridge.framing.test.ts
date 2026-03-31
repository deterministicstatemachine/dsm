// Helper to wrap responses in BridgeRpcResponse format
function wrapSuccessEnvelope(data: Uint8Array): Uint8Array {
  const pb = require('../../proto/dsm_app_pb');
  const br = new pb.BridgeRpcResponse({ result: { case: 'success', value: { data } } });
  return br.toBinary();
}

function u32be(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

describe.skip('WebViewBridge framing invariants', () => {
  beforeEach(() => {
    (global as any).window = (global as any).window ?? {};
  });

  test('frameCall produces [u32be(len)][utf8 method][payload]', async () => {
    const seen: { method?: string; payload?: Uint8Array } = {};

    (global as any).window.DsmBridge = {
      __callBin: async (reqBytes: Uint8Array) => {
        const pb = require('../../proto/dsm_app_pb');
        const req = pb.BridgeRpcRequest.fromBinary(reqBytes);
        seen.method = req.method;
        seen.payload = req.payload?.case === 'bytes' ? req.payload.value.data : new Uint8Array(0);
        // Return wrapped success envelope with some bytes
        return wrapSuccessEnvelope(new Uint8Array([1, 2, 3]));
      },
    };

    const envelope = new Uint8Array([9, 9, 9, 9]);
    await processEnvelopeV3Bin(envelope);

    expect(seen.method).toBe('appRouterInvoke');

    const enc = new TextEncoder();
    const expectedInnerMethod = enc.encode('processEnvelopeV3');

    // processEnvelopeV3Bin constructs a frameCall('processEnvelopeV3', envelope)
    const expectedFramed = concat(u32be(expectedInnerMethod.length), expectedInnerMethod, envelope);

    expect(seen.payload).toBeInstanceOf(Uint8Array);
    expect(seen.payload).toEqual(expectedFramed);
  });

  test('normalizeToBytes rejects non-Uint8Array / non-number[] payloads', async () => {
    // This is indirectly tested via __callBin return type normalization.
    (global as any).window.DsmBridge = {
      __callBin: async () => {
        return { nope: true } as any;
      },
    };

    await expect(processEnvelopeV3Bin(new Uint8Array([1]))).rejects.toThrow(
      /normalizeToBytes: expected Uint8Array or number\[]/,
    );
  });
});
