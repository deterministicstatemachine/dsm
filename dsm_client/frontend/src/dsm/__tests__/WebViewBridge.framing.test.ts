import { processEnvelopeV3Bin } from '../WebViewBridge';
import { BridgeRpcRequest, BridgeRpcResponse, EnvelopeOp, IngressRequest, IngressResponse } from '../../proto/dsm_app_pb';

function wrapSuccessEnvelope(data: Uint8Array): Uint8Array {
  const br = new BridgeRpcResponse({ result: { case: 'success', value: { data } } });
  return br.toBinary();
}

describe.skip('WebViewBridge framing invariants', () => {
  beforeEach(() => {
    (global as any).window = (global as any).window ?? {};
  });

  test('processEnvelopeV3Bin uses nativeBoundaryIngress with an envelope op', async () => {
    const seen: { method?: string; payload?: Uint8Array } = {};
    const response = new IngressResponse({
      result: { case: 'okBytes', value: new Uint8Array([1, 2, 3]) },
    }).toBinary();

    (global as any).window.DsmBridge = {
      __callBin: async (reqBytes: Uint8Array) => {
        const req = BridgeRpcRequest.fromBinary(reqBytes);
        seen.method = req.method;
        seen.payload = req.payload?.case === 'bytes' ? req.payload.value.data : new Uint8Array(0);
        return wrapSuccessEnvelope(response);
      },
    };

    const envelope = new Uint8Array([9, 9, 9, 9]);
    await processEnvelopeV3Bin(envelope);

    expect(seen.method).toBe('nativeBoundaryIngress');
    const ingressRequest = IngressRequest.fromBinary(seen.payload ?? new Uint8Array(0));
    expect(ingressRequest.operation.case).toBe('envelope');
    expect((ingressRequest.operation.value as EnvelopeOp).envelopeBytes).toEqual(envelope);
  });

  test('normalizeToBytes rejects non-Uint8Array / non-number[] payloads', async () => {
    (global as any).window.DsmBridge = {
      __callBin: async () => ({ nope: true } as any),
    };

    await expect(processEnvelopeV3Bin(new Uint8Array([1]))).rejects.toThrow(
      /normalizeToBytes: expected Uint8Array or number\[]/,
    );
  });
});
