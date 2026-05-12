import { routerQueryBin } from '../WebViewBridge';
import { BridgeRpcRequest, BridgeRpcResponse, IngressRequest, IngressResponse } from '../../proto/dsm_app_pb';

function wrapSuccessEnvelope(data: Uint8Array): Uint8Array {
  return (global as any).createDsmBridgeSuccessResponse(data);
}

describe('MessagePort ingress symmetry', () => {
  beforeEach(() => {
    (globalThis as any).window = (globalThis as any).window ?? {};
  });

  test('router queries send nativeBoundaryIngress and return ingress okBytes without request-id stripping', async () => {
    const okBytes = new Uint8Array([7, 8, 9]);

    (globalThis as any).window.DsmBridge = {
      __binary: true,
      sendMessageBin: async (reqBytes: Uint8Array) => {
        const req = BridgeRpcRequest.fromBinary(reqBytes);
        expect(req.method).toBe('nativeBoundaryIngress');
        const ingressRequest = IngressRequest.fromBinary(
          req.payload?.case === 'bytes' ? req.payload.value.data : new Uint8Array(0),
        );
        expect(ingressRequest.operation.case).toBe('routerQuery');
        return wrapSuccessEnvelope(
          new IngressResponse({
            result: { case: 'okBytes', value: okBytes },
          }).toBinary(),
        );
      },
    };

    const out = await routerQueryBin('/transport/headersV3', new Uint8Array([9, 9, 9]));
    expect(out).toEqual(okBytes);
  });
});
