// SPDX-License-Identifier: MIT OR Apache-2.0

import { routerQueryBin } from '../WebViewBridge';
import { BridgeRpcRequest, BridgeRpcResponse, IngressRequest, IngressResponse } from '../../proto/dsm_app_pb';

function wrapSuccessEnvelope(data: Uint8Array): Uint8Array {
  const br = new BridgeRpcResponse({ result: { case: 'success', value: { data: new Uint8Array(data) } } });
  return br.toBinary();
}

describe('WebViewBridge framing invariants', () => {
  beforeEach(() => {
    (global as any).window = (global as any).window ?? {};
  });

  test('a router query goes to nativeBoundaryIngress as a routerQuery op', async () => {
    const seen: { method?: string; payload?: Uint8Array } = {};
    const response = new IngressResponse({
      result: { case: 'okBytes', value: new Uint8Array([1, 2, 3]) },
    }).toBinary();

    (global as any).window.DsmBridge = {
      sendMessageBin: async (reqBytes: Uint8Array) => {
        const req = BridgeRpcRequest.fromBinary(reqBytes);
        seen.method = req.method;
        seen.payload = req.payload?.case === 'bytes' ? req.payload.value.data : new Uint8Array(0);
        return wrapSuccessEnvelope(response);
      },
    };

    const params = new Uint8Array([9, 9, 9, 9]);
    await expect(routerQueryBin('balance.list', params)).resolves.toEqual(new Uint8Array([1, 2, 3]));

    expect(seen.method).toBe('nativeBoundaryIngress');
    const ingressRequest = IngressRequest.fromBinary(seen.payload ?? new Uint8Array(0));
    expect(ingressRequest.operation.case).toBe('routerQuery');
    expect(ingressRequest.operation.case === 'routerQuery' && ingressRequest.operation.value.method).toBe('balance.list');
    expect(ingressRequest.operation.case === 'routerQuery' && ingressRequest.operation.value.args).toEqual(params);
  });

  // The guard is on the bridge's own `ingress` wrapper's answer: index.html
  // answers bytes or throws, and anything else is refused here.
  test('a native answer that is not bytes is refused', async () => {
    (global as any).window.DsmBridge = {
      sendMessageBin: async () => new Uint8Array(0),
      ingress: async () => ({ nope: true } as any),
    };

    await expect(routerQueryBin('balance.list')).rejects.toThrow(
      /expected Uint8Array response from native boundary/,
    );
  });
});
