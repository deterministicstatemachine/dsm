// SPDX-License-Identifier: MIT OR Apache-2.0

/* eslint-disable @typescript-eslint/no-explicit-any */
import { BridgeRpcRequest, BridgeRpcResponse, IngressRequest, IngressResponse } from '../../proto/dsm_app_pb';
import { callBin, routerQueryBin } from '../WebViewBridge/transportCore';

function success(data: Uint8Array): Uint8Array {
  return new BridgeRpcResponse({ result: { case: 'success', value: { data: new Uint8Array(data) } } }).toBinary();
}

describe('the transport is the bridge index.html installs', () => {
  // Every transport path used to branch on `__callBin`, a function only the
  // jest stub installed, and fall back to `sendMessageBin`.
  test('a bridge object without the port transport is refused', async () => {
    (global as any).window.DsmBridge = { isAvailable: () => true };
    await expect(callBin('getPreference')).rejects.toThrow('DSM bridge not available');
  });

  // Router calls go through the bridge object's own `ingress` wrapper — the
  // one index.html installs over the port — never through a fallback that
  // re-encodes the request here.
  test('a router query goes through the bridge’s ingress wrapper', async () => {
    const seen: Uint8Array[] = [];
    const answer = new IngressResponse({ result: { case: 'okBytes', value: new Uint8Array([9, 9]) } }).toBinary();
    (global as any).window.DsmBridge = {
      sendMessageBin: async () => { throw new Error('the port must not be called directly for a router query'); },
      ingress: async (payload: Uint8Array) => { seen.push(payload); return answer; },
    };
    await expect(routerQueryBin('balance.list', new Uint8Array(0))).resolves.toEqual(new Uint8Array([9, 9]));
    expect(seen).toHaveLength(1);
    expect(IngressRequest.fromBinary(seen[0]).operation.case).toBe('routerQuery');
  });
});
