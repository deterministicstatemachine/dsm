// SPDX-License-Identifier: MIT OR Apache-2.0

import { setBridgeInstance } from '../../bridge/BridgeRegistry';
import { routerQueryBin } from '../WebViewBridge';
import { IngressRequest, IngressResponse } from '../../proto/dsm_app_pb';

describe('NativeBoundaryBridge', () => {
  beforeEach(() => {
    (globalThis as any).window = (globalThis as any).window ?? {};
  });

  afterEach(() => {
    setBridgeInstance(undefined);
    delete (globalThis as any).window.DsmBridge;
  });

  test('routerQueryBin uses ingress boundary when available', async () => {
    let seenRequest: IngressRequest | undefined;
    const bridge = {
      __binary: true,
      ingress: async (requestBytes: Uint8Array) => {
        seenRequest = IngressRequest.fromBinary(requestBytes);
        return new IngressResponse({
          result: { case: 'okBytes', value: new Uint8Array([9, 8, 7]) },
        }).toBinary();
      },
    };
    // The setter registers the bridge with the DI registry.
    (globalThis as any).window.DsmBridge = bridge;

    const result = await routerQueryBin('wallet.balance', new Uint8Array([1, 2, 3]));

    expect(result).toEqual(new Uint8Array([9, 8, 7]));
    const op = seenRequest?.operation;
    expect(op?.case).toBe('routerQuery');
    if (op?.case !== 'routerQuery') throw new Error('expected a routerQuery operation');
    expect(op.value.method).toBe('wallet.balance');
    expect(op.value.args).toEqual(new Uint8Array([1, 2, 3]));
  });
});
