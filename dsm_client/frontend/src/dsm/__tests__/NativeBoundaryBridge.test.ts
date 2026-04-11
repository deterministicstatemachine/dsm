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
    (globalThis as any).window.DsmBridge = bridge;
    setBridgeInstance(bridge);

    const result = await routerQueryBin('wallet.balance', new Uint8Array([1, 2, 3]));

    expect(result).toEqual(new Uint8Array([9, 8, 7]));
    expect(seenRequest?.operation.case).toBe('routerQuery');
    expect(seenRequest?.operation.value.method).toBe('wallet.balance');
    expect(seenRequest?.operation.value.args).toEqual(new Uint8Array([1, 2, 3]));
  });
});
