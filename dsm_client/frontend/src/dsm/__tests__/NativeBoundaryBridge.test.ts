import { setBridgeInstance } from '../../bridge/BridgeRegistry';
import { appRouterQueryBin } from '../WebViewBridge';
import { decodeSdkEventToLegacyTopic } from '../NativeBoundaryBridge';
import { IngressRequest, IngressResponse, SdkEvent, SdkEventKind } from '../../proto/dsm_app_pb';

describe('NativeBoundaryBridge', () => {
  beforeEach(() => {
    (globalThis as any).window = (globalThis as any).window ?? {};
  });

  afterEach(() => {
    setBridgeInstance(undefined);
    delete (globalThis as any).window.DsmBridge;
  });

  test('appRouterQueryBin uses ingress boundary when available', async () => {
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

    const result = await appRouterQueryBin('wallet.balance', new Uint8Array([1, 2, 3]));

    expect(result).toEqual(new Uint8Array([9, 8, 7]));
    expect(seenRequest?.operation.case).toBe('routerQuery');
    expect(seenRequest?.operation.value.method).toBe('wallet.balance');
    expect(seenRequest?.operation.value.args).toEqual(new Uint8Array([1, 2, 3]));
  });

  test('typed sdk events map to legacy topic names only in the web adapter', () => {
    const bytes = new SdkEvent({
      kind: SdkEventKind.WALLET_REFRESH,
      payload: new Uint8Array([0xaa]),
    }).toBinary();

    expect(decodeSdkEventToLegacyTopic(bytes)).toEqual({
      topic: 'dsm-wallet-refresh',
      payload: new Uint8Array([0xaa]),
    });
  });
});
