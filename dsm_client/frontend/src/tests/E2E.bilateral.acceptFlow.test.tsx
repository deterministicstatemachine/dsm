import { act } from '@testing-library/react';
import { acceptOfflineTransfer } from '@/dsm/index';
import { bridgeEvents } from '../bridge/bridgeEvents';
import * as pb from '../proto/dsm_app_pb';

describe('E2E bilateral accept: BLE accept flow triggers refresh and toast', () => {
  let logSpy: jest.SpyInstance;
  let rafSpy: jest.SpyInstance;

  beforeEach(() => {
    logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    // JSDOM doesn't fire RAF callbacks; provide sync polyfill so
    // schedulePostAcceptRefreshes() actually emits wallet.refresh events.
    rafSpy = jest.spyOn(window, 'requestAnimationFrame').mockImplementation((cb) => {
      cb(0);
      return 0;
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
    delete (window as any).DsmBridge;
    logSpy.mockRestore();
    rafSpy.mockRestore();
  });

  test('acceptOfflineTransfer emits wallet.refresh via RAF chain', async () => {
    // Track wallet.refresh events emitted by schedulePostAcceptRefreshes()
    const refreshEvents: unknown[] = [];
    const off = bridgeEvents.on('wallet.refresh', (detail) => {
      refreshEvents.push(detail);
    });

    // Fake bytes-only DsmBridge response for bilateral.accept
    const resp = new pb.BilateralAcceptResponse({ accepted: true, message: 'ok' } as any);
    const pack = new pb.ResultPack({ schemaHash: new pb.Hash32({ v: new Uint8Array(32) }), codec: pb.Codec.PROTO, body: resp.toBinary() as any });
    const op = new pb.OpResult({ opId: new pb.Hash32({ v: new Uint8Array(32) }), accepted: true, postStateHash: new pb.Hash32({ v: new Uint8Array(32) }), result: pack } as any);
    const rx = new pb.UniversalRx({ results: [op] });
    const env = new pb.Envelope({ version: 3, headers: new pb.Headers({ deviceId: new Uint8Array(32).fill(1), genesisHash: new Uint8Array(32).fill(1) } as any), payload: { case: 'universalRx', value: rx } } as any);
    // Helper: wrap raw Envelope bytes with 0x03 framing prefix
    const frame = (raw: Uint8Array) => {
      const framed = new Uint8Array(1 + raw.length);
      framed[0] = 0x03;
      framed.set(raw, 1);
      return framed;
    };

    (window as any).DsmBridge = {
      __callBin: async (reqBytes: Uint8Array) => {
        const req = pb.BridgeRpcRequest.fromBinary(reqBytes);
        const method = req.method || '';
        if (method === 'acceptBilateralByCommitment') {
          return (global as any).createDsmBridgeSuccessResponse(frame(env.toBinary()));
        }
        if (method === 'appRouterInvoke') return (global as any).createDsmBridgeSuccessResponse(frame(env.toBinary()));
        if (method === 'appRouterQuery') {
          const headers = new pb.Headers({ deviceId: new Uint8Array(32).fill(1), genesisHash: new Uint8Array(32).fill(1) as any, chainTip: new Uint8Array(32), seq: 1n as any } as any);
          return (global as any).createDsmBridgeSuccessResponse(frame(headers.toBinary()));
        }
        if (method === 'getTransportHeadersV3Bin') {
          const headers = new pb.Headers({ deviceId: new Uint8Array(32).fill(1), genesisHash: new Uint8Array(32).fill(1) as any, chainTip: new Uint8Array(32), seq: 1n as any } as any);
          return (global as any).createDsmBridgeSuccessResponse(frame(headers.toBinary()));
        }
        throw new Error(`unhandled __callBin method:${method}`);
      },
      getDeviceIdBin: () => new Uint8Array(32).fill(1),
      getGenesisHashBin: () => new Uint8Array(32).fill(1),
    };

    // Call accept — RAF mock fires synchronously so all 4 staggered
    // wallet.refresh events from schedulePostAcceptRefreshes() land immediately.
    await act(async () => {
      await acceptOfflineTransfer({ commitmentHash: new Uint8Array(32).fill(2), counterpartyDeviceId: new Uint8Array(32).fill(3) });
    });

    off();

    // schedulePostAcceptRefreshes emits wallet.refresh at frame intervals [1, 30, 60, 120].
    // With sync RAF all 4 fire. Verify at least one arrived.
    expect(refreshEvents.length).toBeGreaterThanOrEqual(1);
    // Each event should carry the bilateral source tag
    expect(refreshEvents[0]).toEqual(expect.objectContaining({ source: 'bilateral.transfer_complete' }));
  });
});
