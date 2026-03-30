import * as pb from '../../proto/dsm_app_pb';
import * as dsm from '../index';
import { emit } from '../EventBridge';

function wrapSuccessEnvelope(data: Uint8Array): Uint8Array {
  return (global as any).createDsmBridgeSuccessResponse(data);
}

function withRouterPrefix(data: Uint8Array): Uint8Array {
  const out = new Uint8Array(8 + data.length);
  out.set(data, 8);
  return out;
}

function frameEnvelope(envelope: pb.Envelope): Uint8Array {
  const bytes = envelope.toBinary();
  const framed = new Uint8Array(1 + bytes.length);
  framed[0] = 0x03;
  framed.set(bytes, 1);
  return framed;
}

describe('offline transfer sender/recipient consistency through WebView bridge', () => {
  let warnSpy: jest.SpyInstance;

  beforeEach(() => {
    jest.restoreAllMocks();
    warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    (global as any).window = (global as any).window || {};
    (global as any).window.DsmBridge = (global as any).window.DsmBridge || {};
  });

  afterEach(() => {
    warnSpy.mockRestore();
  });

  test('dBTC offline send is encoded as wallet.sendOffline with token and memo hints', async () => {
    const to = new Uint8Array(32).fill(0xcc);
    const bleAddress = 'AA:BB:CC:DD:EE:FF';
    const commitmentHash = new Uint8Array(32).fill(0x77);

    (global as any).window.DsmBridge.__callBin = async (reqBytes: Uint8Array) => {
      const req = pb.BridgeRpcRequest.fromBinary(reqBytes);
      expect(req.payload.case).toBe('appRouter');
      expect(req.payload.value.methodName).toBe('wallet.sendOffline');

      const argPack = pb.ArgPack.fromBinary(req.payload.value.args);
      const prepare = pb.BilateralPrepareRequest.fromBinary(argPack.body);
      expect(prepare.counterpartyDeviceId).toEqual(to);
      expect(prepare.transferAmountDisplay).toBe('5');
      expect(prepare.bleAddress).toBe(bleAddress);
      expect(prepare.tokenIdHint).toBe('dBTC');
      expect(prepare.memoHint).toBe('hi');

      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'bilateralPrepareResponse',
          value: new pb.BilateralPrepareResponse({
            commitmentHash: new pb.Hash32({ v: commitmentHash }),
          }),
        },
      });
      return wrapSuccessEnvelope(withRouterPrefix(frameEnvelope(env)));
    };

    const promise = dsm.offlineSend({ to, amount: 5n, tokenId: 'DBTC', bleAddress, memo: 'hi' } as any);
    await new Promise((resolve) => setTimeout(resolve, 0));
    emit('bilateral.event', new pb.BilateralEventNotification({
      eventType: pb.BilateralEventType.BILATERAL_EVENT_TRANSFER_COMPLETE,
      commitmentHash,
      status: 'completed',
      message: 'done',
    }).toBinary());

    await expect(promise).resolves.toEqual(expect.objectContaining({ accepted: true }));
  });

  test('dBTC lowercase canonical token hint stays canonical', async () => {
    const to = new Uint8Array(32).fill(0xdd);
    const bleAddress = 'AA:BB:CC:DD:EE:11';
    const commitmentHash = new Uint8Array(32).fill(0x33);

    (global as any).window.DsmBridge.__callBin = async (reqBytes: Uint8Array) => {
      const req = pb.BridgeRpcRequest.fromBinary(reqBytes);
      const argPack = pb.ArgPack.fromBinary(req.payload.value.args);
      const prepare = pb.BilateralPrepareRequest.fromBinary(argPack.body);
      expect(prepare.tokenIdHint).toBe('dBTC');

      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'bilateralPrepareResponse',
          value: new pb.BilateralPrepareResponse({
            commitmentHash: new pb.Hash32({ v: commitmentHash }),
          }),
        },
      });
      return wrapSuccessEnvelope(withRouterPrefix(frameEnvelope(env)));
    };

    const promise = dsm.offlineSend({ to, amount: 7n, tokenId: 'dBTC', bleAddress, memo: 'ok' } as any);
    await new Promise((resolve) => setTimeout(resolve, 0));
    emit('bilateral.event', new pb.BilateralEventNotification({
      eventType: pb.BilateralEventType.BILATERAL_EVENT_TRANSFER_COMPLETE,
      commitmentHash,
      status: 'completed',
      message: 'done',
    }).toBinary());

    await expect(promise).resolves.toEqual(expect.objectContaining({ accepted: true }));
  });
});
