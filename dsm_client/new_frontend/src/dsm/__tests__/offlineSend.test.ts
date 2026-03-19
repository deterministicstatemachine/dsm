import * as dsm from '../index';
import * as pb from '../../proto/dsm_app_pb';
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

function decodeRouterInvoke(reqBytes: Uint8Array): { route: string; args: Uint8Array } {
  const req = pb.BridgeRpcRequest.fromBinary(reqBytes);
  if (req.payload.case !== 'appRouter') {
    throw new Error(`expected appRouter payload, got ${req.payload.case}`);
  }
  return {
    route: req.payload.value.methodName,
    args: req.payload.value.args,
  };
}

function prepareResponseBytes(commitmentHash: Uint8Array): Uint8Array {
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
}

describe('offlineSend', () => {
  beforeEach(() => {
    jest.restoreAllMocks();
    (global as any).window = (global as any).window || {};
    (global as any).window.DsmBridge = (global as any).window.DsmBridge || {};
  });

  test('delegates missing BLE address resolution to wallet.sendOffline', async () => {
    const to = new Uint8Array(32).fill(0x22);
    const commitmentHash = new Uint8Array(32).fill(0x99);

    (global as any).window.DsmBridge.__callBin = async (reqBytes: Uint8Array) => {
      const { route, args } = decodeRouterInvoke(reqBytes);
      expect(route).toBe('wallet.sendOffline');
      const argPack = pb.ArgPack.fromBinary(args);
      const request = pb.BilateralPrepareRequest.fromBinary(argPack.body);
      expect(request.counterpartyDeviceId).toEqual(to);
      expect(request.transferAmount).toBe(1n);
      expect(request.tokenIdHint).toBe('ERA');
      expect(request.memoHint).toBe('');
      expect(request.bleAddress).toBe('');
      return prepareResponseBytes(commitmentHash);
    };

    const promise = dsm.offlineSend({ to, amount: 1n, tokenId: 'ERA' });
    await new Promise((resolve) => setTimeout(resolve, 0));
    emit('bilateral.event', new pb.BilateralEventNotification({
      eventType: pb.BilateralEventType.BILATERAL_EVENT_TRANSFER_COMPLETE,
      commitmentHash,
      status: 'completed',
      message: 'done',
    }).toBinary());

    await expect(promise).resolves.toEqual(expect.objectContaining({ accepted: true }));
  });

  test('passes provided BLE address to wallet.sendOffline', async () => {
    const to = new Uint8Array(32).fill(0x33);
    const bleAddress = 'AA:BB:CC:DD:EE:FF';
    const commitmentHash = new Uint8Array(32).fill(0x55);

    (global as any).window.DsmBridge.__callBin = async (reqBytes: Uint8Array) => {
      const { route, args } = decodeRouterInvoke(reqBytes);
      expect(route).toBe('wallet.sendOffline');
      const request = pb.BilateralPrepareRequest.fromBinary(pb.ArgPack.fromBinary(args).body);
      expect(request.counterpartyDeviceId).toEqual(to);
      expect(request.bleAddress).toBe(bleAddress);
      return prepareResponseBytes(commitmentHash);
    };

    const promise = dsm.offlineSend({ to, amount: 7n, tokenId: 'ERA', bleAddress });
    await new Promise((resolve) => setTimeout(resolve, 0));
    emit('bilateral.event', new pb.BilateralEventNotification({
      eventType: pb.BilateralEventType.BILATERAL_EVENT_TRANSFER_COMPLETE,
      commitmentHash,
      status: 'completed',
      message: 'done',
    }).toBinary());

    await expect(promise).resolves.toEqual(expect.objectContaining({ accepted: true }));
  });

  test('surfaces bilateral prepare rejects from wallet.sendOffline', async () => {
    const to = new Uint8Array(32).fill(0x44);

    (global as any).window.DsmBridge.__callBin = async (reqBytes: Uint8Array) => {
      const { route } = decodeRouterInvoke(reqBytes);
      expect(route).toBe('wallet.sendOffline');
      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'bilateralPrepareReject',
          value: new pb.BilateralPrepareReject({ reason: 'offline rejected' }),
        },
      });
      return wrapSuccessEnvelope(withRouterPrefix(frameEnvelope(env)));
    };

    await expect(dsm.offlineSend({ to, amount: 1n, tokenId: 'ERA' })).resolves.toEqual(
      expect.objectContaining({ accepted: false, result: 'offline rejected' }),
    );
  });
});
