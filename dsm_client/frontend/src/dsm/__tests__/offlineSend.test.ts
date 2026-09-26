// SPDX-License-Identifier: MIT OR Apache-2.0

import * as dsm from '../index';
import * as pb from '../../proto/dsm_app_pb';
import { emit } from '../EventBridge';

function wrapSuccessEnvelope(data: Uint8Array): Uint8Array {
  const ingressResp = new pb.IngressResponse({
    result: { case: 'okBytes', value: data },
  });
  return (global as any).createDsmBridgeSuccessResponse(ingressResp.toBinary());
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
  if (req.method !== 'nativeBoundaryIngress') {
    throw new Error(`expected nativeBoundaryIngress method, got ${req.method}`);
  }
  if (req.payload.case !== 'bytes') {
    throw new Error(`expected bytes payload, got ${req.payload.case}`);
  }
  const ingressReq = pb.IngressRequest.fromBinary(req.payload.value.data);
  if (ingressReq.operation.case !== 'routerInvoke') {
    throw new Error(`expected routerInvoke operation, got ${ingressReq.operation.case}`);
  }
  return {
    route: ingressReq.operation.value.method,
    args: ingressReq.operation.value.args,
  };
}

function prepareResponseBytes(commitmentHash: Uint8Array): Uint8Array {
  const env = new pb.Envelope({
    version: 3,
    payload: {
      case: 'bilateralPrepareResponse',
      value: new pb.BilateralPrepareResponse({
        commitmentHash: new pb.Hash32({ v: new Uint8Array(commitmentHash) }),
      }),
    },
  });
  return wrapSuccessEnvelope(frameEnvelope(env));
}

describe('offlineSend', () => {
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

  // The send is what the user asked for, byte for byte, and nothing else:
  // where the counterparty's phone is over BLE is Rust's to know.
  test('an offline send reaches wallet.sendOffline as what the user asked for, and nothing else', async () => {
    const to = new Uint8Array(32).fill(0x22);
    const commitmentHash = new Uint8Array(32).fill(0x99);

    (global as any).window.DsmBridge.sendMessageBin = async (reqBytes: Uint8Array) => {
      const { route, args } = decodeRouterInvoke(reqBytes);
      expect(route).toBe('wallet.sendOffline');
      const argPack = pb.ArgPack.fromBinary(args);
      expect(argPack.body).toEqual(new pb.OfflineTransferRequest({
        counterpartyDeviceId: to,
        tokenId: 'ERA',
        amount: '1',
        memo: '',
      }).toBinary());
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

  test('surfaces bilateral prepare rejects from wallet.sendOffline', async () => {
    const to = new Uint8Array(32).fill(0x44);

    (global as any).window.DsmBridge.sendMessageBin = async (reqBytes: Uint8Array) => {
      const { route } = decodeRouterInvoke(reqBytes);
      expect(route).toBe('wallet.sendOffline');
      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'bilateralPrepareReject',
          value: new pb.BilateralPrepareReject({ reason: 'offline rejected' }),
        },
      });
      return wrapSuccessEnvelope(frameEnvelope(env));
    };

    await expect(dsm.offlineSend({ to, amount: 1n, tokenId: 'ERA' })).resolves.toEqual(
      expect.objectContaining({ accepted: false, result: 'offline rejected' }),
    );
  });
});
