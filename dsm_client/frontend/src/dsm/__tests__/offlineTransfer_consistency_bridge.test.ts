// SPDX-License-Identifier: MIT OR Apache-2.0

import * as pb from '../../proto/dsm_app_pb';
import * as dsm from '../index';
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
  if (req.method !== 'nativeBoundaryIngress' || req.payload.case !== 'bytes') {
    throw new Error(`expected nativeBoundaryIngress/bytes, got ${req.method}/${req.payload.case}`);
  }
  const ingressReq = pb.IngressRequest.fromBinary(req.payload.value.data);
  if (ingressReq.operation.case !== 'routerInvoke') {
    throw new Error(`expected routerInvoke, got ${ingressReq.operation.case}`);
  }
  return { route: ingressReq.operation.value.method, args: ingressReq.operation.value.args };
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

  // The token is forwarded exactly as chosen: Rust canonicalizes it
  // (`canonicalize_token_id`) and refuses one that names nothing.
  test('an offline send reaches wallet.sendOffline with the token and memo as given', async () => {
    const to = new Uint8Array(32).fill(0xcc);
    const commitmentHash = new Uint8Array(32).fill(0x77);

    (global as any).window.DsmBridge.sendMessageBin = async (reqBytes: Uint8Array) => {
      const { route, args } = decodeRouterInvoke(reqBytes);
      expect(route).toBe('wallet.sendOffline');

      const argPack = pb.ArgPack.fromBinary(args);
      const request = pb.OfflineTransferRequest.fromBinary(argPack.body);
      expect(request.counterpartyDeviceId).toEqual(to);
      expect(request.amount).toBe('5');
      expect(request.tokenId).toBe('DBTC');
      expect(request.memo).toBe('hi');

      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'bilateralPrepareResponse',
          value: new pb.BilateralPrepareResponse({
            commitmentHash: new pb.Hash32({ v: commitmentHash }),
          }),
        },
      });
      return wrapSuccessEnvelope(frameEnvelope(env));
    };

    const promise = dsm.offlineSend({ to, amount: 5n, tokenId: 'DBTC', memo: 'hi' });
    await new Promise((resolve) => setTimeout(resolve, 0));
    emit('bilateral.event', new pb.BilateralEventNotification({
      eventType: pb.BilateralEventType.BILATERAL_EVENT_TRANSFER_COMPLETE,
      commitmentHash,
      status: 'completed',
      message: 'done',
    }).toBinary());

    await expect(promise).resolves.toEqual(expect.objectContaining({ accepted: true }));
  });

  test('dBTC lowercase canonical token stays canonical', async () => {
    const to = new Uint8Array(32).fill(0xdd);
    const commitmentHash = new Uint8Array(32).fill(0x33);

    (global as any).window.DsmBridge.sendMessageBin = async (reqBytes: Uint8Array) => {
      const { args } = decodeRouterInvoke(reqBytes);
      const argPack = pb.ArgPack.fromBinary(args);
      expect(pb.OfflineTransferRequest.fromBinary(argPack.body).tokenId).toBe('dBTC');

      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'bilateralPrepareResponse',
          value: new pb.BilateralPrepareResponse({
            commitmentHash: new pb.Hash32({ v: commitmentHash }),
          }),
        },
      });
      return wrapSuccessEnvelope(frameEnvelope(env));
    };

    const promise = dsm.offlineSend({ to, amount: 7n, tokenId: 'dBTC', memo: 'ok' });
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
