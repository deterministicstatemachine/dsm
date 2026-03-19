/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// E2E-style test: start offlineSend and simulate a BilateralPrepareResponse arriving over BLE

// Mock getContacts to avoid protobuf decoding issues
jest.mock('../dsm/index', () => ({
  ...jest.requireActual('../dsm/index'),
  getContacts: jest.fn().mockResolvedValue({
    contacts: [{
      alias: 'Bob',
      deviceId: new Uint8Array(32).fill(9),
      genesisHash: new Uint8Array(32).fill(3),
      chainTip: new Uint8Array(32).fill(4),
      bleAddress: 'AA:BB:CC:DD:EE:FF',
    }],
  }),
}));

import * as pb from '../proto/dsm_app_pb';
import { emit, initializeEventBridge } from '../dsm/EventBridge';
import { offlineSend } from '../dsm/index';
import { encodeBase32Crockford as base32CrockfordEncode } from '../utils/textId';
import { bridgeEvents } from '../bridge/bridgeEvents';

function zeroHash32(): pb.Hash32 { return new pb.Hash32({ v: new Uint8Array(32) as any }); }

// Helper to wrap response in DSM_BRIDGE format
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

describe('E2E: Offline BLE exchange -> wallet refresh', () => {
  beforeEach(() => {
    // Ensure event bridge installed
    initializeEventBridge();
  });

  test('offline send then receive BilateralPrepareResponse triggers wallet refresh', async () => {
    // Mock bridge methods
    (global as any).window = (global as any).window || {};
    const ALICE_DEVICE_ID = new Uint8Array(32).fill(1);
    const ALICE_GENESIS = new Uint8Array(32).fill(2);
    const BOB_DEVICE_ID = new Uint8Array(32).fill(9);
    const BOB_GENESIS = new Uint8Array(32).fill(3);
    const BOB_TIP = new Uint8Array(32).fill(4);
    const recipient = BOB_DEVICE_ID;

    // Mock bridge methods
    (global as any).window = (global as any).window || {};
    (global as any).window.DsmBridge = {
      __binary: true,
      sendMessageBin: async (reqBytes: Uint8Array) => {
        const req = pb.BridgeRpcRequest.fromBinary(reqBytes);
        const method = req.method || '';
        const data = req.payload?.case === 'bytes' ? req.payload.value.data : new Uint8Array(0);
        if (method === 'appRouterQuery') {
          const enc = new TextEncoder();
          const path = enc.encode('contacts.list');
          if (data.length === 4 + path.length && data[0] === 0 && data[1] === 0 && data[2] === 0 && data[3] === path.length) {
            const contactsListResponse = new pb.ContactsListResponse({
              contacts: [
                {
                  alias: 'Bob',
                  deviceId: BOB_DEVICE_ID,
                  genesisHash: new pb.Hash32({ v: BOB_GENESIS } as any),
                  chainTip: new pb.Hash32({ v: BOB_TIP } as any),
                  bleAddress: 'AA:BB:CC:DD:EE:FF',
                },
              ],
            } as any);
            // Return Envelope-wrapped response with framing byte and router prefix
            const env = new pb.Envelope({
              version: 3,
              payload: { case: 'contactsListResponse', value: contactsListResponse },
            } as any);
            const framed = new Uint8Array([0x03, ...env.toBinary()]);
            return wrapSuccessEnvelope(withRouterPrefix(framed));
          }
          return wrapSuccessEnvelope(withRouterPrefix(new Uint8Array(0)));
        }
        throw new Error(`unhandled sendMessageBin: ${reqBytes.length} bytes`);
      },
      __callBin: async (reqBytes: Uint8Array) => {
        const req = pb.BridgeRpcRequest.fromBinary(reqBytes);
        const method = req.method || '';
        const payload = req.payload?.case === 'bytes' ? req.payload.value.data : new Uint8Array(0);
        if (method === 'getTransportHeadersV3Bin') {
          const headersBytes = new pb.Headers({
            deviceId: ALICE_DEVICE_ID,
            genesisHash: ALICE_GENESIS as any,
            chainTip: new Uint8Array(32),
            seq: 1n as any,
          }).toBinary();
          return wrapSuccessEnvelope(headersBytes);
        }
        if (method === 'getSigningPublicKeyBin') {
          return wrapSuccessEnvelope(new Uint8Array(64).fill(0x5a));
        }
        if (method === 'appRouterQuery') {
          const contactsListResponse = new pb.ContactsListResponse({
            contacts: [
              {
                alias: 'Bob',
                deviceId: BOB_DEVICE_ID,
                genesisHash: new pb.Hash32({ v: BOB_GENESIS } as any),
                chainTip: new pb.Hash32({ v: BOB_TIP } as any),
                bleAddress: 'AA:BB:CC:DD:EE:FF',
              },
            ],
          } as any);
          // Return Envelope-wrapped response with framing byte and router prefix
          const env = new pb.Envelope({
            version: 3,
            payload: { case: 'contactsListResponse', value: contactsListResponse },
          } as any);
          const framed = new Uint8Array([0x03, ...env.toBinary()]);
          return wrapSuccessEnvelope(withRouterPrefix(framed));
        }
        if (method === 'appRouterInvoke') {
          // bilateralOfflineSendBin routes through router invoke.
          // Return a BilateralPrepareResponse envelope with a commitment hash
          // so offlineSend can proceed.
          const resp = new pb.BilateralPrepareResponse({
            commitmentHash: new pb.Hash32({ v: new Uint8Array(32) } as any), // Fixed: should be Hash32 object
            localSignature: new Uint8Array(64),
          });
          const rx = new pb.UniversalRx({
            results: [
              new pb.OpResult({
                accepted: true,
                result: new pb.ResultPack({
                  codec: pb.Codec.PROTO,
                  body: resp.toBinary(),
                } as any),
              } as any),
            ],
          } as any);
          const env = new pb.Envelope({
            version: 3,
            payload: { case: 'universalRx', value: rx },
          } as any);
          return wrapSuccessEnvelope(withRouterPrefix(frameEnvelope(env)));
        }
        throw new Error(`unhandled __callBin method: ${method} (payloadLen=${payload.length})`);
      },
      // Some call sites read base32 Crockford strings from these getters.
      getDeviceIdBin: () => base32CrockfordEncode(ALICE_DEVICE_ID),
      getGenesisHashBin: () => base32CrockfordEncode(ALICE_GENESIS),
      getTransportHeadersV3Bin: () =>
        new pb.Headers({ deviceId: ALICE_DEVICE_ID, genesisHash: ALICE_GENESIS as any, chainTip: new Uint8Array(32) }).toBinary(),
    };

    // Start offline send
    const offlineSendPromise = offlineSend({ to: recipient, amount: '1', tokenId: 'ERA', bleAddress: 'AA:BB:CC:DD:EE:FF' });

    // Emit TRANSFER_COMPLETE event to resolve offlineSend
    await new Promise((r) => setTimeout(r, 0));
    const completeNote = new pb.BilateralEventNotification({
      eventType: 4,
      commitmentHash: new Uint8Array(32),
      counterpartyDeviceId: recipient,
      status: 'accepted',
      message: '',
    });
    emit('bilateral.event', new Uint8Array(completeNote.toBinary()));

    const res = await offlineSendPromise;
    expect((res as any).accepted).toBe(true);

    // Listen for wallet refresh
    const handler = jest.fn();
    const unsubscribe = bridgeEvents.on('wallet.refresh', handler as any);

    // Craft BilateralPrepareResponse envelope arriving over BLE
    const resp = new pb.BilateralPrepareResponse({ commitmentHash: zeroHash32(), localSignature: new Uint8Array(64) });
    const env = new pb.Envelope({ version: 3, headers: new pb.Headers({ deviceId: ALICE_DEVICE_ID, genesisHash: ALICE_GENESIS as any, chainTip: new Uint8Array(32) }), payload: { case: 'bilateralPrepareResponse', value: resp } });
    const rawBytes = env.toBinary();
    const bytes = new Uint8Array(1 + rawBytes.length);
    bytes[0] = 0x03;
    bytes.set(rawBytes, 1);

    // Emit through the real DOM ingress path that EventBridge listens to.
    window.dispatchEvent(new CustomEvent('dsm-event-bin', {
      detail: { topic: 'ble.envelope.bin', payload: bytes },
    }));

    expect(handler).toHaveBeenCalled();
    const calledWith = handler.mock.calls.find(c => c && c[0] && typeof c[0].source === 'string' && c[0].source.indexOf('bilateral') >= 0);
    expect(Boolean(calledWith)).toBe(true);
    unsubscribe();
  });
});
