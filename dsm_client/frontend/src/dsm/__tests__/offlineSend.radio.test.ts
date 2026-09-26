// SPDX-License-Identifier: Apache-2.0
// The frontend makes no radio decisions. An offline send is one router call —
// `wallet.sendOffline` — and the native side advertises, scans and connects as
// the dispatch needs. The send used to set the advertised identity, start
// advertising and scanning through host requests, and sleep 1.5 s first,
// swallowing every failure.

/* eslint-disable @typescript-eslint/no-explicit-any */
import * as pb from '../../proto/dsm_app_pb';
import { emit, initializeEventBridge } from '../EventBridge';
import { offlineSend } from '../transactions';
import { encodeBase32Crockford } from '../../utils/textId';

const COMMITMENT = new Uint8Array(32).fill(0x5c);
const PEER = new Uint8Array(32).fill(9);

function framed(envelope: pb.Envelope): Uint8Array {
  const bytes = envelope.toBinary();
  const out = new Uint8Array(1 + bytes.length);
  out[0] = 0x03;
  out.set(bytes, 1);
  return out;
}

/** What the page sent over the port: each RPC's method, and each router call's name. */
function recordingBridge() {
  const methods: string[] = [];
  const routerCalls: string[] = [];
  (window as any).DsmBridge = {
    __binary: true,
    sendMessageBin: async (reqBytes: Uint8Array) => {
      const req = pb.BridgeRpcRequest.fromBinary(reqBytes);
      methods.push(req.method);
      if (req.method !== 'nativeBoundaryIngress') {
        return (global as any).createDsmBridgeErrorResponse(`no ${req.method} here`);
      }
      const payload = req.payload.case === 'bytes' ? req.payload.value.data : new Uint8Array(0);
      const op = pb.IngressRequest.fromBinary(payload).operation;
      const name = op.case === 'routerInvoke' || op.case === 'routerQuery' ? op.value.method : String(op.case);
      routerCalls.push(name);
      const answer = name === 'wallet.sendOffline'
        ? framed(new pb.Envelope({
          version: 3,
          payload: {
            case: 'bilateralPrepareResponse',
            value: new pb.BilateralPrepareResponse({ commitmentHash: new pb.Hash32({ v: COMMITMENT }) }),
          },
        }))
        : new Uint8Array(0);
      return (global as any).createDsmBridgeSuccessResponse(
        new pb.IngressResponse({ result: { case: 'okBytes', value: answer } }).toBinary(),
      );
    },
  };
  return { methods, routerCalls };
}

describe('offline send: the radio is native’s', () => {
  beforeEach(() => {
    initializeEventBridge();
  });

  test('an offline send asks for the send and nothing else — no host request, no identity relay, no wait', async () => {
    const seen = recordingBridge();

    const pending = offlineSend({ to: encodeBase32Crockford(PEER), amount: '1', tokenId: 'ERA' } as any);
    // The send reaches Rust at once: nothing is awaited on a timer first.
    for (let i = 0; i < 10 && !seen.routerCalls.includes('wallet.sendOffline'); i++) {
      await Promise.resolve();
    }
    expect(seen.routerCalls).toEqual(['wallet.sendOffline']);

    // Rust announces the completed transfer; the send finishes on it.
    const note = new pb.BilateralEventNotification({
      eventType: pb.BilateralEventType.BILATERAL_EVENT_TRANSFER_COMPLETE,
      commitmentHash: COMMITMENT,
      counterpartyDeviceId: PEER,
      status: 'completed',
    });
    emit('bilateral.event', new Uint8Array(note.toBinary()));
    await expect(pending).resolves.toEqual(expect.objectContaining({ accepted: true }));
    // Whatever the send started has reached the port by now.
    await new Promise((r) => setTimeout(r, 0));

    // Every request was a router call through the ingress boundary: no
    // nativeHostRequest (advertise / scan) and no setBleIdentityForAdvertising.
    expect(new Set(seen.methods)).toEqual(new Set(['nativeBoundaryIngress']));
  });
});
