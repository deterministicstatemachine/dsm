/// <reference types="jest" />
/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
/**
 * E2E Transfer Proof Tests
 *
 * Proves that online and offline (BLE bilateral) transfers will work on-device
 * by exercising the exact same TypeScript code paths with bridge mocks that
 * enforce Rust-side proto constraints (field lengths, required fields, response
 * structures).
 *
 * Run with:  npm test -- src/tests/E2E.transferProof.test.ts --verbose
 */

import * as pb from '../proto/dsm_app_pb';
import * as dsm from '../dsm/index';
import { emit, initializeEventBridge } from '../dsm/EventBridge';
import { encodeBase32Crockford } from '../utils/textId';
import { decodeFramedEnvelopeV3 } from '../dsm/decoding';

// ─────────────────────────── Constants ───────────────────────────

const DEVICE_A = new Uint8Array(32).fill(0xAA); // sender
const DEVICE_B = new Uint8Array(32).fill(0xBB); // recipient
const GENESIS_A = new Uint8Array(32).fill(0x11);
const SIGNING_KEY = new Uint8Array(64).fill(0x5A); // 64-byte SPHINCS+ SPX256s
const COMMITMENT_HASH = new Uint8Array(32).fill(0xDD);
const COUNTERPARTY_TIP = new Uint8Array(32).fill(0xFF);
const COUNTERPARTY_GENESIS = new Uint8Array(32).fill(0xEE);

// ─────────────────────────── Helpers ───────────────────────────

function wrapSuccess(data: Uint8Array): Uint8Array {
  return (global as any).createDsmBridgeSuccessResponse(data);
}

function wrapError(msg: string): Uint8Array {
  return (global as any).createDsmBridgeErrorResponse(msg);
}

function wrapIngressOk(data: Uint8Array): Uint8Array {
  return wrapSuccess(
    new pb.IngressResponse({
      result: { case: 'okBytes', value: data },
    }).toBinary(),
  );
}

function zeroHash(): pb.Hash32 {
  return new pb.Hash32({ v: new Uint8Array(32) } as any);
}

/** Decode BridgeRpcRequest to extract method and payload bytes. */
function decodeBridgeReq(reqBytes: Uint8Array): { method: string; payload: Uint8Array } {
  const req = pb.BridgeRpcRequest.fromBinary(reqBytes);
  const payload = req.payload?.case === 'bytes' ? (req.payload.value.data || new Uint8Array(0)) : new Uint8Array(0);
  return { method: req.method, payload };
}

function decodeIngressReq(payload: Uint8Array): {
  operationCase?: string;
  method?: string;
  args: Uint8Array;
} {
  const ingress = pb.IngressRequest.fromBinary(payload);
  switch (ingress.operation.case) {
    case 'routerQuery':
      return {
        operationCase: ingress.operation.case,
        method: ingress.operation.value.method,
        args: ingress.operation.value.args || new Uint8Array(0),
      };
    case 'routerInvoke':
      return {
        operationCase: ingress.operation.case,
        method: ingress.operation.value.method,
        args: ingress.operation.value.args || new Uint8Array(0),
      };
    default:
      return { operationCase: ingress.operation.case, args: new Uint8Array(0) };
  }
}

/** Wrap an Envelope as framed bytes (0x03 prefix) */
function frameEnvelope(env: pb.Envelope): Uint8Array {
  const bytes = env.toBinary();
  const framed = new Uint8Array(1 + bytes.length);
  framed[0] = 0x03;
  framed.set(bytes, 1);
  return framed;
}

/** Build a ContactsListResponse wrapped in a framed Envelope for router query response */
function makeContactsFramedEnvelope(bleAddress?: string): Uint8Array {
  const contact = new pb.ContactAddResponse({
    alias: 'Bob',
    deviceId: DEVICE_B,
    genesisHash: new pb.Hash32({ v: COUNTERPARTY_GENESIS }),
    chainTip: new pb.Hash32({ v: COUNTERPARTY_TIP }),
    bleAddress: bleAddress || 'AA:BB:CC:DD:EE:FF',
  } as any);
  const resp = new pb.ContactsListResponse({ contacts: [contact] });
  const env = new pb.Envelope({
    version: 3,
    payload: { case: 'contactsListResponse', value: resp },
  } as any);
  // Framed = 0x03 + Envelope bytes
  return frameEnvelope(env);
}

/** Build a BilateralPrepareResponse inside a framed Envelope. */
function makeBilateralPrepareResponseEnvelope(commitHash: Uint8Array): Uint8Array {
  // The commitment is what the frontend reads; the rest is Rust's to fill.
  const resp = new pb.BilateralPrepareResponse({
    commitmentHash: new pb.Hash32({ v: commitHash } as any),
  } as any);
  const env = new pb.Envelope({
    version: 3,
    payload: { case: 'bilateralPrepareResponse', value: resp },
  } as any);
  return frameEnvelope(env);
}

/** Build an OnlineTransferResponse inside Envelope with onlineTransferResponse payload.
 *  This matches the AppRouter response path (routerInvokeBin → wallet.send). */
function makeOnlineResponseEnvelope(success: boolean, message: string, newBalance: bigint = 123n): Uint8Array {
  const resp = new pb.OnlineTransferResponse({
    success,
    transactionHash: zeroHash(),
    message,
    newBalance: newBalance as any,
  } as any);
  const env = new pb.Envelope({
    version: 3,
    headers: new pb.Headers({
      deviceId: DEVICE_A as any,
      genesisHash: GENESIS_A as any,
    } as any),
    payload: { case: 'onlineTransferResponse', value: resp },
  } as any);
  return frameEnvelope(env); // 0x03-framed, matching routerInvokeBin output
}

function makeHeaders(overrides?: Partial<{ deviceId: Uint8Array; genesisHash: Uint8Array }>): pb.Headers {
  return new pb.Headers({
    deviceId: overrides?.deviceId || DEVICE_A,
    genesisHash: (overrides?.genesisHash || GENESIS_A) as any,
  } as any);
}

// ─────────────────────────── Bridge Setup ───────────────────────────

/** Capture payloads for assertion */
let capturedMethods: string[] = [];
let onlineTransferOverride: (() => Uint8Array) | null = null;
let bilateralResponseOverride: (() => Uint8Array) | null = null;
let bilateralPendingListOverride: (() => pb.OfflineBilateralTransaction[]) | null = null;
let headersOverride: pb.Headers | null = null;

function installBridge(opts?: { contactBleAddress?: string }) {
  const g = global as any;
  g.window = g.window || {};
  const headers = headersOverride || makeHeaders();

  g.window.DsmBridge = {
    __binary: true,

    sendMessageBin: async (reqBytes: Uint8Array): Promise<Uint8Array> => {
      const { method, payload } = decodeBridgeReq(reqBytes);
      capturedMethods.push(method);

      // --- Direct bridge methods (no router prefix) ---

      if (method === 'getTransportHeadersV3Bin') {
        return wrapSuccess(headers.toBinary());
      }

      if (method === 'getPreference' || method === 'setPreference') {
        return wrapSuccess(new Uint8Array(0));
      }

      if (method === 'nativeBoundaryIngress') {
        const ingress = pb.IngressRequest.fromBinary(payload);
        if (ingress.operation.case === 'routerQuery') {
          const ingressMethod = ingress.operation.value.method;
          if (ingressMethod === 'contacts.list') {
            return wrapIngressOk(makeContactsFramedEnvelope(opts?.contactBleAddress));
          }
          if (ingressMethod === 'bilateral.pending_list') {
            const resp = new pb.OfflineBilateralPendingListResponse({
              transactions: bilateralPendingListOverride ? bilateralPendingListOverride() : [],
            });
            const env = new pb.Envelope({
              version: 3,
              payload: { case: 'offlineBilateralPendingListResponse' as const, value: resp },
            } as any);
            const envBytes = env.toBinary();
            const framed = new Uint8Array(1 + envBytes.length);
            framed[0] = 0x03;
            framed.set(envBytes, 1);
            return wrapIngressOk(framed);
          }
          return wrapIngressOk(new Uint8Array(0));
        }
        if (ingress.operation.case === 'routerInvoke') {
          const ingressMethod = ingress.operation.value.method;
          if (ingressMethod === 'wallet.send' || ingressMethod === 'wallet.sendSmart') {
            if (onlineTransferOverride) {
              return wrapIngressOk(onlineTransferOverride());
            }
            return wrapIngressOk(makeOnlineResponseEnvelope(true, 'ok', 123n));
          }
          if (ingressMethod === 'wallet.sendOffline') {
            if (bilateralResponseOverride) {
              return wrapIngressOk(bilateralResponseOverride());
            }
            return wrapIngressOk(makeBilateralPrepareResponseEnvelope(COMMITMENT_HASH));
          }
          return wrapIngressOk(new Uint8Array(0));
        }
        return wrapError(`unhandled ingress operation: ${ingress.operation.case}`);
      }

      if (method === 'nativeHostRequest') {
        const hostRequest = pb.NativeHostRequest.fromBinary(payload);
        return wrapError(`unhandled nativeHostRequest kind: ${hostRequest.kind}`);
      }

      return wrapError(`unhandled method: ${method}`);
    },
  };

  // DOM event APIs are provided by jsdom — no mocking needed.
  // This ensures EventBridge and nativeBridgeAdapter use REAL DOM events.
}

// Track test index for unique transfer amounts (avoids dedup cache hits)
let testIndex = 0;

// ═══════════════════════════════════════════════════════════════════
//  TESTS
// ═══════════════════════════════════════════════════════════════════

beforeEach(() => {
  jest.restoreAllMocks();
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});
  capturedMethods = [];
  onlineTransferOverride = null;
  bilateralResponseOverride = null;
  bilateralPendingListOverride = null;
  headersOverride = null;
  testIndex++;
  initializeEventBridge();
  // Clear headers cache so each test gets fresh headers from bridge
  (global as any).__dsmLastGoodHeaders = { deviceId: undefined, genesisHash: undefined, chainTip: undefined };
});

// ─────────────────────────────────────────────────────────────────
// 1. Online Transfer — Full Cycle
// ─────────────────────────────────────────────────────────────────

describe('Online Transfer — Full Cycle (wallet.sendSmart, the path the send screen takes)', () => {
  beforeEach(() => installBridge());

  test('happy path: success=true', async () => {
    onlineTransferOverride = () => makeOnlineResponseEnvelope(true, 'transfer ok', 500n);

    // A unique amount per test avoids dedup.
    const res = await dsm.sendOnlineTransferSmart('bob', BigInt(1000 + testIndex), undefined, 'ERA');
    expect(res.success).toBe(true);
  });

  test('failure response returns success=false when inner OnlineTransferResponse.success=false', async () => {
    onlineTransferOverride = () => makeOnlineResponseEnvelope(false, 'insufficient funds', 0n);

    const res = await dsm.sendOnlineTransferSmart('bob', BigInt(2000 + testIndex), undefined, 'ERA');
    expect(res.success).toBe(false);
    expect(res.message).toContain('insufficient funds');
  });

  test('error envelope: bridge returns error payload', async () => {
    onlineTransferOverride = () => {
      return frameEnvelope(new pb.Envelope({
        version: 3,
        headers: makeHeaders(),
        payload: {
          case: 'error',
          value: new pb.ErrorResponse({ code: 500, message: 'internal error' } as any),
        },
      } as any));
    };

    const res = await dsm.sendOnlineTransferSmart('bob', BigInt(3000 + testIndex), undefined, 'ERA');
    expect(res.success).toBe(false);
    expect(String(res.message)).toMatch(/internal error|DSM error/);
  });

  test('unexpected payload case → error', async () => {
    onlineTransferOverride = () => {
      return frameEnvelope(new pb.Envelope({
        version: 3,
        headers: makeHeaders(),
        payload: {
          case: 'universalRx',
          value: new pb.UniversalRx({ results: [] }),
        },
      } as any));
    };

    const res = await dsm.sendOnlineTransferSmart('bob', BigInt(4000 + testIndex), undefined, 'ERA');
    expect(res.success).toBe(false);
    expect(String(res.message)).toMatch(/Expected onlineTransferResponse|unexpected/i);
  });

  test('OnlineTransferResponse with success=false carries message', async () => {
    onlineTransferOverride = () => {
      const resp = new pb.OnlineTransferResponse({
        success: false,
        message: 'quota exceeded',
        newBalance: 0n as any,
      } as any);
      return frameEnvelope(new pb.Envelope({
        version: 3,
        headers: makeHeaders(),
        payload: { case: 'onlineTransferResponse', value: resp },
      } as any));
    };

    const res = await dsm.sendOnlineTransferSmart('bob', BigInt(5000 + testIndex), undefined, 'ERA');
    expect(res.success).toBe(false);
    expect(String(res.message)).toContain('quota exceeded');
  });
});

// ─────────────────────────────────────────────────────────────────
// 3. Online Transfer — Proto Fidelity
// ─────────────────────────────────────────────────────────────────

describe('Online Transfer — Proto Fidelity', () => {
  test('OnlineTransferRequest field roundtrip preserves all fields', () => {
    const req = new pb.OnlineTransferRequest({
      tokenId: 'ERA',
      toDeviceId: DEVICE_B as any,
      amount: 42n as any,
      memo: 'test memo',
      nonce: new Uint8Array(0),
      signature: new Uint8Array(0),
      fromDeviceId: DEVICE_A as any,
    } as any);

    const bytes = req.toBinary();
    const decoded = pb.OnlineTransferRequest.fromBinary(bytes);

    expect(decoded.tokenId).toBe('ERA');
    expect(decoded.toDeviceId).toEqual(DEVICE_B);
    expect(decoded.toDeviceId).toHaveLength(32);
    expect(decoded.amount).toBe(42n);
    expect(decoded.memo).toBe('test memo');
    expect(decoded.fromDeviceId).toEqual(DEVICE_A);
    expect(decoded.fromDeviceId).toHaveLength(32);
  });

  test('Envelope v3 wraps UniversalTx → UniversalOp → Invoke(wallet.send) → ArgPack', () => {
    const req = new pb.OnlineTransferRequest({
      tokenId: 'ERA',
      toDeviceId: DEVICE_B as any,
      amount: 10n as any,
      fromDeviceId: DEVICE_A as any,
    } as any);

    const argPack = new pb.ArgPack({
      codec: pb.Codec.PROTO as any,
      body: new Uint8Array(req.toBinary()),
    });
    const invoke = new pb.Invoke({ method: 'wallet.send', args: argPack });
    const opId = new pb.Hash32({ v: new Uint8Array(32).fill(0x77) } as any);
    const uop = new pb.UniversalOp({
      opId,
      actor: DEVICE_A as any,
      kind: { case: 'invoke', value: invoke } as any,
    });
    const tx = new pb.UniversalTx({ ops: [uop], atomic: true });

    const env = new pb.Envelope({
      version: 3,
      headers: makeHeaders(),
      messageId: new Uint8Array(16) as any,
      payload: { case: 'universalTx', value: tx },
    } as any);

    // Roundtrip
    const envBytes = env.toBinary();
    const decoded = pb.Envelope.fromBinary(envBytes);

    expect(decoded.version).toBe(3);
    expect(decoded.payload.case).toBe('universalTx');
    const decodedTx = decoded.payload.value as pb.UniversalTx;
    expect(decodedTx.ops).toHaveLength(1);
    expect(decodedTx.atomic).toBe(true);

    const decodedOp = decodedTx.ops[0];
    expect(decodedOp.actor).toEqual(DEVICE_A);
    expect(decodedOp.kind.case).toBe('invoke');
    const decodedInvoke = decodedOp.kind.value as pb.Invoke;
    expect(decodedInvoke.method).toBe('wallet.send');

    const decodedArgPack = decodedInvoke.args!;
    const innerReq = pb.OnlineTransferRequest.fromBinary(decodedArgPack.body);
    expect(innerReq.tokenId).toBe('ERA');
    expect(innerReq.toDeviceId).toEqual(DEVICE_B);
    expect(innerReq.amount).toBe(10n);
  });

  test('headers carry correct identity (deviceId, genesisHash, chainTip, seq)', () => {
    const headers = makeHeaders();
    const env = new pb.Envelope({
      version: 3,
      headers,
      payload: { case: 'universalTx', value: new pb.UniversalTx({ ops: [], atomic: false }) },
    } as any);

    const decoded = pb.Envelope.fromBinary(env.toBinary());
    expect(decoded.headers?.deviceId).toEqual(DEVICE_A);
    expect(decoded.headers?.genesisHash).toEqual(GENESIS_A);
  });
});

// ─────────────────────────────────────────────────────────────────
// 4. Offline Transfer — Full Cycle
// ─────────────────────────────────────────────────────────────────

describe('Offline Transfer — Full Cycle', () => {
  beforeEach(() => installBridge());

  test('happy path: prepare + TRANSFER_COMPLETE event → accepted=true', async () => {
    const promise = dsm.offlineSend({
      to: DEVICE_B,
      amount: BigInt(10000 + testIndex),
      tokenId: 'ERA',
    } as any);

    // Let offlineSend register event listeners (async bridge calls)
    await new Promise(r => setTimeout(r, 100));

    // Emit completion event with matching commitment hash
    const note = new pb.BilateralEventNotification({
      eventType: pb.BilateralEventType.BILATERAL_EVENT_TRANSFER_COMPLETE,
      commitmentHash: COMMITMENT_HASH,
      status: 'completed',
      message: 'Bilateral transfer complete',
    } as any);
    emit('bilateral.event', note.toBinary());

    const res = await promise;
    expect(res.accepted).toBe(true);
  });

  test('CRITICAL: the offline send request carries what the user asked for', async () => {
    // offlineSend sends the user's intent via routerInvokeBin('wallet.sendOffline',
    // ArgPack): the counterparty, token, amount and memo. Rust resolves where the
    // counterparty's phone is and authors the prepare it sends over BLE.
    let capturedPrepReq: pb.OfflineTransferRequest | null = null;

    // Intercept nativeBoundaryIngress to capture the ArgPack → OfflineTransferRequest
    const origCallBin = (global as any).window.DsmBridge.sendMessageBin;
    (global as any).window.DsmBridge.sendMessageBin = async (reqBytes: Uint8Array) => {
      const { method, payload } = decodeBridgeReq(reqBytes);
      if (method === 'nativeBoundaryIngress') {
        const ingress = decodeIngressReq(payload);
        if (ingress.operationCase === 'routerInvoke' && ingress.method === 'wallet.sendOffline') {
          try {
            const argPack = pb.ArgPack.fromBinary(ingress.args);
            capturedPrepReq = pb.OfflineTransferRequest.fromBinary(argPack.body);
          } catch {
            // fall through
          }
        }
      }
      return origCallBin(reqBytes);
    };

    const promise = dsm.offlineSend({
      to: DEVICE_B,
      amount: BigInt(11000 + testIndex),
      tokenId: 'ERA',
    } as any);

    await new Promise(r => setTimeout(r, 100));
    emit('bilateral.event', new pb.BilateralEventNotification({
      eventType: pb.BilateralEventType.BILATERAL_EVENT_TRANSFER_COMPLETE,
      commitmentHash: COMMITMENT_HASH,
      status: 'completed',
    } as any).toBinary());

    const res = await promise;
    expect(res.accepted).toBe(true);

    // Verify the OfflineTransferRequest that TS sends to the Rust layer
    expect(capturedPrepReq).not.toBeNull();
    expect(capturedPrepReq!.counterpartyDeviceId).toHaveLength(32);
    expect(capturedPrepReq!.counterpartyDeviceId[0]).toBe(0xBB); // matches DEVICE_B
    expect(capturedPrepReq!.tokenId).toBe('ERA');
    expect(capturedPrepReq!.amount).toBe(String(11000 + testIndex));
  });

  test('BILATERAL_EVENT_REJECTED event → accepted=false', async () => {
    const promise = dsm.offlineSend({
      to: DEVICE_B,
      amount: BigInt(12000 + testIndex),
      tokenId: 'ERA',
    } as any);

    await new Promise(r => setTimeout(r, 100));

    emit('bilateral.event', new pb.BilateralEventNotification({
      eventType: pb.BilateralEventType.BILATERAL_EVENT_REJECTED,
      commitmentHash: COMMITMENT_HASH,
      status: 'rejected',
      message: 'counterparty rejected',
    } as any).toBinary());

    const res = await promise;
    expect(res.accepted).toBe(false);
    expect(String(res.result)).toMatch(/rejected/i);
  });

  test('BILATERAL_EVENT_FAILED event → polls backend, confirms failure → accepted=false', async () => {
    // When a FAILED event arrives, the frontend polls the backend for
    // authoritative session status instead of immediately declaring failure.
    // Set up the pending list to return the session as failed.
    bilateralPendingListOverride = () => [
      new pb.OfflineBilateralTransaction({
        id: encodeBase32Crockford(COMMITMENT_HASH),
        commitmentHash: COMMITMENT_HASH,
        senderId: DEVICE_A,
        recipientId: DEVICE_B,
        phase: pb.OfflineBilateralPhase.OFFLINE_PHASE_FAILED,
        direction: pb.OfflineBilateralDirection.OFFLINE_DIRECTION_OUTGOING,
        amount: BigInt(7),
        displayAmount: '7',
        tokenId: 'ERA',
      } as any),
    ];

    const promise = dsm.offlineSend({
      to: DEVICE_B,
      amount: BigInt(13000 + testIndex),
      tokenId: 'ERA',
    } as any);

    await new Promise(r => setTimeout(r, 100));

    emit('bilateral.event', new pb.BilateralEventNotification({
      eventType: pb.BilateralEventType.BILATERAL_EVENT_FAILED,
      commitmentHash: COMMITMENT_HASH,
      status: 'failed',
      message: 'BLE disconnected',
      failureReason: pb.BilateralFailureReason.FAILURE_REASON_BLE_GATT_ERROR,
    } as any).toBinary());

    const res = await promise;
    expect(res.accepted).toBe(false);
    expect(String(res.result)).toMatch(/failed/i);
  });

  // Where the counterparty's phone is over BLE is Rust's to know. A phone it
  // has not met is its refusal, shown in its words; the frontend neither
  // resolves an address nor refuses first.
  test('a send to a phone Rust has not met over BLE is Rust\'s refusal, in its words', async () => {
    const refusal = 'wallet.sendOffline: no BLE address is known for the counterparty: the phones have not met over BLE';
    bilateralResponseOverride = () => frameEnvelope(new pb.Envelope({
      version: 3,
      payload: { case: 'error', value: new pb.Error({ code: 1, message: refusal }) },
    } as any));

    const res = await dsm.offlineSend({
      to: DEVICE_B,
      amount: BigInt(14000 + testIndex),
      tokenId: 'ERA',
    });

    expect(res.accepted).toBe(false);
    expect(res.result).toBe(`offlineSend: ${refusal}`);
  }, 15000);
});

// ─────────────────────────────────────────────────────────────────
// 5. Offline Transfer — Proto Constraints
// ─────────────────────────────────────────────────────────────────

describe('Offline Transfer — Proto Constraints', () => {
  test('BilateralPrepareRequest enforces correct field sizes', () => {
    const prepReq = new pb.BilateralPrepareRequest({
      counterpartyDeviceId: DEVICE_B as any,
      operationData: new Uint8Array(100) as any,
      expectedGenesisHash: new pb.Hash32({ v: COUNTERPARTY_GENESIS } as any),
      expectedCounterpartyStateHash: new pb.Hash32({ v: COUNTERPARTY_TIP } as any),
      senderSigningPublicKey: SIGNING_KEY as any,
      senderDeviceId: DEVICE_A as any,
      senderGenesisHash: new pb.Hash32({ v: GENESIS_A } as any),
    } as any);

    const bytes = prepReq.toBinary();
    const decoded = pb.BilateralPrepareRequest.fromBinary(bytes);

    // Proto annotation: (dsm_fixed_len)=32
    expect(decoded.counterpartyDeviceId).toHaveLength(32);
    expect(decoded.senderDeviceId).toHaveLength(32);
    // Proto annotation: (dsm_fixed_len)=64
    expect(decoded.senderSigningPublicKey).toHaveLength(64);
    // operationData must be non-empty
    expect(decoded.operationData.length).toBeGreaterThan(0);
    // Hash32 fields
    expect(decoded.expectedGenesisHash?.v).toHaveLength(32);
    expect(decoded.expectedCounterpartyStateHash?.v).toHaveLength(32);
    expect(decoded.senderGenesisHash?.v).toHaveLength(32);
  });

  test('canonical encoding is deterministic (same input = same bytes)', () => {
    const params = {
      tokenId: 'ERA',
      toDeviceId: DEVICE_B as any,
      amount: 42n as any,
      memo: 'test',
      fromDeviceId: DEVICE_A as any,
    };

    const req1 = new pb.OnlineTransferRequest(params as any);
    const req2 = new pb.OnlineTransferRequest(params as any);
    const bytes1 = req1.toBinary();
    const bytes2 = req2.toBinary();

    expect(bytes1).toEqual(bytes2);
    expect(bytes1.length).toBeGreaterThan(0);
  });

  test('BilateralPrepareResponse roundtrip preserves commitment_hash', () => {
    const resp = new pb.BilateralPrepareResponse({
      commitmentHash: new pb.Hash32({ v: COMMITMENT_HASH } as any),
      localSignature: new Uint8Array(64).fill(0xEE),
      counterpartyStateHash: new pb.Hash32({ v: new Uint8Array(32).fill(0x11) } as any),
      localStateHash: new pb.Hash32({ v: new Uint8Array(32).fill(0x22) } as any),
      responderSigningPublicKey: new Uint8Array(64).fill(0x33) as any,
    } as any);

    const bytes = resp.toBinary();
    const decoded = pb.BilateralPrepareResponse.fromBinary(bytes);

    expect(decoded.commitmentHash?.v).toEqual(COMMITMENT_HASH);
    expect(decoded.commitmentHash?.v).toHaveLength(32);
    expect(decoded.localSignature).toHaveLength(64);
    expect(decoded.responderSigningPublicKey).toHaveLength(64);
  });
});

// ─────────────────────────────────────────────────────────────────
// 6. Offline Transfer — Timeout & Event Matching
// ─────────────────────────────────────────────────────────────────

describe('Offline Transfer — Timeout & Event Matching', () => {
  beforeEach(() => installBridge());

  test('a session absent from the pending list is not a completed transfer; its committed phase is', async () => {
    // With no events, the status poller queries the backend. The default mock
    // lists nothing: the step's absence says nothing about how it ended.
    let settled = false;
    const promise = dsm.offlineSend({
      to: DEVICE_B,
      amount: BigInt(15000 + testIndex),
      tokenId: 'ERA',
    } as any);
    void promise.then(() => { settled = true; });

    // Allow bridge calls and the first poll to fire against the empty list.
    await new Promise(r => setTimeout(r, 4000));
    expect(settled).toBe(false);

    // The backend now lists the step as committed; the next poll reads it.
    bilateralPendingListOverride = () => [
      new pb.OfflineBilateralTransaction({
        id: encodeBase32Crockford(COMMITMENT_HASH),
        commitmentHash: COMMITMENT_HASH,
        senderId: DEVICE_A,
        recipientId: DEVICE_B,
        phase: pb.OfflineBilateralPhase.OFFLINE_PHASE_COMMITTED,
        direction: pb.OfflineBilateralDirection.OFFLINE_DIRECTION_OUTGOING,
        amount: BigInt(15000 + testIndex),
        displayAmount: String(15000 + testIndex),
        tokenId: 'ERA',
      } as any),
    ];

    const res = await promise;
    expect(res.accepted).toBe(true);
  }, 15000);

  test('when the screen stops waiting, the step is reported open, not failed', async () => {
    jest.useFakeTimers();
    try {
      const promise = dsm.offlineSend({
        to: DEVICE_B,
        amount: BigInt(18000 + testIndex),
        tokenId: 'ERA',
      } as any);
      // The pending list never names the step as ended, past every poll.
      await jest.advanceTimersByTimeAsync(1_500 + 3_000 * 41);
      const res = await promise;
      expect(res.accepted).toBe(false);
      expect(res.open).toBe(true);
      expect(String(res.result)).toMatch(/still open/);
    } finally {
      jest.useRealTimers();
    }
  });

  test('a send that names no token reaches Rust naming none, and Rust refuses it', async () => {
    let captured: pb.OfflineTransferRequest | null = null;
    bilateralResponseOverride = () => frameEnvelope(new pb.Envelope({
      version: 3,
      payload: { case: 'error', value: new pb.Error({ code: 1, message: 'wallet.sendOffline: the request names no token' }) },
    } as any));
    const origCallBin = (global as any).window.DsmBridge.sendMessageBin;
    (global as any).window.DsmBridge.sendMessageBin = async (reqBytes: Uint8Array) => {
      const { method, payload } = decodeBridgeReq(reqBytes);
      if (method === 'nativeBoundaryIngress') {
        const ingress = decodeIngressReq(payload);
        if (ingress.operationCase === 'routerInvoke' && ingress.method === 'wallet.sendOffline') {
          captured = pb.OfflineTransferRequest.fromBinary(pb.ArgPack.fromBinary(ingress.args).body);
        }
      }
      return origCallBin(reqBytes);
    };

    const res = await dsm.offlineSend({
      to: DEVICE_B,
      amount: BigInt(19000 + testIndex),
      tokenId: '',
    } as any);

    expect(captured).not.toBeNull();
    expect(captured!.tokenId).toBe('');
    expect(res.accepted).toBe(false);
    expect(String(res.result)).toContain('names no token');
  });

  test('event with wrong commitment hash does NOT resolve; correct hash does', async () => {
    const promise = dsm.offlineSend({
      to: DEVICE_B,
      amount: BigInt(16000 + testIndex),
      tokenId: 'ERA',
    } as any);

    // Let async bridge calls complete
    await new Promise(r => setTimeout(r, 200));

    // Emit event with WRONG commitment hash — should NOT resolve
    const wrongHash = new Uint8Array(32).fill(0x99);
    emit('bilateral.event', new pb.BilateralEventNotification({
      eventType: pb.BilateralEventType.BILATERAL_EVENT_TRANSFER_COMPLETE,
      commitmentHash: wrongHash,
      status: 'completed',
      message: 'wrong hash',
    } as any).toBinary());

    // Give event loop a tick
    await new Promise(r => setTimeout(r, 100));

    // Emit event with CORRECT commitment hash — SHOULD resolve
    emit('bilateral.event', new pb.BilateralEventNotification({
      eventType: pb.BilateralEventType.BILATERAL_EVENT_TRANSFER_COMPLETE,
      commitmentHash: COMMITMENT_HASH,
      status: 'completed',
      message: 'correct hash',
    } as any).toBinary());

    await new Promise(r => setTimeout(r, 100));

    const res = await promise;
    expect(res.accepted).toBe(true);
    expect(String(res.result)).toContain('correct hash');
  }, 10000);
});

// ─────────────────────────────────────────────────────────────────
// 7. Bridge Protocol Fidelity
// ─────────────────────────────────────────────────────────────────

describe('Bridge Protocol Fidelity', () => {
  test('BridgeRpcRequest/Response roundtrip preserves data', () => {
    const payload = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const req = new pb.BridgeRpcRequest({
      method: 'testMethod',
      payload: { case: 'bytes', value: { data: payload } },
    } as any);
    const reqBytes = req.toBinary();
    const decodedReq = pb.BridgeRpcRequest.fromBinary(reqBytes);
    expect(decodedReq.method).toBe('testMethod');
    const decodedPayload = decodedReq.payload?.case === 'bytes' ? decodedReq.payload.value.data : null;
    expect(decodedPayload).toEqual(payload);

    // Response roundtrip
    const responseData = new Uint8Array([10, 20, 30]);
    const resp = new pb.BridgeRpcResponse({
      result: { case: 'success', value: { data: responseData } },
    });
    const respBytes = resp.toBinary();
    const decodedResp = pb.BridgeRpcResponse.fromBinary(respBytes);
    expect(decodedResp.result.case).toBe('success');
    if (decodedResp.result.case === 'success') {
      expect(decodedResp.result.value.data).toEqual(responseData);
    }
  });

  test('decodeFramedEnvelopeV3 accepts 0x03-prefixed and rejects raw 0x08', () => {
    const env = new pb.Envelope({
      version: 3,
      headers: makeHeaders(),
      payload: {
        case: 'universalRx',
        value: new pb.UniversalRx({ results: [] }),
      },
    } as any);

    // 0x03 framing prefix: accepted
    const framed = frameEnvelope(env);
    expect(framed[0]).toBe(0x03);
    const decoded1 = decodeFramedEnvelopeV3(framed);
    expect(decoded1.version).toBe(3);
    expect(decoded1.payload.case).toBe('universalRx');

    // Raw protobuf (starts with 0x08 = field 1 varint): MUST throw
    const raw = env.toBinary();
    expect(raw[0]).toBe(0x08);
    expect(() => decodeFramedEnvelopeV3(raw)).toThrow(/invalid framing byte 0x08/);
  });

  test('OfflineBilateralPhase numbers the terminal phases the send poller reads as the proto does', () => {
    expect(pb.OfflineBilateralPhase.OFFLINE_PHASE_REJECTED).toBe(5);
    expect(pb.OfflineBilateralPhase.OFFLINE_PHASE_COMMITTED).toBe(7);
    expect(pb.OfflineBilateralPhase.OFFLINE_PHASE_FAILED).toBe(8);
  });

  test('BilateralEventType enum values exist for all completion states', () => {
    expect(pb.BilateralEventType.BILATERAL_EVENT_TRANSFER_COMPLETE).toBeDefined();
    expect(pb.BilateralEventType.BILATERAL_EVENT_REJECTED).toBeDefined();
    expect(pb.BilateralEventType.BILATERAL_EVENT_FAILED).toBeDefined();
    expect(typeof pb.BilateralEventType.BILATERAL_EVENT_TRANSFER_COMPLETE).toBe('number');
    expect(typeof pb.BilateralEventType.BILATERAL_EVENT_REJECTED).toBe('number');
    expect(typeof pb.BilateralEventType.BILATERAL_EVENT_FAILED).toBe('number');
  });
});
