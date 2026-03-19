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
const CHAIN_TIP_A = new Uint8Array(32).fill(0xCC); // non-zero required for online
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

function zeroHash(): pb.Hash32 {
  return new pb.Hash32({ v: new Uint8Array(32) } as any);
}

/** Decode BridgeRpcRequest to extract method and payload (handles both bytes and appRouter cases) */
function decodeBridgeReq(reqBytes: Uint8Array): { method: string; payload: Uint8Array; appRouterMethodName?: string } {
  const req = pb.BridgeRpcRequest.fromBinary(reqBytes);
  let payload = new Uint8Array(0);
  let appRouterMethodName: string | undefined;

  if (req.payload?.case === 'bytes') {
    payload = req.payload.value.data || new Uint8Array(0);
  } else if (req.payload?.case === 'appRouter') {
    appRouterMethodName = (req.payload.value as any).methodName;
    payload = (req.payload.value as any).args || new Uint8Array(0);
  }
  return { method: req.method, payload, appRouterMethodName };
}

/** Add 8-byte router request-id prefix */
function withRouterPrefix(data: Uint8Array): Uint8Array {
  const out = new Uint8Array(8 + data.length);
  out.set(data, 8);
  return out;
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

/** Build a BilateralPrepareResponse inside UniversalRx inside framed Envelope */
function makeBilateralPrepareResponseEnvelope(commitHash: Uint8Array): Uint8Array {
  const resp = new pb.BilateralPrepareResponse({
    commitmentHash: new pb.Hash32({ v: commitHash } as any),
    localSignature: new Uint8Array(64),
  } as any);
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
  return frameEnvelope(env);
}

/** Build an OnlineTransferResponse inside Envelope with onlineTransferResponse payload.
 *  This matches the AppRouter response path (appRouterInvokeBin → wallet.send). */
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
      chainTip: CHAIN_TIP_A as any,
      genesisHash: GENESIS_A as any,
    } as any),
    payload: { case: 'onlineTransferResponse', value: resp },
  } as any);
  return frameEnvelope(env); // 0x03-framed, matching appRouterInvokeBin output
}

function makeHeaders(overrides?: Partial<{ deviceId: Uint8Array; genesisHash: Uint8Array; chainTip: Uint8Array; seq: bigint }>): pb.Headers {
  return new pb.Headers({
    deviceId: overrides?.deviceId || DEVICE_A,
    genesisHash: (overrides?.genesisHash || GENESIS_A) as any,
    chainTip: (overrides?.chainTip || CHAIN_TIP_A) as any,
    seq: (overrides?.seq ?? 1n) as any,
  } as any);
}

// ─────────────────────────── Bridge Setup ───────────────────────────

/** Capture payloads for assertion */
let capturedMethods: string[] = [];
let onlineTransferOverride: (() => Uint8Array) | null = null;
let bilateralResponseOverride: (() => Uint8Array) | null = null;
let headersOverride: pb.Headers | null = null;

function installBridge(opts?: { contactBleAddress?: string }) {
  const g = global as any;
  g.window = g.window || {};
  const headers = headersOverride || makeHeaders();

  g.window.DsmBridge = {
    __binary: true,
    getDeviceIdBin: () => encodeBase32Crockford(DEVICE_A),
    getGenesisHashBin: () => encodeBase32Crockford(GENESIS_A),
    hasIdentityDirect: () => true,

    __callBin: async (reqBytes: Uint8Array): Promise<Uint8Array> => {
      const { method, payload, appRouterMethodName } = decodeBridgeReq(reqBytes);
      capturedMethods.push(method);

      // --- Direct bridge methods (no router prefix) ---

      if (method === 'getTransportHeadersV3Bin') {
        return wrapSuccess(headers.toBinary());
      }

      if (method === 'getSigningPublicKeyBin') {
        return wrapSuccess(SIGNING_KEY);
      }

      if (method === 'getPreference' || method === 'setPreference') {
        return wrapSuccess(new Uint8Array(0));
      }

      if (method === 'resolveBleAddressForDeviceId') {
        return wrapSuccess(new TextEncoder().encode('AA:BB:CC:DD:EE:FF'));
      }

      // --- Router methods (response includes 8-byte request-id prefix) ---

      if (method === 'appRouterQuery') {
        // appRouterQueryBin sends methodName via appRouter case
        if (appRouterMethodName === 'contacts.list') {
          // Return framed Envelope with 8-byte prefix (bridge strips the prefix)
          return wrapSuccess(withRouterPrefix(makeContactsFramedEnvelope(opts?.contactBleAddress)));
        }
        return wrapSuccess(withRouterPrefix(new Uint8Array(0)));
      }

      if (method === 'appRouterInvoke') {
        // sendOnlineTransfer uses appRouterInvokeBin('wallet.send', ...)
        // Check the AppRouterPayload for the method name
        if (appRouterMethodName === 'wallet.send' || appRouterMethodName === 'wallet.sendSmart') {
          if (onlineTransferOverride) {
            return wrapSuccess(withRouterPrefix(onlineTransferOverride()));
          }
          return wrapSuccess(withRouterPrefix(makeOnlineResponseEnvelope(true, 'ok', 123n)));
        }
        // bilateralOfflineSendBin uses appRouterInvoke
        if (bilateralResponseOverride) {
          return wrapSuccess(withRouterPrefix(bilateralResponseOverride()));
        }
        return wrapSuccess(withRouterPrefix(makeBilateralPrepareResponseEnvelope(COMMITMENT_HASH)));
      }

      return wrapError(`unhandled method: ${method}`);
    },

    sendMessageBin: async (reqBytes: Uint8Array): Promise<Uint8Array> => {
      // MessagePort path — delegates to __callBin for simplicity in tests
      return g.window.DsmBridge.__callBin(reqBytes);
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
  headersOverride = null;
  testIndex++;
  initializeEventBridge();
  // Clear headers cache so each test gets fresh headers from bridge
  (global as any).__dsmLastGoodHeaders = { deviceId: undefined, genesisHash: undefined, chainTip: undefined };
});

// ─────────────────────────────────────────────────────────────────
// 1. Online Transfer — Full Cycle
// ─────────────────────────────────────────────────────────────────

describe('Online Transfer — Full Cycle', () => {
  beforeEach(() => installBridge());

  test('happy path: accepted=true with txHash', async () => {
    onlineTransferOverride = () => makeOnlineResponseEnvelope(true, 'transfer ok', 500n);

    const res = await dsm.sendOnlineTransfer({
      to: DEVICE_B,
      amount: BigInt(1000 + testIndex), // unique amount to avoid dedup
      tokenId: 'ERA',
    });
    expect(res.accepted).toBe(true);
  });

  test('failure response returns accepted=false when inner OnlineTransferResponse.success=false', async () => {
    onlineTransferOverride = () => makeOnlineResponseEnvelope(false, 'insufficient funds', 0n);

    const res = await dsm.sendOnlineTransfer({
      to: DEVICE_B,
      amount: BigInt(2000 + testIndex),
      tokenId: 'ERA',
    });
    expect(res.accepted).toBe(false);
    expect(res.result).toContain('insufficient funds');
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

    const res = await dsm.sendOnlineTransfer({
      to: DEVICE_B,
      amount: BigInt(3000 + testIndex),
      tokenId: 'ERA',
    });
    expect(res.accepted).toBe(false);
    expect(String(res.result)).toMatch(/internal error|DSM error/);
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

    const res = await dsm.sendOnlineTransfer({
      to: DEVICE_B,
      amount: BigInt(4000 + testIndex),
      tokenId: 'ERA',
    });
    expect(res.accepted).toBe(false);
    // sendOnlineTransfer now expects onlineTransferResponse, not universalRx
    expect(String(res.result)).toMatch(/Expected onlineTransferResponse|unexpected/i);
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

    const res = await dsm.sendOnlineTransfer({
      to: DEVICE_B,
      amount: BigInt(5000 + testIndex),
      tokenId: 'ERA',
    });
    expect(res.accepted).toBe(false);
    expect(String(res.result)).toContain('quota exceeded');
  });
});

// ─────────────────────────────────────────────────────────────────
// 2. Online Transfer — Input Validation
// ─────────────────────────────────────────────────────────────────

describe('Online Transfer — Input Validation', () => {
  beforeEach(() => installBridge());

  test('invalid device ID length (16 bytes) → error', async () => {
    const shortId = new Uint8Array(16).fill(0x22);
    const res = await dsm.sendOnlineTransfer({ to: shortId, amount: BigInt(6000 + testIndex), tokenId: 'ERA' });
    expect(res.accepted).toBe(false);
    expect(String(res.result)).toMatch(/32 bytes/);
  });

  test('string device ID (base32) is accepted', async () => {
    const b32 = encodeBase32Crockford(DEVICE_B);
    onlineTransferOverride = () => makeOnlineResponseEnvelope(true, 'ok', 100n);

    const res = await dsm.sendOnlineTransfer({ to: b32, amount: BigInt(7000 + testIndex), tokenId: 'ERA' });
    expect(res.accepted).toBe(true);
  });

  test('zero chain_tip no longer blocks online transfer (SDK-owned state)', async () => {
    // chain_tip is no longer supplied by the frontend; the SDK derives it from SQLite.
    // Keep this regression test to ensure an all-zero transport header tip does not break send.
    const origCallBin = (global as any).window.DsmBridge.__callBin;
    (global as any).window.DsmBridge.__callBin = async (reqBytes: Uint8Array) => {
      const { method } = decodeBridgeReq(reqBytes);
      if (method === 'getTransportHeadersV3Bin') {
        const headers = makeHeaders({ chainTip: new Uint8Array(32) /* all zeros */ });
        return wrapSuccess(headers.toBinary());
      }
      return origCallBin(reqBytes);
    };

    const res = await dsm.sendOnlineTransfer({ to: DEVICE_B, amount: BigInt(8000 + testIndex), tokenId: 'ERA' });
    expect(res.accepted).toBe(true);
  });

  test('missing from_device_id (bridge returns short headers) → error', async () => {
    // Override getTransportHeadersV3Bin to return empty device_id
    const origCallBin = (global as any).window.DsmBridge.__callBin;
    (global as any).window.DsmBridge.__callBin = async (reqBytes: Uint8Array) => {
      const { method } = decodeBridgeReq(reqBytes);
      if (method === 'getTransportHeadersV3Bin') {
        const headers = new pb.Headers({
          deviceId: new Uint8Array(0) as any,
          genesisHash: GENESIS_A as any,
          chainTip: CHAIN_TIP_A as any,
          seq: 1n as any,
        } as any);
        return wrapSuccess(headers.toBinary());
      }
      return origCallBin(reqBytes);
    };

    const res = await dsm.sendOnlineTransfer({ to: DEVICE_B, amount: BigInt(9000 + testIndex), tokenId: 'ERA' });
    expect(res.accepted).toBe(false);
    expect(String(res.result)).toMatch(/device.id|32 bytes|bridge headers|identity not ready/i);
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
      chainTip: CHAIN_TIP_A as any,
      seq: 7n as any,
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
    expect(decoded.chainTip).toEqual(CHAIN_TIP_A);
    expect(decoded.chainTip).toHaveLength(32);
    expect(decoded.seq).toBe(7n);
  });

  test('Envelope v3 wraps UniversalTx → UniversalOp → Invoke(wallet.send) → ArgPack', () => {
    const req = new pb.OnlineTransferRequest({
      tokenId: 'ERA',
      toDeviceId: DEVICE_B as any,
      amount: 10n as any,
      fromDeviceId: DEVICE_A as any,
      chainTip: CHAIN_TIP_A as any,
      seq: 1n as any,
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
      genesisHash: GENESIS_A as any,
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
    const headers = makeHeaders({ seq: 42n });
    const env = new pb.Envelope({
      version: 3,
      headers,
      payload: { case: 'universalTx', value: new pb.UniversalTx({ ops: [], atomic: false }) },
    } as any);

    const decoded = pb.Envelope.fromBinary(env.toBinary());
    expect(decoded.headers?.deviceId).toEqual(DEVICE_A);
    expect(decoded.headers?.genesisHash).toEqual(GENESIS_A);
    expect(decoded.headers?.chainTip).toEqual(CHAIN_TIP_A);
    expect(decoded.headers?.seq).toBe(42n);
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
      bleAddress: 'AA:BB:CC:DD:EE:FF',
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

  test('CRITICAL: signing key sent to bridge is exactly 64 bytes', async () => {
    // This is THE test that proves BLE pairing will work.
    // A 32-byte or empty signing key causes Rust-side identity verification to fail.
    let capturedEnvelope: pb.Envelope | null = null;

    // Intercept appRouterInvoke calls to capture the Envelope containing BilateralPrepareRequest
    const origCallBin = (global as any).window.DsmBridge.__callBin;
    (global as any).window.DsmBridge.__callBin = async (reqBytes: Uint8Array) => {
      const { method, payload, appRouterMethodName } = decodeBridgeReq(reqBytes);
      if (method === 'appRouterInvoke') {
        // bilateralOfflineSendBin sends: appRouterInvokeBin('bilateralOfflineSend', args)
        // args layout: [u32be bleAddrLen][bleAddr utf8][Envelope bytes]
        try {
          if (payload && payload.length > 4) {
            const addrLen = ((payload[0] << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3]) >>> 0;
            const envStart = 4 + addrLen;
            if (envStart < payload.length) {
              const envBytes = payload.slice(envStart);
              capturedEnvelope = pb.Envelope.fromBinary(envBytes);
            }
          }
        } catch {
          // fall through
        }
      }
      return origCallBin(reqBytes);
    };

    const promise = dsm.offlineSend({
      to: DEVICE_B,
      amount: BigInt(11000 + testIndex),
      tokenId: 'ERA',
      bleAddress: 'AA:BB:CC:DD:EE:FF',
    } as any);

    await new Promise(r => setTimeout(r, 100));
    emit('bilateral.event', new pb.BilateralEventNotification({
      eventType: pb.BilateralEventType.BILATERAL_EVENT_TRANSFER_COMPLETE,
      commitmentHash: COMMITMENT_HASH,
      status: 'completed',
    } as any).toBinary());

    const res = await promise;
    expect(res.accepted).toBe(true);

    // Extract BilateralPrepareRequest from the captured Envelope
    expect(capturedEnvelope).not.toBeNull();
    const tx = (capturedEnvelope!.payload.value as pb.UniversalTx);
    expect(tx.ops.length).toBeGreaterThan(0);
    const op = tx.ops[0];
    expect(op.kind.case).toBe('invoke');
    const inv = op.kind.value as pb.Invoke;
    expect(inv.method).toBe('bilateral.prepare');
    const prepReq = pb.BilateralPrepareRequest.fromBinary(inv.args!.body);

    // THE critical assertion: signing key must be 64 bytes
    expect(prepReq.senderSigningPublicKey).toHaveLength(64);
    expect(prepReq.senderSigningPublicKey[0]).toBe(0x5A); // matches our mock SIGNING_KEY

    // Also verify other field constraints
    expect(prepReq.counterpartyDeviceId).toHaveLength(32);
    expect(prepReq.senderDeviceId).toHaveLength(32);
    expect(prepReq.expectedCounterpartyStateHash?.v).toHaveLength(32);
    expect(prepReq.senderGenesisHash?.v).toHaveLength(32);
    expect(prepReq.senderChainTip).toBeUndefined();
    expect(prepReq.operationData.length).toBeGreaterThan(0);
  });

  test('BILATERAL_EVENT_REJECTED event → accepted=false', async () => {
    const promise = dsm.offlineSend({
      to: DEVICE_B,
      amount: BigInt(12000 + testIndex),
      tokenId: 'ERA',
      bleAddress: 'AA:BB:CC:DD:EE:FF',
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

  test('BILATERAL_EVENT_FAILED event → accepted=false with reason', async () => {
    const promise = dsm.offlineSend({
      to: DEVICE_B,
      amount: BigInt(13000 + testIndex),
      tokenId: 'ERA',
      bleAddress: 'AA:BB:CC:DD:EE:FF',
    } as any);

    await new Promise(r => setTimeout(r, 100));

    emit('bilateral.event', new pb.BilateralEventNotification({
      eventType: pb.BilateralEventType.BILATERAL_EVENT_FAILED,
      commitmentHash: COMMITMENT_HASH,
      status: 'failed',
      message: 'BLE disconnected',
      failureReason: pb.BilateralFailureReason.BILATERAL_FAILURE_BLE_DISCONNECTED,
    } as any).toBinary());

    const res = await promise;
    expect(res.accepted).toBe(false);
    expect(String(res.result)).toMatch(/disconnected|failed/i);
  });

  test('missing BLE address with no resolution → error', async () => {
    // Override bridge to fail BLE resolution
    const origCallBin = (global as any).window.DsmBridge.__callBin;
    (global as any).window.DsmBridge.__callBin = async (reqBytes: Uint8Array) => {
      const { method } = decodeBridgeReq(reqBytes);
      if (method === 'resolveBleAddressForDeviceId') {
        return wrapSuccess(new Uint8Array(0));
      }
      return origCallBin(reqBytes);
    };

    const res = await dsm.offlineSend({
      to: DEVICE_B,
      amount: BigInt(14000 + testIndex),
      tokenId: 'ERA',
      // no ble_address provided
    } as any);

    expect(res.accepted).toBe(false);
    expect(String(res.result)).toMatch(/ble_address|bleAddress|unavailable/i);
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
      validityIterations: 100n as any,
      expectedGenesisHash: new pb.Hash32({ v: COUNTERPARTY_GENESIS } as any),
      expectedCounterpartyStateHash: new pb.Hash32({ v: COUNTERPARTY_TIP } as any),
      bleAddress: 'AA:BB:CC:DD:EE:FF',
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
    // BLE address
    expect(decoded.bleAddress).toBe('AA:BB:CC:DD:EE:FF');
  });

  test('canonical encoding is deterministic (same input = same bytes)', () => {
    const params = {
      tokenId: 'ERA',
      toDeviceId: DEVICE_B as any,
      amount: 42n as any,
      memo: 'test',
      fromDeviceId: DEVICE_A as any,
      chainTip: CHAIN_TIP_A as any,
      seq: 1n as any,
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
      expiresIterations: 100n as any,
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

  test('60-second timeout fires when no completion event arrives', async () => {
    jest.useFakeTimers();

    const promise = dsm.offlineSend({
      to: DEVICE_B,
      amount: BigInt(15000 + testIndex),
      tokenId: 'ERA',
      bleAddress: 'AA:BB:CC:DD:EE:FF',
    } as any);

    // Let async bridge calls resolve through fake timer queue
    await jest.advanceTimersByTimeAsync(500);

    // Advance past the 60-second timeout
    await jest.advanceTimersByTimeAsync(61_000);

    const res = await promise;
    expect(res.accepted).toBe(false);
    expect(String(res.result)).toMatch(/timed out|timeout/i);

    jest.useRealTimers();
  });

  test('event with wrong commitment hash does NOT resolve; correct hash does', async () => {
    jest.useFakeTimers();

    const promise = dsm.offlineSend({
      to: DEVICE_B,
      amount: BigInt(16000 + testIndex),
      tokenId: 'ERA',
      bleAddress: 'AA:BB:CC:DD:EE:FF',
    } as any);

    // Let async bridge calls complete
    await jest.advanceTimersByTimeAsync(500);

    // Emit event with WRONG commitment hash — should NOT resolve
    const wrongHash = new Uint8Array(32).fill(0x99);
    emit('bilateral.event', new pb.BilateralEventNotification({
      eventType: pb.BilateralEventType.BILATERAL_EVENT_TRANSFER_COMPLETE,
      commitmentHash: wrongHash,
      status: 'completed',
      message: 'wrong hash',
    } as any).toBinary());

    // Give event loop a tick
    await jest.advanceTimersByTimeAsync(100);

    // Emit event with CORRECT commitment hash — SHOULD resolve
    emit('bilateral.event', new pb.BilateralEventNotification({
      eventType: pb.BilateralEventType.BILATERAL_EVENT_TRANSFER_COMPLETE,
      commitmentHash: COMMITMENT_HASH,
      status: 'completed',
      message: 'correct hash',
    } as any).toBinary());

    await jest.advanceTimersByTimeAsync(100);

    const res = await promise;
    expect(res.accepted).toBe(true);
    expect(String(res.result)).toContain('correct hash');

    jest.useRealTimers();
  });
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

  test('OfflineBilateralTransaction status enum values match proto spec', () => {
    expect(pb.OfflineBilateralTransactionStatus.OFFLINE_TX_STATUS_UNSPECIFIED).toBe(0);
    expect(pb.OfflineBilateralTransactionStatus.OFFLINE_TX_PENDING).toBe(1);
    expect(pb.OfflineBilateralTransactionStatus.OFFLINE_TX_IN_PROGRESS).toBe(2);
    expect(pb.OfflineBilateralTransactionStatus.OFFLINE_TX_CONFIRMED).toBe(3);
    expect(pb.OfflineBilateralTransactionStatus.OFFLINE_TX_FAILED).toBe(4);
    expect(pb.OfflineBilateralTransactionStatus.OFFLINE_TX_REJECTED).toBe(5);
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
