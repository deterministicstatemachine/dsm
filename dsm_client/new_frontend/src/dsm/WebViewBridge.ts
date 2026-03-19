/* eslint-disable security/detect-object-injection */
// SPDX-License-Identifier: Apache-2.0
// ============================================================================
// DSM APP INTEGRATION BOUNDARY — Frontend Binary Bridge
// ============================================================================
//
// If you are building a custom UI or replacing the existing app, THIS is your
// main communication artery to the DSM Rust Core.
//
// HOW TO HOOK IN:
//   1. Import { appRouterQueryBin, appRouterInvokeBin } from this module.
//   2. Construct a protobuf message (e.g., OnlineTransferRequest, ArgPack).
//      Types are in '../proto/dsm_app_pb.ts' (regenerate: npm run proto:gen).
//   3. For reads:  appRouterQueryBin(path, params)  -> Promise<Uint8Array>
//      For writes: appRouterInvokeBin(method, args) -> Promise<Uint8Array>
//   4. Decode the response: strip 0x03 prefix, Envelope.fromBinary(rest).
//      Use decodeFramedEnvelopeV3() from decoding.ts for this.
//
// PROTOCOL RULES (violating any = rejected by Rust SDK):
//   - NO JSON, NO HEX, NO BASE64 on the wire. Protobuf Uint8Array ONLY.
//   - DO NOT sign transactions in the UI layer — Rust core handles SPHINCS+.
//   - DO NOT use Date.now() for protocol logic — core is 100% clockless.
//     Wall-clock is only for BLE staleness, transport DoS limits, and UI display.
//
// WIRE FORMAT:
//   Request:  [8-byte msgId (u64 BE)][BridgeRpcRequest protobuf]
//   Response: [0x03][Envelope v3 protobuf]
//   Transport: MessagePort binary (ArrayBuffer), NOT @JavascriptInterface.
//
// KEY EXPORTS:
//   processEnvelopeV3Bin()   — generic Envelope v3 processing
//   appRouterQueryBin()      — read-only queries (balance, history, contacts)
//   appRouterInvokeBin()     — state-mutating ops (send, create token, claim)
//   bilateralOfflineSendBin()— BLE offline bilateral transfers
//
// See docs/INTEGRATION_GUIDE.md for the full developer onboarding guide.
// ============================================================================
/*
 * Canonical WebView bridge facade for DSM (Envelope v3, bytes-only transport).
 * - No addJavascriptInterface.
 * - No ISO-8859-1 / Latin1.
 * - No hex / base32 / base64 string transports.
 */

import { bridgeGate } from './BridgeGate';
import { BridgeRpcRequest, BridgeRpcResponse, BytesPayload, EmptyPayload, ArgPack, Codec, AppStateRequest, InboxRequest, StorageSyncRequest, CreateGenesisPayload, BleIdentityPayload, BilateralPayload, AppRouterPayload, ArchitectureInfoProto, SessionConfigureLockRequest } from '../proto/dsm_app_pb';
import { bridgeEvents } from '../bridge/bridgeEvents';
import { getBridgeInstance } from '../bridge/BridgeRegistry';
import type { AndroidBridgeV3 } from './bridgeTypes';
import { emitDeterministicSafetyIfPresent } from '../utils/deterministicSafety';
import { decodeFramedEnvelopeV3 } from './decoding';
import { dispatchNativeQrScannerActive } from './qrScannerState';
import { logger as appLogger } from '../utils/logger';

let bridgeEventCounter = 0;
const ENVELOPE_V3 = 3 as const;

function nextBridgeEventCounter(): number {
  bridgeEventCounter = (bridgeEventCounter + 1) >>> 0;
  return bridgeEventCounter;
}

const log = {
  info: (...args: unknown[]) => appLogger.info(...args),
  warn: (...args: unknown[]) => appLogger.warn(...args),
  error: (...args: unknown[]) => appLogger.error(...args),
  debug: (...args: unknown[]) => appLogger.debug(...args),
  log: (...args: unknown[]) => appLogger.info(...args),
};

function mustBridge(): AndroidBridgeV3 {
  const b = getBridgeInstance();
  if (!b) throw new Error('DSM bridge not available');
  return b;
}

export function normalizeToBytes(data: unknown): Uint8Array {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (Array.isArray(data)) return new Uint8Array(data);
  throw new Error('normalizeToBytes: expected Uint8Array or number[]');
}

const toBytes = (bytes: Uint8Array): Uint8Array<ArrayBuffer> => {
  const needsCopy = !(bytes.buffer instanceof ArrayBuffer);
  const buf = bytes.buffer instanceof ArrayBuffer
    ? bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength)
    : new ArrayBuffer(bytes.byteLength);
  const out = new Uint8Array(buf);
  if (needsCopy || bytes.byteOffset !== 0 || bytes.byteLength !== bytes.buffer.byteLength) {
    out.set(bytes);
  }
  return out;
};

// Strip one u32 length prefix if it matches the buffer length. Module-scope to
// avoid per-call closure allocation.
function maybeUnframe(buf: Uint8Array): Uint8Array {
  if (buf.length < 4) return buf;
  const nBE = ((buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]) >>> 0;
  if (4 + nBE === buf.length) return buf.slice(4, 4 + nBE);
  const nLE = (buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24)) >>> 0;
  if (4 + nLE === buf.length) return buf.slice(4, 4 + nLE);
  return buf;
}

// Structured bridge error class (thrown when bridge returns a protobuf ErrorResponse)
export class BridgeError extends Error {
  errorCode?: number;
  details?: unknown;
  constructor(errorCode: number | undefined, message: string) {
    super(message);
    this.name = 'BridgeError';
    this.errorCode = errorCode;
    // capture prototype chain for instanceof to work in older targets
    Object.setPrototypeOf(this, BridgeError.prototype);
  }
}

// --- MessagePort transport encoding ---
// Bytes-only contract end-to-end.
// Base32-Crockford is UI/debug-only (e.g., event payloads), never protocol requests.

// STRICT protobuf-only contract: All responses MUST be valid BridgeRpcResponse bytes.
const unwrapProtobufResponse = async (method: string, buf: Uint8Array): Promise<Uint8Array> => {
  if (!buf || buf.length === 0) {
    throw new Error('Empty response from bridge');
  }

  try {
    const br = BridgeRpcResponse.fromBinary(buf);
    const result = br.result;
    if (result.case === 'success') {
      const data = result.value?.data;
      return data instanceof Uint8Array ? data : new Uint8Array(0);
    }
    if (result.case === 'error') {
      const err = result.value;
      const code = err.errorCode ?? 0;

      // Map raw error codes to UI-friendly messages ("specific UIToast notification")
      // Always include HEX code for beta debugging
      const hex = `0x${code.toString(16).toUpperCase()}`;
      let uiMessage = err.message ?? `Bridge error ${hex}`;

      if (code === 460) {
         uiMessage = `Transfer Rejected (Offline Mode) - Check peer connection [${hex}]`;
      } else if (code === 404) {
         uiMessage = `Item Not Found - State may be stale [${hex}]`;
      } else if (code === 408) {
         uiMessage = `Protocol Timeout - Peer did not respond [${hex}]`;
      } else if (!uiMessage.includes(hex)) {
         uiMessage += ` [${hex}]`;
      }

      emitDeterministicSafetyIfPresent(uiMessage);

      const be = new BridgeError(code, uiMessage);
      be.details = err;

      // Beta: Ensure last error is accessible for StateBoy metrics/diagnostics
      const win = window as Window & { __lastBridgeError?: { message: string; code: string; counter: number } };
      win.__lastBridgeError = { message: uiMessage, code: hex, counter: nextBridgeEventCounter() };

      try {
        // Pass the mapped message to the event bus for Toast display
        bridgeEvents.emit('bridge.error', { code: be.errorCode, message: be.message, debugB32: err.debugB32 });
      } catch (_e) {
        // ignore
      }
      throw be;
    }
    const errorMessage = new TextDecoder().decode(buf);
    emitDeterministicSafetyIfPresent(errorMessage);
    try { bridgeEvents.emit('bridge.error', { code: 0, message: errorMessage, debugB32: '' }); } catch (_e) {}
    throw new BridgeError(0, `Bridge error: ${errorMessage}`);
  } catch (_e) {
    const errorMessage = new TextDecoder().decode(buf);
    emitDeterministicSafetyIfPresent(errorMessage);
    try { bridgeEvents.emit('bridge.error', { code: 0, message: errorMessage, debugB32: '' }); } catch (_e) {}
    throw new BridgeError(0, `Bridge error: ${errorMessage}`);
  }
};

const buildBridgeRequest = (method: string, payload?: Uint8Array): Uint8Array => {
  const bytes = payload instanceof Uint8Array ? new Uint8Array(payload) : new Uint8Array(0);
  const req = new BridgeRpcRequest({
    method,
    payload:
      bytes.length > 0
        ? { case: 'bytes', value: new BytesPayload({ data: bytes }) }
        : { case: 'empty', value: new EmptyPayload({}) },
  });
  return req.toBinary();
};

const sendBridgeRequestBytes = async (
  method: string,
  requestBytes: Uint8Array,
): Promise<Uint8Array> => {
  const b = mustBridge();

  const waitForBinaryBridgeReady = async (): Promise<void> => {
    const maybeBridge = b as unknown as { isAvailable?: () => boolean };
    if (typeof maybeBridge.isAvailable !== 'function' || maybeBridge.isAvailable()) {
      return;
    }

    await new Promise<void>((resolve) => {
      let done = false;
      const finish = () => {
        if (!done) {
          done = true;
          resolve();
        }
      };
      const onReady = () => finish();
      if (typeof window !== 'undefined') {
        window.addEventListener('dsm-bridge-ready', onReady, { once: true });
      }
      setTimeout(() => {
        if (typeof window !== 'undefined') {
          window.removeEventListener('dsm-bridge-ready', onReady);
        }
        finish();
      }, 2500);
    });
  };

  // Test harness / node environment hook: allow unit tests to provide a minimal
  // bytes-only bridge without MessagePort plumbing.
  // Contract: __callBin(BridgeRpcRequest bytes) -> Promise<Uint8Array>.
  if (typeof b.__callBin === 'function') {
    const respBytes = await b.__callBin(requestBytes);
    const resp = await unwrapProtobufResponse(method, normalizeToBytes(respBytes));
    // For router methods, strip the 8-byte request ID prefix that Kotlin always
    // prepends (see BridgeRouterHandler.appRouterQuery/appRouterInvoke — all paths
    // copy reqId into position 0). The reqId is random bytes, so checking the first
    // byte for 0x03 is unreliable (breaks 1/256 of the time).
    if ((method === 'appRouterQuery' || method === 'appRouterInvoke') && resp.length >= 8) {
      return resp.slice(8);
    }
    return resp;
  }

  if (b.__binary === true && typeof b.sendMessageBin === 'function') {
    await waitForBinaryBridgeReady();

    // MessagePort bridge
    // sendMessageBin expects (method: string, payload: Uint8Array).
    // The page-level sendMessageBin (index.html) now handles message correlation
    // (8-byte float message IDs) internally and resolves with only the response
    // payload bytes. Therefore we send the payload as-is and do not add our own
    // correlation prefix.
    
    const respBytes = await b.sendMessageBin(requestBytes);
    const respFramed = normalizeToBytes(respBytes);

    const resp = await unwrapProtobufResponse(method, maybeUnframe(respFramed));

    // For router methods, strip the 8-byte request ID prefix that Kotlin always
    // prepends (see BridgeRouterHandler.appRouterQuery/appRouterInvoke — all paths
    // copy reqId into position 0). The reqId is random bytes, so checking the first
    // byte for 0x03 is unreliable (breaks 1/256 of the time).
    if ((method === 'appRouterQuery' || method === 'appRouterInvoke') && resp.length >= 8) {
      return resp.slice(8);
    }

    // The response is the raw protobuf payload after unframing (page-level
    // sendMessageBin already handled message ID correlation).
    return resp;
  }

  throw new Error('DSM bridge not available (bytes-only MessagePort required)');
};

export async function callBin(method: string, payload?: Uint8Array): Promise<Uint8Array> {
  const reqBytes = buildBridgeRequest(method, payload);
  return sendBridgeRequestBytes(method, reqBytes);
}

// Resolve BLE address for a 32-byte device_id (native lookup). Returns UTF-8 address bytes.
export async function resolveBleAddressForDeviceIdBridge(deviceId: Uint8Array): Promise<string | undefined> {
  const bytes = deviceId instanceof Uint8Array ? deviceId : new Uint8Array(0);
  if (bytes.length !== 32) return undefined;
  const resp = await callBin('resolveBleAddressForDeviceId', bytes);
  if (!resp || resp.length === 0) return undefined;
  const s = new TextDecoder().decode(resp).trim();
  return s || undefined;
}

/**
 * Decrypt an encrypted recovery capsule (e.g., imported via NFC) using the provided mnemonic key.
 *
 * Transport rules:
 * - protobuf-only
 * - bytes-only (no JSON)
 *
 * IMPORTANT: This uses the strict core/SDK handler routing for RecoveryCapsuleDecryptRequest.
 */
export async function decryptRecoveryCapsuleStrict(
  encryptedCapsule: Uint8Array,
  mnemonicKey: Uint8Array,
): Promise<import('../proto/dsm_app_pb').RecoveryCapsuleDecryptResponse> {
  const pb = await import('../proto/dsm_app_pb');

  // Defensive copy to satisfy generated protobuf typings (Uint8Array<ArrayBuffer>).
  // Some environments type Uint8Array as Uint8Array<ArrayBufferLike> (e.g., SharedArrayBuffer-capable),
  // which makes TS reject direct assignment.
  const encryptedCapsuleBytes = new Uint8Array(encryptedCapsule);
  const mnemonicKeyBytes = new Uint8Array(mnemonicKey);

  const req = new pb.Envelope({
    version: ENVELOPE_V3,
    payload: {
      case: 'universalTx',
      value: new pb.UniversalTx({
        atomic: true,
        ops: [
          new pb.UniversalOp({
            kind: {
              case: 'recoveryCapsuleDecrypt',
              value: new pb.RecoveryCapsuleDecryptRequest({
                encryptedCapsule: encryptedCapsuleBytes,
                mnemonicKey: mnemonicKeyBytes,
              }),
            },
          }),
        ],
      }),
    },
  });

  const resBytes = await bridgeGate.enqueue(() => callBin('processEnvelopeV3', req.toBinary()));
  const resEnv = decodeFramedEnvelopeV3(resBytes);
  const payload = resEnv.payload;

  // Expected: UniversalRx with OpResult containing RecoveryCapsuleDecryptResponse in ResultPack.body
  const rx = payload?.case === 'universalRx' ? payload.value : undefined;
  if (!rx || !Array.isArray(rx.results) || rx.results.length < 1) {
    throw new Error('recovery_capsule_decrypt: missing UniversalRx results');
  }
  const first = rx.results[0];
  const accepted = Boolean(first?.accepted);
  if (!accepted) {
    const err = first?.error;
    const msg = typeof err?.message === 'string' ? err.message : 'recovery_capsule_decrypt rejected';
    throw new Error(msg);
  }
  const body: Uint8Array | undefined = first?.result?.body;
  if (!(body instanceof Uint8Array) || body.length === 0) {
    throw new Error('recovery_capsule_decrypt: empty response body');
  }
  return pb.RecoveryCapsuleDecryptResponse.fromBinary(body);
}


/**
 * Request BLE permissions from the Android system.
 * Transport: RPC "requestBlePermissions"
 * Input: empty
 * Output: empty (permissions requested asynchronously)
 */
export async function requestBlePermissions(): Promise<void> {
  await callBin('requestBlePermissions', new Uint8Array(0));
}

/**
 * Open the device's native Bluetooth settings screen.
 * Transport: RPC "openBluetoothSettings"
 * Input: empty
 * Output: empty (settings opened; fire-and-forget)
 */
export async function openBluetoothSettings(): Promise<void> {
  await callBin('openBluetoothSettings', new Uint8Array(0));
}

/**
 * Start the Rust-driven pairing orchestrator loop.
 * Scans all unpaired contacts and drives BLE pairing automatically.
 * Fire-and-forget — status updates arrive via 'ble.pairingStatus' bridgeEvents.
 *
 * Transport: RPC "startPairingAll"
 * Input: empty
 * Output: empty (loop runs asynchronously in Rust)
 */
export async function startPairingAll(): Promise<void> {
  try {
    await callBin('startPairingAll', new Uint8Array(0));
  } catch (e) {
    log.warn('[BLE] startPairingAll failed:', e);
  }
}

/**
 * Signal the Rust pairing orchestrator to stop its loop.
 *
 * Transport: RPC "stopPairingAll"
 * Input: empty
 * Output: empty
 */
export async function stopPairingAll(): Promise<void> {
  try {
    await callBin('stopPairingAll', new Uint8Array(0));
  } catch (e) {
    log.warn('[BLE] stopPairingAll failed:', e);
  }
}

// Export persisted bridge diagnostics log (if present).
export async function getDiagnosticsLogStrict(): Promise<Uint8Array> {
  try {
    const resBytes = await callBin('getDiagnosticsLog', new Uint8Array(0));
    return resBytes instanceof Uint8Array ? resBytes : new Uint8Array(0);
  } catch {
    return new Uint8Array(0);
  }
}

/**
 * Convenience re-export for consumers that import from WebViewBridge rather
 * than services/telemetry. Delegates to getDiagnosticsLogStrict.
 */
export async function exportDiagnosticsReport(): Promise<Uint8Array> {
  return getDiagnosticsLogStrict();
}



async function maybeThrowOnEmpty(result: Uint8Array): Promise<Uint8Array> {
  if (result.length > 0) return result;
  const b = mustBridge();
  try {
    if (typeof b.lastError === 'function') {
      const msg = b.lastError();
      if (msg && typeof msg === 'string' && msg.length > 0) {
        throw new Error(`DSM native error: ${msg}`);
      }
    }
  } catch (e) {
    // Only swallow retrieval errors; propagate intentional DSM native error
    if (e instanceof Error && /DSM native error/.test(e.message)) throw e;
  }
  return result;
}

// --- Public API ---
export async function processEnvelopeV3Bin(envelopeBytes: Uint8Array): Promise<Uint8Array> {
  return bridgeGate.enqueue(() => callBin('processEnvelopeV3', envelopeBytes));
}

// --- App router invoke/query (bytes-only) ---
export async function appRouterInvokeBin(method: string, args?: Uint8Array): Promise<Uint8Array> {
  if (typeof method !== 'string' || method.length === 0) {
    throw new Error('appRouterInvokeBin: method required');
  }
  const appRouterPayload = new AppRouterPayload({
    methodName: method,
    args: args instanceof Uint8Array ? new Uint8Array(args) : new Uint8Array(0),
  });
  const req = new BridgeRpcRequest({
    method: 'appRouterInvoke',
    payload: { case: 'appRouter', value: appRouterPayload },
  });
  const reqBytes = req.toBinary();
  return bridgeGate.enqueue(() => sendBridgeRequestBytes('appRouterInvoke', reqBytes));
}

export async function appRouterQueryBin(path: string, params?: Uint8Array): Promise<Uint8Array> {
  if (typeof path !== 'string' || path.length === 0) {
    throw new Error('appRouterQueryBin: path required');
  }
  const req = new BridgeRpcRequest({
    method: 'appRouterQuery',
    payload: {
      case: 'appRouter',
      value: new AppRouterPayload({
        methodName: path,
        args: params instanceof Uint8Array ? new Uint8Array(params) : new Uint8Array(0),
      }),
    },
  });
  const reqBytes = req.toBinary();
  return bridgeGate.enqueue(() => sendBridgeRequestBytes('appRouterQuery', reqBytes));
}

/**
 * Fetch raw Headers proto bytes via the dedicated Kotlin bypass route.
 *
 * Does NOT route through appRouter to avoid the ArgPack / Envelope v3 decode
 * ambiguity. `getTransportHeadersV3Bin` returns raw `Headers` proto bytes
 * (deviceId + genesisHash) directly from the Rust SDK, which is exactly what
 * `identity.ts / readFromBridge` passes to `pb.Headers.fromBinary()`.
 *
 * Returns empty Uint8Array if the SDK is not yet initialized (cold-start race);
 * callers should retry until non-empty.
 */
export async function queryTransportHeadersV3(): Promise<Uint8Array> {
  const responseBytes = await callBin('getTransportHeadersV3Bin', new Uint8Array(0));
  return maybeThrowOnEmpty(responseBytes);
}

export async function createGenesisViaRouter(locale: string, networkId: string, entropy: Uint8Array): Promise<Uint8Array> {
  if (entropy.length !== 32) throw new Error('entropy must be 32 bytes');
  const req = new CreateGenesisPayload({
    locale: String(locale ?? ''),
    networkId: String(networkId ?? ''),
    entropy: new Uint8Array(entropy),
  });
  const res = await appRouterInvokeBin('identity.genesis.create', req.toBinary());
  return maybeThrowOnEmpty(res);
}

export async function startNativeQrScannerViaRouter(): Promise<void> {
  dispatchNativeQrScannerActive(true);
  try {
    await appRouterInvokeBin('device.qr.scan.start', new Uint8Array(0));
  } catch (error) {
    dispatchNativeQrScannerActive(false);
    throw error;
  }
}

export async function startBleScanViaRouter(): Promise<void> {
  await appRouterInvokeBin('device.ble.scan.start', new Uint8Array(0));
}

export async function stopBleScanViaRouter(): Promise<void> {
  await appRouterInvokeBin('device.ble.scan.stop', new Uint8Array(0));
}

export async function startBleAdvertisingViaRouter(): Promise<{ success: boolean; error?: { message?: string } }> {
  try {
    await appRouterInvokeBin('device.ble.advertise.start', new Uint8Array(0));
    return { success: true };
  } catch (e) {
    return { success: false, error: { message: e instanceof Error ? e.message : 'device.ble.advertise.start failed' } };
  }
}

export async function stopBleAdvertisingViaRouter(): Promise<{ success: boolean; error?: { message?: string } }> {
  try {
    await appRouterInvokeBin('device.ble.advertise.stop', new Uint8Array(0));
    return { success: true };
  } catch (e) {
    return { success: false, error: { message: e instanceof Error ? e.message : 'device.ble.advertise.stop failed' } };
  }
}

export async function lockSessionViaRouter(): Promise<void> {
  await appRouterInvokeBin('session.lock', new Uint8Array(0));
}

export async function unlockSessionViaRouter(): Promise<void> {
  await appRouterInvokeBin('session.unlock', new Uint8Array(0));
}

export async function configureLockViaRouter(args: {
  enabled: boolean;
  method: 'pin' | 'combo' | 'biometric';
  lockOnPause: boolean;
}): Promise<void> {
  const req = new SessionConfigureLockRequest({
    enabled: args.enabled,
    method: args.method,
    lockOnPause: args.lockOnPause,
  });
  const argPack = new ArgPack({
    codec: Codec.PROTO,
    body: new Uint8Array(req.toBinary()),
  });
  await appRouterInvokeBin('session.configure_lock', argPack.toBinary());
}

// --- BLE bilateral offline send (bytes-only) ---
// Frame payload: [u32be bleAddrLen][bleAddr utf8][envelopeBytes]
export async function bilateralOfflineSendBin(envelopeBytes: Uint8Array, bleAddress: string, p0: string): Promise<Uint8Array> {
  void p0;
  if (!(envelopeBytes instanceof Uint8Array) || envelopeBytes.length === 0) {
    throw new Error('bilateralOfflineSendBin: envelopeBytes required');
  }
  if (typeof bleAddress !== 'string' || bleAddress.length === 0) {
    throw new Error('bilateralOfflineSendBin: bleAddress required');
  }

  const addrBytes = new TextEncoder().encode(bleAddress);
  const args = new Uint8Array(4 + addrBytes.length + envelopeBytes.length);
  const addrLen = addrBytes.length;
  args[0] = (addrLen >>> 24) & 0xff;
  args[1] = (addrLen >>> 16) & 0xff;
  args[2] = (addrLen >>> 8) & 0xff;
  args[3] = addrLen & 0xff;
  args.set(addrBytes, 4);
  args.set(envelopeBytes, 4 + addrBytes.length);

  const req = new BridgeRpcRequest({
    method: 'appRouterInvoke',
    payload: {
      case: 'appRouter',
      value: new AppRouterPayload({
        methodName: 'bilateralOfflineSend',
        args,
      }),
    },
  });
  const res = await bridgeGate.enqueue(() => sendBridgeRequestBytes('appRouterInvoke', req.toBinary()));
  return res;
}

export async function getTransportHeadersV3Bin(): Promise<Uint8Array> {
  return queryTransportHeadersV3();
}

export async function createGenesisBin(locale: string, networkId: string, entropy: Uint8Array): Promise<Uint8Array> {
  return createGenesisViaRouter(locale, networkId, entropy);
}

/**
 * Inject genesis + device_id into native BLE layer to enable advertising after genesis creation.
 * @param genesisHash - 32-byte genesis hash
 * @param deviceId - 32-byte device_id
 */
export async function setBleIdentityForAdvertising(genesisHash: Uint8Array, deviceId: Uint8Array): Promise<void> {
  if (genesisHash.length !== 32) throw new Error('setBleIdentityForAdvertising: genesis_hash must be 32 bytes');
  if (deviceId.length !== 32) throw new Error('setBleIdentityForAdvertising: device_id must be 32 bytes');

  const req = new BleIdentityPayload({
    genesisHash: new Uint8Array(genesisHash),
    deviceId: new Uint8Array(deviceId),
  });

  await bridgeGate.enqueue(() => callBin('setBleIdentityForAdvertising', req.toBinary()));
}

/**
 * Add a secondary device to an existing genesis
 * @param genesisHash - Genesis hash from root device (32 bytes)
 * @param deviceEntropy - New device's entropy (32 bytes)
 * @returns Envelope v3 response with new device_id bound to genesis
 */
export async function addSecondaryDeviceBin(genesisHash: Uint8Array, deviceEntropy: Uint8Array): Promise<Uint8Array> {
  const pb = await import('../proto/dsm_app_pb');
  const genesisHashBytes = new Uint8Array(genesisHash);
  const deviceEntropyBytes = new Uint8Array(deviceEntropy);
  const req = new pb.SecondaryDeviceRequest({
    genesisHash: genesisHashBytes,
    deviceEntropy: deviceEntropyBytes,
  });
  const arg = new pb.ArgPack({
    codec: pb.Codec.PROTO,
    body: toBytes(req.toBinary()),
  });
  const res = await appRouterInvokeBin('system.secondary_device', arg.toBinary());
  // Canonical Envelope v3 decode
  const env = decodeFramedEnvelopeV3(res);
  if (env.payload.case === 'error') {
    const errMsg = env.payload.value.message || `Error code ${env.payload.value.code}`;
    throw new Error(`initializeSecondaryDevice failed: ${errMsg}`);
  }
  if (env.payload.case === 'secondaryDeviceResponse') {
    return env.payload.value.toBinary();
  }
  throw new Error(`initializeSecondaryDevice failed: unexpected payload case ${env.payload.case}`);
}

/**
 * Get a persisted preference string from the native bridge.
 * @param key The preference key
 */
export async function getPreference(key: string): Promise<string | null> {
  try {
    const req = new AppStateRequest({
      key: String(key),
      operation: 'get',
      value: '',
    });
    const arg = new ArgPack({
      codec: Codec.PROTO,
      body: toBytes(req.toBinary()),
    });
    const res = await appRouterQueryBin('prefs.get', arg.toBinary());
    if (!res || res.length === 0) return null;
    
    // Canonical Envelope v3 decode
    const env = decodeFramedEnvelopeV3(res);
    if (env.payload.case === 'error') {
      log.warn('getPreference native error:', env.payload.value.message);
      return null;
    }
    if (env.payload.case !== 'appStateResponse') {
      log.warn(`Expected appStateResponse, got ${env.payload.case}`);
      return null;
    }
    const resp = env.payload.value;
    return resp.value ?? null;
  } catch (e) {
    log.warn('getPreference failed', e);
    return null;
  }
}

/**
 * Set a persisted preference string in the native bridge.
 * @param key The preference key
 * @param value The value to store
 */
export async function setPreference(key: string, value: string): Promise<void> {
  try {
    const req = new AppStateRequest({
      key: String(key),
      operation: 'set',
      value: String(value ?? ''),
    });
    const arg = new ArgPack({
      codec: Codec.PROTO,
      body: toBytes(req.toBinary()),
    });
    const res = await appRouterQueryBin('prefs.set', arg.toBinary());
    if (!res || res.length === 0) return;

    // Canonical Envelope v3 decode
    const env = decodeFramedEnvelopeV3(res);
    if (env.payload.case === 'error') {
      log.warn('setPreference native error:', env.payload.value.message);
      return;
    }
    if (env.payload.case === 'appStateResponse') {
      // Success - state response decoded
      return;
    }
  } catch (e) {
    log.warn('setPreference failed', e);
  }
}

export interface ArchitectureInfo {
  status: 'COMPATIBLE' | 'UNSUPPORTED_ABI' | 'INCOMPATIBLE_JVM' | 'UNKNOWN';
  deviceArch: string;
  supportedAbis: string;
  message: string;
  recommendation: string;
}

/**
 * Get device architecture compatibility information for diagnostics.
 * Returns architecture details and compatibility status.
 * 
 * @returns Promise<ArchitectureInfo> containing architecture status and recommendations
 */
export async function getArchitectureInfo(): Promise<ArchitectureInfo> {
  try {
    const bytes = await callBin('getArchitectureInfo');
     if (!bytes || bytes.length === 0) {
       return {
         status: 'UNKNOWN',
         deviceArch: 'unavailable',
         supportedAbis: '',
         message: 'Architecture info not available (empty response)',
         recommendation: ''
       };
    }
    const parsed = ArchitectureInfoProto.fromBinary(bytes);
    return {
      status: (parsed.status || 'UNKNOWN') as ArchitectureInfo['status'],
      deviceArch: parsed.deviceArch || 'unknown',
      supportedAbis: parsed.supportedAbis || '',
      message: parsed.message || 'Unknown',
      recommendation: parsed.recommendation || ''
    };
  } catch (e) {
    log.warn('Failed to get architecture info from bridge:', e);
    return {
      status: 'UNKNOWN',
      deviceArch: 'error',
      supportedAbis: '',
      message: 'Architecture check error',
      recommendation: ''
    };
  }
}

// ---- Event channel (UI-only listeners; payload is bytes) ----
export type DsmEvent = { topic: string; payload: Uint8Array };

export function addDsmEventListener(fn: (evt: DsmEvent) => void): () => void {
  const handler = (evt: Event) => {
    try {
      const detail = (evt as CustomEvent).detail as { topic?: unknown; payload?: unknown } | undefined;
      const topic: string | undefined = typeof detail?.topic === 'string' ? detail.topic : undefined;
      const payloadRaw = detail?.payload;
      if (!topic) return;
      const payload = normalizeToBytes(payloadRaw ?? new Uint8Array(0));
      fn({ topic, payload });
    } catch (e) {
      log.warn('[WebViewBridge] dsm-event handler threw:', e);
    }
  };

  window.addEventListener('dsm-event-bin', handler as EventListener);
  return () => window.removeEventListener('dsm-event-bin', handler as EventListener);
}
// ---------- Manual bilateral accept/reject (bytes-only) ----------
export async function acceptBilateralByCommitmentBridge(commitmentHash: Uint8Array): Promise<Uint8Array> {
  if (!(commitmentHash instanceof Uint8Array) || commitmentHash.length !== 32) {
    throw new Error('acceptBilateralByCommitmentBridge: commitmentHash must be 32 bytes');
  }
  const res = await callBin('acceptBilateralByCommitment', commitmentHash);
  return maybeThrowOnEmpty(res);
}

export async function rejectBilateralByCommitmentBridge(commitmentHash: Uint8Array, reason: string): Promise<Uint8Array> {
  if (!(commitmentHash instanceof Uint8Array) || commitmentHash.length !== 32) {
    throw new Error('rejectBilateralByCommitmentBridge: commitmentHash must be 32 bytes');
  }

  const req = new BridgeRpcRequest({
    method: 'rejectBilateralByCommitment',
    payload: {
      case: 'bilateral',
      value: new BilateralPayload({
        commitment: new Uint8Array(commitmentHash),
        reason: String(reason ?? ''),
      }),
    },
  });
  const res = await sendBridgeRequestBytes('rejectBilateralByCommitment', req.toBinary());
  return maybeThrowOnEmpty(res);
}

// ---------- Diagnostics wrappers ----------
/**
 * Get device ID via RPC bridge (async).
 * Returns 32-byte device ID or empty array if not available.
 */
export async function getDeviceIdBinBridgeAsync(): Promise<Uint8Array> {
  try {
    const headers = await queryTransportHeadersV3();
    const hdr = (await import('../proto/dsm_app_pb')).Headers.fromBinary(headers);
    const result = hdr.deviceId instanceof Uint8Array ? hdr.deviceId : new Uint8Array(0);
    if (result.length === 0) {
      log.warn('[WebViewBridge] getDeviceIdBin returned empty');
    }
    return result;
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    log.warn('[WebViewBridge] getDeviceIdBin failed:', msg);
    return new Uint8Array(0);
  }
}

/**
 * Get signing public key via RPC bridge (async).
 * Returns 64-byte SPHINCS+ public key or empty array if not available.
 */
export async function getSigningPublicKeyBinBridgeAsync(): Promise<Uint8Array> {
  try {
    const result = await callBin('getSigningPublicKeyBin', new Uint8Array(0));
    if (result.length === 0) {
      log.warn('[WebViewBridge] getSigningPublicKeyBin returned empty');
    }
    return result;
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    log.warn('[WebViewBridge] getSigningPublicKeyBin failed:', msg);
    return new Uint8Array(0);
  }
}

/**
 * Get signing public key via RPC bridge (async).
 * Returns 64-byte SPHINCS+ public key or empty array if not available.
 */
// Direct bridge methods removed - use router paths instead:
// - identity.pairing_qr for contact QR generation
// - contacts.handle_contact_qr_v3 for QR scanning

export function getAppRouterStatusBridge(): number {
  const b = mustBridge();
  if (typeof b.getAppRouterStatus !== 'function') {
    log.warn('[WebViewBridge] getAppRouterStatus not available');
    return -1;
  }
  try {
    const res = b.getAppRouterStatus();
    if (typeof res === 'number') return res;
    return -1;
  } catch (e: unknown) {
    log.error('[WebViewBridge] getAppRouterStatus failed:', e);
    return -1;
  }
}

export function computeB0xAddressBridge(genesis: Uint8Array, deviceId: Uint8Array, tip: Uint8Array): string {
  const b = mustBridge();
  if (typeof b.computeB0xAddress !== 'function') {
    log.warn('[WebViewBridge] computeB0xAddress not available');
    return '';
  }
  try {
    const g = normalizeToBytes(genesis);
    const d = normalizeToBytes(deviceId);
    const t = normalizeToBytes(tip);
    if (g.length !== 32 || d.length !== 32 || t.length !== 32) {
      log.warn('[WebViewBridge] computeB0xAddress: inputs must be 32 bytes');
      return '';
    }
    const res = b.computeB0xAddress(g, d, t);
    if (typeof res === 'string') return res;
    return '';
  } catch (e: unknown) {
    log.error('[WebViewBridge] computeB0xAddress failed:', e);
    return '';
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function runNativeBridgeSelfTest(): Record<string, any> {
  const b = mustBridge();
  if (typeof b.runNativeBridgeSelfTest !== 'function') {
    return { error: 'method_missing' };
  }
  try {
    const raw = b.runNativeBridgeSelfTest();
    // STRICT: Do not JSON-parse runtime bridge output. If native returns structured
    // data, it should do so via the binary bridge.
    if (typeof raw === 'string') {
      return { raw };
    }
    if (raw && typeof raw === 'object') {
      return { raw };
    }
    return { error: 'invalid_return_type', rawType: typeof raw };
  } catch (e: unknown) {
    return { error: e instanceof Error ? e.message : 'exception' };
  }
}


export async function getContactsStrictBridge(): Promise<Uint8Array> {
  const res = await appRouterQueryBin('contacts.list');
  return maybeThrowOnEmpty(res);
}

export async function getAllBalancesStrictBridge(): Promise<Uint8Array> {
  const b = mustBridge();

  // Use the router path. This is the stable cross-platform behavior.
  if (!(typeof b.__callBin === 'function' || (b.__binary && typeof b.sendMessageBin === 'function'))) {
    throw new Error('getAllBalancesStrictBridge not available (requires binary bridge)');
  }
  // Call the strict JNI endpoint directly to get a FramedEnvelopeV3 (no 8-byte router prefix).
  const res = await bridgeGate.enqueue(() => {
    return callBin('getAllBalancesStrict');
  }) as Uint8Array;
  return maybeThrowOnEmpty(res);
}

export async function getWalletHistoryStrictBridge(): Promise<Uint8Array> {
  const pb = await import('../proto/dsm_app_pb');
  const limitOffset = new Uint8Array(16);
  // limit=0, offset=0 (little-endian u64 each)
  const arg = new pb.ArgPack({
    codec: pb.Codec.PROTO,
    body: toBytes(limitOffset),
  });
  const res = await appRouterQueryBin('wallet.history', arg.toBinary());
  return maybeThrowOnEmpty(res);
}

export async function getInboxStrictBridge(args?: { limit?: number }): Promise<Uint8Array> {
  const b = mustBridge();
  if (!(typeof b.__callBin === 'function' || (b.__binary && typeof b.sendMessageBin === 'function'))) {
    throw new Error('getInboxStrictBridge not available (requires binary bridge)');
  }

  const limit = typeof args?.limit === 'number' ? args.limit : 50;
  const req = new InboxRequest({ limit });
  const arg = new ArgPack({
    codec: Codec.PROTO,
    body: toBytes(req.toBinary()),
  });

  const res = await appRouterQueryBin('inbox.pull', arg.toBinary());
  return maybeThrowOnEmpty(res);
}

export async function getPendingBilateralListStrictBridge(): Promise<Uint8Array> {
  const pb = await import('../proto/dsm_app_pb');
  const arg = new pb.ArgPack({
    codec: pb.Codec.PROTO,
    body: new Uint8Array(0),
  });
  const res = await appRouterQueryBin('bilateral.pending_list', arg.toBinary());
  return maybeThrowOnEmpty(res);
}

export async function syncWithStorageStrictBridge(args?: {
  pullInbox?: boolean;
  pushPending?: boolean;
  limit?: number;
}): Promise<Uint8Array> {
  const b = mustBridge();
  if (!(typeof b.__callBin === 'function' || (b.__binary && typeof b.sendMessageBin === 'function'))) {
    throw new Error('syncWithStorageStrictBridge not available (requires binary bridge)');
  }

  const req = new StorageSyncRequest({
    pullInbox: args?.pullInbox !== false,
    pushPending: args?.pushPending === true,
    limit: typeof args?.limit === 'number' ? args.limit : 50,
  });
  const arg = new ArgPack({
    codec: Codec.PROTO,
    body: toBytes(req.toBinary()),
  });

  const res = await appRouterQueryBin('storage.sync', arg.toBinary());
  return maybeThrowOnEmpty(res);
}

export async function getPersistedGenesisEnvelopeBin(): Promise<Uint8Array> {
  const res = await callBin('getPersistedGenesisEnvelope', new Uint8Array(0));
  return maybeThrowOnEmpty(res);
}

/**
 * Check if native QR scanner is available (ML Kit on Android).
 * @returns true if native scanner can be launched
 */
export async function hasNativeQrScanner(): Promise<boolean> {
  try {
    const res = await callBin('hasNativeQrScanner', new Uint8Array(0));
    return res.length > 0 && res[0] !== 0;
  } catch {
    return false;
  }
}

/**
 * Launch the native QR scanner.
 * Result will be delivered via 'dsm-event' with topic 'qr_scan_result'.
 * Listen for the event to get the scanned QR code or empty string on cancel/error.
 */
export async function startNativeQrScanner(): Promise<void> {
  await startNativeQrScannerViaRouter();
}

// -- Missing Functions from Refactor --

export async function publishTokenPolicyBytes(policyBytes: Uint8Array): Promise<Uint8Array> {
   // Assuming 'tokens.publishPolicy' is the router path
   return await appRouterInvokeBin('tokens.publishPolicy', policyBytes);
}

export async function getTokenPolicyBytes(policyId: Uint8Array): Promise<Uint8Array> {
   return await appRouterQueryBin('tokens.getPolicy', policyId);
}

export async function listCachedTokenPolicies(): Promise<Uint8Array> {
   return await appRouterQueryBin('tokens.listCachedPolicies', new Uint8Array(0));
}

type ResultPackLike = { body?: Uint8Array };
function _extractResultPack(result: unknown): ResultPackLike | undefined {
  if (!result || typeof result !== 'object') return undefined;
  const r = result as {
    resultPack?: ResultPackLike;
    result_pack?: ResultPackLike;
    pack?: ResultPackLike;
    result?: ResultPackLike;
  };
  return r.resultPack ?? r.result_pack ?? r.pack ?? r.result;
}
