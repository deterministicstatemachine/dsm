/* eslint-disable security/detect-object-injection */
// SPDX-License-Identifier: Apache-2.0

import { getBridgeInstance } from '../bridge/BridgeRegistry';
import logger from '../utils/logger';
import type { AndroidBridgeV3 } from './bridgeTypes';
import {
  BridgeRpcRequest,
  BridgeRpcResponse,
  BytesPayload,
  DrainEventsOp,
  EmptyPayload,
  EnvelopeOp,
  IngressRequest,
  IngressResponse,
  RouterInvokeOp,
  RouterQueryOp,
  SdkEvent,
  SdkEventBatch,
  SdkEventKind,
  StartupRequest,
  StartupResponse,
} from '../proto/dsm_app_pb';

const EVENT_DRAIN_INTERVAL_MS = 250;
const EVENT_DRAIN_BATCH_SIZE = 32;

let eventPumpStarted = false;
let eventPumpDisabled = false;
let drainInFlight = false;

function mustBridge(): AndroidBridgeV3 {
  const bridge = getBridgeInstance();
  if (!bridge) {
    throw new Error('DSM bridge not available');
  }
  return bridge;
}

function normalizeToBytes(data: unknown): Uint8Array {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (Array.isArray(data)) return new Uint8Array(data);
  throw new Error('expected Uint8Array response from native boundary');
}

function buildBridgeRequest(method: string, payload: Uint8Array): Uint8Array {
  const req = new BridgeRpcRequest({
    method,
    payload:
      payload.length > 0
        ? { case: 'bytes', value: new BytesPayload({ data: new Uint8Array(payload) }) }
        : { case: 'empty', value: new EmptyPayload({}) },
  });
  return req.toBinary();
}

function unwrapBridgeRpcResponse(method: string, responseBytes: Uint8Array): Uint8Array {
  const response = BridgeRpcResponse.fromBinary(responseBytes);
  if (response.result.case === 'success') {
    const data = response.result.value?.data;
    return data instanceof Uint8Array ? data : new Uint8Array(0);
  }
  if (response.result.case === 'error') {
    const message = response.result.value?.message || `bridge error while calling ${method}`;
    throw new Error(message);
  }
  throw new Error(`empty bridge response for ${method}`);
}

async function callBoundaryMethod(method: 'nativeBoundaryStartup' | 'nativeBoundaryIngress', payload: Uint8Array): Promise<Uint8Array> {
  const bridge = mustBridge();
  if (method === 'nativeBoundaryStartup' && typeof bridge.startup === 'function') {
    return normalizeToBytes(await bridge.startup(payload));
  }
  if (method === 'nativeBoundaryIngress' && typeof bridge.ingress === 'function') {
    return normalizeToBytes(await bridge.ingress(payload));
  }

  const requestBytes = buildBridgeRequest(method, payload);
  if (typeof bridge.__callBin === 'function') {
    const responseBytes = await bridge.__callBin(requestBytes);
    return unwrapBridgeRpcResponse(method, normalizeToBytes(responseBytes));
  }
  if (bridge.__binary === true && typeof bridge.sendMessageBin === 'function') {
    const responseBytes = await bridge.sendMessageBin(requestBytes);
    return unwrapBridgeRpcResponse(method, normalizeToBytes(responseBytes));
  }
  throw new Error('DSM bridge does not expose the native boundary transport');
}

function encodeStartupRequest(request: StartupRequest | Uint8Array): Uint8Array {
  return request instanceof Uint8Array ? new Uint8Array(request) : request.toBinary();
}

function encodeIngressRequest(request: IngressRequest | Uint8Array): Uint8Array {
  return request instanceof Uint8Array ? new Uint8Array(request) : request.toBinary();
}

function unwrapStartupResponse(responseBytes: Uint8Array): Uint8Array {
  const response = StartupResponse.fromBinary(responseBytes);
  if (response.result.case === 'okBytes') {
    return response.result.value;
  }
  if (response.result.case === 'error') {
    throw new Error(response.result.value?.message || 'startup boundary error');
  }
  throw new Error('startup boundary returned no result');
}

function unwrapIngressResponse(responseBytes: Uint8Array): Uint8Array {
  const response = IngressResponse.fromBinary(responseBytes);
  if (response.result.case === 'okBytes') {
    return response.result.value;
  }
  if (response.result.case === 'error') {
    throw new Error(response.result.value?.message || 'ingress boundary error');
  }
  throw new Error('ingress boundary returned no result');
}

export async function startupBoundary(request: StartupRequest | Uint8Array): Promise<Uint8Array> {
  return callBoundaryMethod('nativeBoundaryStartup', encodeStartupRequest(request));
}

export async function ingressBoundary(request: IngressRequest | Uint8Array): Promise<Uint8Array> {
  return callBoundaryMethod('nativeBoundaryIngress', encodeIngressRequest(request));
}

export async function startupBoundaryOk(request: StartupRequest | Uint8Array): Promise<Uint8Array> {
  return unwrapStartupResponse(await startupBoundary(request));
}

export async function ingressBoundaryOk(request: IngressRequest | Uint8Array): Promise<Uint8Array> {
  return unwrapIngressResponse(await ingressBoundary(request));
}

export function buildRouterQueryIngressRequest(path: string, params?: Uint8Array): IngressRequest {
  return new IngressRequest({
    operation: {
      case: 'routerQuery',
      value: new RouterQueryOp({
        method: path,
        args: params instanceof Uint8Array ? new Uint8Array(params) : new Uint8Array(0),
      }),
    },
  });
}

export function buildRouterInvokeIngressRequest(method: string, args?: Uint8Array): IngressRequest {
  return new IngressRequest({
    operation: {
      case: 'routerInvoke',
      value: new RouterInvokeOp({
        method,
        args: args instanceof Uint8Array ? new Uint8Array(args) : new Uint8Array(0),
      }),
    },
  });
}

export function buildEnvelopeIngressRequest(envelopeBytes: Uint8Array): IngressRequest {
  return new IngressRequest({
    operation: {
      case: 'envelope',
      value: new EnvelopeOp({ envelopeBytes: new Uint8Array(envelopeBytes) }),
    },
  });
}

export function buildDrainEventsIngressRequest(maxEvents = EVENT_DRAIN_BATCH_SIZE): IngressRequest {
  return new IngressRequest({
    operation: {
      case: 'drainEvents',
      value: new DrainEventsOp({ maxEvents }),
    },
  });
}

export function decodeSdkEventToLegacyTopic(eventBytes: Uint8Array): { topic: string; payload: Uint8Array } | null {
  const event = SdkEvent.fromBinary(eventBytes);
  switch (event.kind) {
    case SdkEventKind.SESSION_STATE:
      return { topic: 'session.state', payload: event.payload };
    case SdkEventKind.BILATERAL_EVENT:
      return { topic: 'bilateral.event', payload: event.payload };
    case SdkEventKind.BLE_ENVELOPE:
      return { topic: 'ble.envelope.bin', payload: event.payload };
    case SdkEventKind.INBOX_UPDATED:
      return { topic: 'inbox.updated', payload: event.payload };
    case SdkEventKind.WALLET_REFRESH:
      return { topic: 'dsm-wallet-refresh', payload: event.payload };
    case SdkEventKind.IDENTITY_READY:
      return { topic: 'dsm-identity-ready', payload: event.payload };
    case SdkEventKind.ENV_CONFIG_ERROR:
      return { topic: 'dsm-env-config-error', payload: event.payload };
    case SdkEventKind.BIOMETRIC_RESULT:
      return { topic: 'dsm-biometric-result', payload: event.payload };
    case SdkEventKind.QR_SCAN_RESULT:
      return { topic: 'qr_scan_result', payload: event.payload };
    case SdkEventKind.BLUETOOTH_PERMISSIONS:
      return { topic: 'bluetooth-permissions', payload: event.payload };
    case SdkEventKind.DETERMINISTIC_SAFETY:
      return { topic: 'dsm.deterministicSafety', payload: event.payload };
    case SdkEventKind.CONTACT_BLE_UPDATED:
      return { topic: 'dsm-contact-ble-updated', payload: event.payload };
    case SdkEventKind.NFC_RECOVERY_CAPSULE:
      return { topic: 'nfc-recovery-capsule', payload: event.payload };
    case SdkEventKind.NFC_BACKUP_WRITTEN:
      return { topic: 'nfc.backup_written', payload: event.payload };
    case SdkEventKind.BRIDGE_READY:
      return { topic: 'dsm-bridge-ready', payload: event.payload };
    default:
      return null;
  }
}

function dispatchSdkEvent(eventBytes: Uint8Array): void {
  if (typeof window === 'undefined') return;
  window.dispatchEvent(new CustomEvent('dsm-sdk-event-bin', { detail: { payload: new Uint8Array(eventBytes) } }));
}

export function isBoundaryUnavailableError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  return (
    error.message.includes('Unknown binary RPC method: nativeBoundaryIngress') ||
    error.message.includes('Unknown binary RPC method: nativeBoundaryStartup') ||
    error.message.includes('unhandled __callBin method') ||
    error.message.includes('does not expose the native boundary transport')
  );
}

async function drainSdkEventsOnce(): Promise<void> {
  if (eventPumpDisabled || drainInFlight) return;
  if (!getBridgeInstance()) return;
  drainInFlight = true;
  try {
    let hasMore = true;
    while (hasMore) {
      const batchBytes = await ingressBoundaryOk(buildDrainEventsIngressRequest());
      const batch = SdkEventBatch.fromBinary(batchBytes);
      for (const event of batch.events) {
        dispatchSdkEvent(event.toBinary());
      }
      hasMore = Boolean(batch.hasMore);
    }
  } catch (error) {
    if (isBoundaryUnavailableError(error)) {
      eventPumpDisabled = true;
      return;
    }
    logger.debug('[NativeBoundaryBridge] drainSdkEventsOnce failed', error);
  } finally {
    drainInFlight = false;
  }
}

export function startSdkEventPump(): void {
  if (eventPumpStarted || typeof window === 'undefined') return;
  eventPumpStarted = true;
  void drainSdkEventsOnce();
  window.setInterval(() => {
    void drainSdkEventsOnce();
  }, EVENT_DRAIN_INTERVAL_MS);
}
