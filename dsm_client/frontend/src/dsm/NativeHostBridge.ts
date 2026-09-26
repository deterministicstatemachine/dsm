/* eslint-disable security/detect-object-injection */
// SPDX-License-Identifier: Apache-2.0

import { getBridgeInstance } from '../bridge/BridgeRegistry';
import { bridgeEvents } from '../bridge/bridgeEvents';
import logger from '../utils/logger';
import type { AndroidBridgeV3 } from './bridgeTypes';
import { bridgeGate } from './BridgeGate';
import { BiometricAuthorizePayload, BiometricAuthorizeResult, HostPermissionsRequestPayload, NativeHostAck, NativeHostCapabilities, NativeHostEvent, NativeHostEventKind, NativeHostRequest, NativeHostRequestKind, NativeHostResponse, NfcTagReadPayload, NfcTagReadResult, NfcTagWritePayload, NfcTagWriteResult, QrScanResultPayload } from '../proto/dsm_app_pb';

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
  throw new Error('expected Uint8Array response from native host boundary');
}

async function callHostMethod(payload: Uint8Array): Promise<Uint8Array> {
  // `hostRequest` is the bridge object's own wrapper over the MessagePort
  // (`index.html`); it answers the host's bytes or throws.
  const bridge = mustBridge();
  if (typeof bridge.hostRequest !== 'function') {
    throw new Error('DSM bridge does not expose nativeHostRequest');
  }
  try {
    return normalizeToBytes(await bridge.hostRequest(payload));
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    bridgeEvents.emit('bridge.error', { code: 0, message, debugB32: '' });
    throw e;
  }
}

function encodeRequest(request: NativeHostRequest | Uint8Array): Uint8Array {
  return request instanceof Uint8Array ? new Uint8Array(request) : request.toBinary();
}

function unwrapHostResponse(responseBytes: Uint8Array): Uint8Array {
  const response = NativeHostResponse.fromBinary(responseBytes);
  if (response.result.case === 'okBytes') {
    return response.result.value;
  }
  if (response.result.case === 'capabilities') {
    return response.result.value.toBinary();
  }
  if (response.result.case === 'error') {
    throw new Error(response.result.value?.message || 'native host boundary error');
  }
  throw new Error('native host boundary returned no result');
}

export function isNativeHostUnavailableError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  return error.message.includes('Unknown binary RPC method: nativeHostRequest');
}

export async function hostRequest(request: NativeHostRequest | Uint8Array): Promise<Uint8Array> {
  return bridgeGate.enqueue(() => callHostMethod(encodeRequest(request)));
}

export async function hostRequestOk(request: NativeHostRequest | Uint8Array): Promise<Uint8Array> {
  return unwrapHostResponse(await hostRequest(request));
}

export function buildHostRequest(kind: NativeHostRequestKind, payload?: Uint8Array): NativeHostRequest {
  return new NativeHostRequest({
    kind,
    payload: payload instanceof Uint8Array ? new Uint8Array(payload) : new Uint8Array(0),
  });
}

export async function getNativeHostCapabilities(): Promise<NativeHostCapabilities> {
  const responseBytes = await hostRequest(buildHostRequest(NativeHostRequestKind.HOST_CONTROL_CAPABILITIES_GET));
  const response = NativeHostResponse.fromBinary(responseBytes);
  if (response.result.case === 'capabilities') {
    return response.result.value;
  }
  if (response.result.case === 'error') {
    throw new Error(response.result.value?.message || 'native host capabilities error');
  }
  throw new Error('native host capabilities response missing capabilities');
}

export async function startNativeQrScan(): Promise<void> {
  await hostRequestOk(buildHostRequest(NativeHostRequestKind.HOST_CONTROL_QR_START_SCAN));
}

export async function stopNativeQrScan(): Promise<void> {
  await hostRequestOk(buildHostRequest(NativeHostRequestKind.HOST_CONTROL_QR_STOP_SCAN));
}

export async function startBleScanHost(): Promise<void> {
  await hostRequestOk(buildHostRequest(NativeHostRequestKind.HOST_CONTROL_BLE_SCAN_START));
}

export async function stopBleScanHost(): Promise<void> {
  await hostRequestOk(buildHostRequest(NativeHostRequestKind.HOST_CONTROL_BLE_SCAN_STOP));
}

export async function startBleAdvertisingHost(): Promise<NativeHostAck> {
  const bytes = await hostRequestOk(buildHostRequest(NativeHostRequestKind.HOST_CONTROL_BLE_ADVERTISE_START));
  return NativeHostAck.fromBinary(bytes);
}

export async function stopBleAdvertisingHost(): Promise<NativeHostAck> {
  const bytes = await hostRequestOk(buildHostRequest(NativeHostRequestKind.HOST_CONTROL_BLE_ADVERTISE_STOP));
  return NativeHostAck.fromBinary(bytes);
}

export async function startNfcReaderHost(): Promise<void> {
  await hostRequestOk(buildHostRequest(NativeHostRequestKind.HOST_CONTROL_NFC_READER_START));
}

export async function stopNfcReaderHost(): Promise<void> {
  await hostRequestOk(buildHostRequest(NativeHostRequestKind.HOST_CONTROL_NFC_READER_STOP));
}

export async function requestHostPermissions(permissions: string[]): Promise<void> {
  const payload = new HostPermissionsRequestPayload({ permissions });
  await hostRequestOk(
    buildHostRequest(NativeHostRequestKind.HOST_CONTROL_PERMISSIONS_REQUEST, payload.toBinary()),
  );
}

export async function authorizeBiometricHost(args?: Partial<BiometricAuthorizePayload>): Promise<void> {
  const payload = new BiometricAuthorizePayload(args);
  await hostRequestOk(
    buildHostRequest(
      NativeHostRequestKind.PLATFORM_PRIMITIVE_BIOMETRIC_AUTHORIZE,
      payload.toBinary(),
    ),
  );
}

export async function readNfcTagPayloadHost(mimeType = 'application/vnd.dsm.recovery'): Promise<NfcTagReadResult> {
  const payload = new NfcTagReadPayload({ mimeType });
  const bytes = await hostRequestOk(
    buildHostRequest(
      NativeHostRequestKind.PLATFORM_PRIMITIVE_NFC_TAG_READ_PAYLOAD,
      payload.toBinary(),
    ),
  );
  return NfcTagReadResult.fromBinary(bytes);
}

export async function writeNfcTagPayloadHost(payload?: Uint8Array, mimeType = 'application/vnd.dsm.recovery'): Promise<NfcTagWriteResult> {
  const requestPayload = new NfcTagWritePayload({
    mimeType,
    payload: payload instanceof Uint8Array ? new Uint8Array(payload) : new Uint8Array(0),
  });
  const bytes = await hostRequestOk(
    buildHostRequest(
      NativeHostRequestKind.PLATFORM_PRIMITIVE_NFC_TAG_WRITE_PAYLOAD,
      requestPayload.toBinary(),
    ),
  );
  return NfcTagWriteResult.fromBinary(bytes);
}

export function decodeNativeHostEventToLegacyTopic(eventBytes: Uint8Array): { topic: string; payload: Uint8Array } | null {
  const event = NativeHostEvent.fromBinary(eventBytes);
  switch (event.kind) {
    case NativeHostEventKind.QR_SCAN_RESULT: {
      try {
        const payload = QrScanResultPayload.fromBinary(event.payload);
        return { topic: 'qr_scan_result', payload: new TextEncoder().encode(payload.textUtf8) };
      } catch (error) {
        logger.warn('[NativeHostBridge] malformed QR host event', error);
        return null;
      }
    }
    case NativeHostEventKind.BLUETOOTH_PERMISSIONS:
      return { topic: 'bluetooth-permissions', payload: event.payload };
    case NativeHostEventKind.BIOMETRIC_RESULT: {
      try {
        const payload = BiometricAuthorizeResult.fromBinary(event.payload);
        if (payload.success) {
          return { topic: 'dsm-biometric-result', payload: new Uint8Array([0x01]) };
        }
        const msgBytes = new TextEncoder().encode(payload.errorMessage || '');
        const out = new Uint8Array(3 + msgBytes.length);
        out[0] = 0x00;
        out[1] = (payload.errorCode >>> 8) & 0xff;
        out[2] = payload.errorCode & 0xff;
        out.set(msgBytes, 3);
        return { topic: 'dsm-biometric-result', payload: out };
      } catch (error) {
        logger.warn('[NativeHostBridge] malformed biometric host event', error);
        return null;
      }
    }
    case NativeHostEventKind.NFC_TAG_READ:
      return { topic: 'nfc-recovery-capsule', payload: event.payload };
    case NativeHostEventKind.NFC_TAG_WRITE:
      return { topic: 'nfc.backup_written', payload: event.payload };
    case NativeHostEventKind.SESSION_STATE_HINT:
      return { topic: 'session.state.hint', payload: event.payload };
    default:
      return null;
  }
}
