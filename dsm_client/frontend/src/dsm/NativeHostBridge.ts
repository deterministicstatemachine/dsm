/* eslint-disable security/detect-object-injection */
// SPDX-License-Identifier: Apache-2.0

import { getBridgeInstance } from '../bridge/BridgeRegistry';
import logger from '../utils/logger';
import type { AndroidBridgeV3 } from './bridgeTypes';
import { bridgeGate } from './BridgeGate';
import {
  BiometricAuthorizePayload,
  BiometricAuthorizeResult,
  BleTransportSendChunksPayload,
  BleTransportSendChunksResult,
  BridgeRpcRequest,
  BridgeRpcResponse,
  BytesPayload,
  DeviceBindingCapturePayload,
  DeviceBindingCaptureResult,
  EmptyPayload,
  HostPermissionsRequestPayload,
  NativeHostAck,
  NativeHostCapabilities,
  NativeHostEvent,
  NativeHostEventKind,
  NativeHostRequest,
  NativeHostRequestKind,
  NativeHostResponse,
  NfcTagReadPayload,
  NfcTagReadResult,
  NfcTagWritePayload,
  NfcTagWriteResult,
  QrScanResultPayload,
} from '../proto/dsm_app_pb';

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

async function callHostMethod(payload: Uint8Array): Promise<Uint8Array> {
  const bridge = mustBridge();
  if (typeof bridge.hostRequest === 'function') {
    return normalizeToBytes(await bridge.hostRequest(payload));
  }

  const requestBytes = buildBridgeRequest('nativeHostRequest', payload);
  if (typeof bridge.__callBin === 'function') {
    const responseBytes = await bridge.__callBin(requestBytes);
    return unwrapBridgeRpcResponse('nativeHostRequest', normalizeToBytes(responseBytes));
  }
  if (bridge.__binary === true && typeof bridge.sendMessageBin === 'function') {
    const responseBytes = await bridge.sendMessageBin(requestBytes);
    return unwrapBridgeRpcResponse('nativeHostRequest', normalizeToBytes(responseBytes));
  }
  throw new Error('DSM bridge does not expose the native host boundary transport');
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
  return (
    error.message.includes('Unknown binary RPC method: nativeHostRequest') ||
    error.message.includes('unhandled __callBin method') ||
    error.message.includes('does not expose the native host boundary transport')
  );
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

export async function captureDeviceBindingForGenesisEnvelope(genesisEnvelope: Uint8Array): Promise<DeviceBindingCaptureResult> {
  const payload = new DeviceBindingCapturePayload({ genesisEnvelope: new Uint8Array(genesisEnvelope) });
  const bytes = await hostRequestOk(
    buildHostRequest(
      NativeHostRequestKind.PLATFORM_PRIMITIVE_DEVICE_BINDING_CAPTURE,
      payload.toBinary(),
    ),
  );
  return DeviceBindingCaptureResult.fromBinary(bytes);
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

export async function sendBleTransportChunksHost(envelopeBytes: Uint8Array, bleAddress: string): Promise<Uint8Array> {
  const payload = new BleTransportSendChunksPayload({
    bleAddress,
    envelopeBytes: new Uint8Array(envelopeBytes),
  });
  const bytes = await hostRequestOk(
    buildHostRequest(
      NativeHostRequestKind.PLATFORM_PRIMITIVE_BLE_TRANSPORT_SEND_CHUNKS,
      payload.toBinary(),
    ),
  );
  return BleTransportSendChunksResult.fromBinary(bytes).responseEnvelope;
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
