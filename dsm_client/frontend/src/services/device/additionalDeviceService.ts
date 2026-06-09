// SPDX-License-Identifier: Apache-2.0
//
// Additional Device (secondary/Nth device) enrollment — frontend transport only.
//
// ARCHITECTURE: all business logic lives in Rust. This module is pure transport: it forwards
// the scanned genesis-device QR (ContactQrV3 bytes) to Rust via the agnostic ingress and renders
// whatever Rust returns. Rust derives DevID_new, drives the BLE admission exchange with the
// existing authorized device (which signs an AddDeviceAdmission with its device signing key),
// verifies the admission, and inserts the new device into the genesis Device Tree. The UI never
// derives ids, generates entropy, or makes admission decisions.

import { routerInvokeBin } from '../../dsm/WebViewBridge';
import { decodeFramedEnvelopeV3 } from '../../dsm/decoding';
import { decodeContactQrV3Payload } from '../qr/contactQrService';
import { encodeBase32Crockford } from '../../utils/textId';

export type AdmissionRequestResult = {
  ok: boolean;
  /** Human-readable status/error surfaced from Rust. */
  message?: string;
};

/**
 * Extract the genesis identity from a scanned/pasted genesis-device QR (ContactQrV3). Pure
 * decode — no logic. Returns null if the QR is not a valid ContactQrV3.
 */
export function readGenesisFromQr(
  qrData: string,
): { genesisHashB32: string; deviceIdB32: string } | null {
  const decoded = decodeContactQrV3Payload(qrData);
  if (!decoded?.contact) return null;
  const c = decoded.contact;
  if (!c.genesisHash?.length) return null;
  return {
    genesisHashB32: encodeBase32Crockford(c.genesisHash),
    deviceIdB32: c.deviceId?.length ? encodeBase32Crockford(c.deviceId) : '',
  };
}

/**
 * Ask Rust to enroll THIS device into the genesis tree advertised by the scanned QR. Forwards
 * the raw ContactQrV3 bytes; Rust extracts the genesis, derives DevID_new, and runs the
 * admission handshake with the existing authorized device. Transport only.
 */
export async function requestAdditionalDeviceAdmission(
  qrData: string,
): Promise<AdmissionRequestResult> {
  const decoded = decodeContactQrV3Payload(qrData);
  if (!decoded) {
    return { ok: false, message: 'Not a valid genesis device QR.' };
  }
  // Forward the validated ContactQrV3 canonical bytes; Rust extracts the genesis + runs admission.
  const resBytes = await routerInvokeBin('device.requestAdmission', decoded.rawBytes);
  if (!resBytes || resBytes.length === 0) {
    return { ok: false, message: 'device.requestAdmission: empty response' };
  }
  const env = decodeFramedEnvelopeV3(resBytes);
  if (env.payload.case === 'error') {
    return { ok: false, message: env.payload.value?.message ?? 'admission failed' };
  }
  return { ok: true, message: 'Device admitted to the genesis tree.' };
}
