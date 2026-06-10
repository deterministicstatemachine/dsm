// SPDX-License-Identifier: Apache-2.0
//
// Additional Device (secondary/Nth device) enrollment — frontend transport only.
//
// ARCHITECTURE: all business logic lives in Rust. This module is pure transport: it forwards the
// inputs to Rust via the agnostic ingress and renders what Rust returns. Rust derives DevID_new,
// runs the co-present BLE admission handshake (the new device requests; the existing device's owner
// approves → gate-signs with its device key → inserts into the genesis Device Tree). The UI never
// derives ids or makes admission decisions; it only generates platform entropy (as genesis does).

import { routerInvokeBin } from '../../dsm/WebViewBridge';
import { decodeFramedEnvelopeV3 } from '../../dsm/decoding';
import { decodeContactQrV3Payload } from '../qr/contactQrService';
import { encodeBase32Crockford } from '../../utils/textId';
import * as pb from '../../proto/dsm_app_pb';

export type AdmissionResult = { ok: boolean; message?: string };

function argpack(body: Uint8Array): Uint8Array {
  return new pb.ArgPack({ codec: pb.Codec.PROTO, body }).toBinary();
}

function readValue(resBytes: Uint8Array): { ok: boolean; value?: string; error?: string } {
  if (!resBytes || resBytes.length === 0) return { ok: false, error: 'empty response' };
  const env = decodeFramedEnvelopeV3(resBytes);
  if (env.payload.case === 'error') {
    return { ok: false, error: env.payload.value?.message ?? 'error' };
  }
  if (env.payload.case === 'appStateResponse') {
    return { ok: true, value: env.payload.value?.value ?? '' };
  }
  return { ok: true };
}

/**
 * Decode the existing device's scanned/pasted QR (ContactQrV3). Pure decode — returns the genesis
 * + device id (Base32) for display, or null if invalid.
 */
export function readGenesisFromQr(
  qrData: string,
): { genesisHashB32: string; deviceIdB32: string } | null {
  const decoded = decodeContactQrV3Payload(qrData);
  if (!decoded?.contact?.genesisHash?.length) return null;
  const c = decoded.contact;
  return {
    genesisHashB32: encodeBase32Crockford(c.genesisHash),
    deviceIdB32: c.deviceId?.length ? encodeBase32Crockford(c.deviceId) : '',
  };
}

/**
 * NEW device: start the admission handshake. `qrData` is the existing device's QR (carries genesis
 * + its signing pubkey); `bleAddress` is the existing device's BLE address (from discovery). Rust
 * derives DevID_new, builds the request, and sends it; the existing device's owner then approves.
 */
export async function requestAdmission(
  qrData: string,
  bleAddress: string,
): Promise<AdmissionResult> {
  const decoded = decodeContactQrV3Payload(qrData);
  if (!decoded?.contact?.genesisHash?.length) {
    return { ok: false, message: 'Not a valid genesis device QR.' };
  }
  const contact = pb.ContactQrV3.fromBinary(decoded.rawBytes);
  if (!contact.signingPublicKey?.length) {
    return { ok: false, message: 'QR is missing the existing device’s signing key.' };
  }
  if (!bleAddress) {
    return { ok: false, message: 'No Bluetooth address for the existing device.' };
  }
  const entropy = crypto.getRandomValues(new Uint8Array(32));
  const req = new pb.AddDeviceAdmissionInitiateV1({
    genesisHash: contact.genesisHash,
    entropy,
    signerSigningPubkey: contact.signingPublicKey,
    bleAddress,
  });
  const res = readValue(await routerInvokeBin('device.requestAdmission', argpack(req.toBinary())));
  return res.ok
    ? { ok: true, message: 'Request sent — approve it on the existing device.' }
    : { ok: false, message: res.error };
}

/**
 * EXISTING device: poll for a pending admission. Returns the requesting device id (Base32) the
 * owner is being asked to approve, or '' if none.
 */
export async function pollPendingAdmission(): Promise<string> {
  const res = readValue(await routerInvokeBin('device.pendingAdmission', argpack(new Uint8Array(0))));
  return res.ok ? res.value ?? '' : '';
}

/** EXISTING device: owner approves the pending admission — Rust gate-signs, inserts, and replies. */
export async function approveAdmission(): Promise<AdmissionResult> {
  const res = readValue(await routerInvokeBin('device.approveAdmission', argpack(new Uint8Array(0))));
  return res.ok ? { ok: true, message: 'Approved.' } : { ok: false, message: res.error };
}
