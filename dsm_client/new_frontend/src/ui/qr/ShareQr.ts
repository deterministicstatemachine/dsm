/* eslint-disable @typescript-eslint/no-explicit-any */
// path: dsm_client/new_frontend/src/ui/qr/ShareQr.ts
// SPDX-License-Identifier: Apache-2.0
// Minimal, QR-safe contact payload renderer (protobuf-only, binary-safe)
// Uses bufbuild-style API (new Message({...}); message.toBinary()).

import QRCode from 'qrcode';
import { encodeBase32Crockford as base32CrockfordEncode } from '../../utils/textId';
import { encodeContactQrV3Payload, type ShareQrInput } from '../../services/qr/contactQrService';

type EccLevel = 'L' | 'M' | 'Q' | 'H';
const ECC_LEVEL: EccLevel = 'M';
export { encodeContactQrV3Payload, type ShareQrInput };




/**
 * Render the ContactQrV3 payload to a canvas element.
 * Uses 'byte' mode to ensure binary data is preserved.
 */
export async function renderContactQr(
  canvas: HTMLCanvasElement,
  input: ShareQrInput
): Promise<void> {
  const payload = await encodeContactQrV3Payload(input);
  const b32 = base32CrockfordEncode(payload);
  const uri = `dsm:contact/v3:${b32}`;

  // Use default mode (auto-detect) which handles alphanumeric efficiently
  await QRCode.toCanvas(canvas, uri, {
    errorCorrectionLevel: ECC_LEVEL,
    width: 300,
    margin: 2,
  });
}