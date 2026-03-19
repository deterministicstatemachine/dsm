/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/services/contacts/blePairingService.ts
// SPDX-License-Identifier: Apache-2.0
// BLE pairing helpers that keep binary/base32 handling out of UI components.

import { decodeBase32Crockford } from '../../utils/textId';

function decodeB32To32Bytes(value: string, label: string): Uint8Array {
  const trimmed = String(value || '').trim();
  const bytes = decodeBase32Crockford(trimmed);
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    throw new Error(`${label} must decode to 32 bytes`);
  }
  return bytes;
}

export function validateBase32Id32(value: string, label: string): { ok: boolean; error?: string } {
  try {
    decodeB32To32Bytes(value, label);
    return { ok: true };
  } catch (e: any) {
    return { ok: false, error: e?.message || `${label} invalid` };
  }
}
