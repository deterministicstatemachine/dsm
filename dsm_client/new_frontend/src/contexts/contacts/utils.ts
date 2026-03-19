/* eslint-disable security/detect-object-injection */
// SPDX-License-Identifier: Apache-2.0
// Contacts utilities. Base32 Crockford ONLY.
import { fromBase32Crockford, toBase32Crockford } from '../../dsm/decoding';

export function parseBinary32(input: Uint8Array | string, label: string): Uint8Array {
  if (input instanceof Uint8Array) {
    if (input.length !== 32) throw new Error(`${label} must be 32 bytes, got ${input.length}`);
    return input;
  }
  const trimmed = String(input || '').trim();
  if (!trimmed) throw new Error(`${label} empty`);
  const bytes = fromBase32Crockford(trimmed);
  if (bytes.length !== 32) throw new Error(`${label} must be 32 bytes`);
  return bytes;
}

export function parseBinary64(input: Uint8Array | string, label: string): Uint8Array {
  if (input instanceof Uint8Array) {
    if (input.length !== 64) throw new Error(`${label} must be 64 bytes, got ${input.length}`);
    return input;
  }
  const trimmed = String(input || '').trim();
  if (!trimmed) throw new Error(`${label} empty`);
  const bytes = fromBase32Crockford(trimmed);
  if (bytes.length !== 64) throw new Error(`${label} must be 64 bytes`);
  return bytes;
}

export function bytesToDisplay(u8: Uint8Array): string {
  if (!(u8 instanceof Uint8Array)) return '';
  return toBase32Crockford(u8);
}
