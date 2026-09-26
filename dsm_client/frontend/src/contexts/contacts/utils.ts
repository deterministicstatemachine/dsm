/* eslint-disable security/detect-object-injection */
// SPDX-License-Identifier: Apache-2.0
// Contacts utilities. Base32 Crockford ONLY.
import { toBase32Crockford } from '../../dsm/decoding';

export function bytesToDisplay(u8: Uint8Array): string {
  if (!(u8 instanceof Uint8Array)) return '';
  return toBase32Crockford(u8);
}
