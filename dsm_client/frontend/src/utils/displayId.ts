/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// Centralized SDK utility for identifier display.
// Enforces that all cryptographic identifiers are passed as raw Uint8Array across the bridge.
// Only this utility is allowed to convert them to base32 for display purposes.

import { encodeBase32Crockford32 } from './textId';

/**
 * Converts a raw 32-byte identifier to its canonical Base32 string representation for display.
 * Throws if the input is not a valid 32-byte Uint8Array.
 */
export function displayIdentifier(id: Uint8Array): string {
  if (!(id instanceof Uint8Array)) {
    throw new Error('Identifier must be a Uint8Array');
  }
  if (id.length !== 32) {
    throw new Error(`Identifier must be exactly 32 bytes, got ${id.length}`);
  }
  return encodeBase32Crockford32(id);
}

/**
 * Converts a raw 32-byte identifier to a short display string (first 8 chars).
 * Throws if the input is not a valid 32-byte Uint8Array.
 */
export function shortId(id: Uint8Array): string {
  return displayIdentifier(id).substring(0, 8);
}
