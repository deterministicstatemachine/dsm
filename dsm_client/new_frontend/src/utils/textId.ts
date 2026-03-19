// SPDX-License-Identifier: Apache-2.0
// Binary-safe textual identifiers for the frontend.
//
// Canonical human-readable encoding in DSM is **Base32 Crockford**.
// This file is the SINGLE source of truth for Base32 Crockford in the frontend.

const CROCKFORD_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ' as const;

/**
 * Normalize Crockford Base32:
 * - uppercase
 * - drop spaces/hyphens
 * - allow common substitutions: O->0, I/L->1
 */
export function normalizeBase32Crockford(s: string): string {
  if (!s) return '';
  return s
    .toUpperCase()
    .replace(/[\s-]/g, '')
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1');
}

/** Base32 Crockford encode (no padding). */
export function encodeBase32Crockford(bytes: Uint8Array): string {
  if (!bytes || bytes.length === 0) return '';

  let bits = 0;
  let value = 0;
  let out = '';

  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      const idx = (value >>> (bits - 5)) & 0x1f;
      out += CROCKFORD_ALPHABET.charAt(idx);
      bits -= 5;
      value &= (1 << bits) - 1;
    }
  }

  if (bits > 0) {
    const idx = (value << (5 - bits)) & 0x1f;
    out += CROCKFORD_ALPHABET.charAt(idx);
  }

  return out;
}

/**
 * Base32 Crockford decode.
 *
 * Strict-ish behavior:
 * - normalizes via `normalizeBase32Crockford`
 * - rejects invalid characters (throws)
 */
export function decodeBase32Crockford(s: string): Uint8Array {
  const clean = normalizeBase32Crockford(s);
  if (!clean) return new Uint8Array(0);

  const out: number[] = [];
  let buffer = 0;
  let bitsLeft = 0;

  for (let i = 0; i < clean.length; i++) {
    const c = clean.charAt(i);
    const idx = CROCKFORD_ALPHABET.indexOf(c);
    if (idx === -1) {
      throw new Error(`Invalid Base32 Crockford character: '${c}'`);
    }

    buffer = (buffer << 5) | idx;
    bitsLeft += 5;

    while (bitsLeft >= 8) {
      out.push((buffer >>> (bitsLeft - 8)) & 0xff);
      bitsLeft -= 8;
    }
  }

  return new Uint8Array(out);
}

export function encodeBase32Crockford32(bytes32: Uint8Array): string {
  if (!(bytes32 instanceof Uint8Array) || bytes32.length !== 32) {
    throw new Error('encodeBase32Crockford32 requires exactly 32 bytes');
  }
  return encodeBase32Crockford(bytes32);
}

export function decodeBase32Crockford32(s: string): Uint8Array {
  const bytes = decodeBase32Crockford(s);
  if (bytes.length !== 32) {
    throw new Error('Base32 Crockford string must decode to exactly 32 bytes');
  }
  return bytes;
}

/**
 * Encode the first N bytes as Base32 Crockford for debug/log prefixes.
 *
 * This is intentionally for *previewing* binary payloads without introducing hex/base64.
 */
export function bytesToBase32CrockfordPrefix(bytes: Uint8Array, maxBytes: number): string {
  if (!(bytes instanceof Uint8Array)) return '';
  const n = Math.min(Math.max(0, maxBytes | 0), bytes.length);
  if (n <= 0) return '';
  return encodeBase32Crockford(bytes.subarray(0, n)).slice(0, 40);
}
