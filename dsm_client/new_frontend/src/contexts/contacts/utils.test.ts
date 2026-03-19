/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// eslint-env jest
// Local declarations to satisfy isolated compilation since test files are excluded from tsconfig type-check.
declare const describe: any;
declare const test: any;
declare const expect: any;
import { parseBinary32, bytesToDisplay } from './utils';

describe('contacts utils', () => {
  test('parseBinary32 parses 32-byte Base32 (UPPERCASE) and rejects wrong size', () => {
    // base32 string representing 32 bytes (just use alphabet cycling)
    const raw = new Uint8Array(32).map((_, i) => i);
    const base32 = bytesToDisplay(raw);
    const parsed = parseBinary32(base32, 'genesis_hash');
    expect(parsed).toBeInstanceOf(Uint8Array);
    expect(parsed.length).toBe(32);
    // wrong size (remove last char so decode length !=32)
    expect(() => parseBinary32(base32.slice(0, -1), 'genesis_hash')).toThrow(/32 bytes/);
  });

  test('bytesToDisplay returns UPPERCASE Base32', () => {
    const u8 = new Uint8Array([0, 1, 2, 254, 255]);
    const disp = bytesToDisplay(u8);
    expect(typeof disp).toBe('string');
    // Crockford alphabet: 0-9 and A-Z excluding I, L, O, U
    expect(disp).toMatch(/^[0-9A-TV-Z]+$/);
  });

  test('parseBinary32 throws on empty/whitespace input', () => {
    expect(() => parseBinary32('', 'genesis_hash')).toThrow(/empty/);
    expect(() => parseBinary32('   ', 'genesis_hash')).toThrow(/empty/);
  });

  test('bytesToDisplay returns empty string for non-Uint8Array inputs', () => {
    // @ts-expect-error intentionally sending wrong type
    expect(bytesToDisplay(null)).toBe('');
    // @ts-expect-error intentionally sending wrong type
    expect(bytesToDisplay(undefined)).toBe('');
    // @ts-expect-error intentionally sending wrong type
    expect(bytesToDisplay('not-bytes')).toBe('');
  });
});
