/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// eslint-env jest
declare const describe: any;
declare const test: any;
declare const expect: any;
declare const it: any;

import {
  normalizeBase32Crockford,
  encodeBase32Crockford,
  decodeBase32Crockford,
  encodeBase32Crockford32,
  decodeBase32Crockford32,
  bytesToBase32CrockfordPrefix,
} from '../textId';

describe('normalizeBase32Crockford', () => {
  test('uppercases input', () => {
    expect(normalizeBase32Crockford('abc')).toBe('ABC');
  });

  test('strips spaces and hyphens', () => {
    expect(normalizeBase32Crockford('AB CD-EF')).toBe('ABCDEF');
    expect(normalizeBase32Crockford('  A-B-C  ')).toBe('ABC');
  });

  test('replaces O with 0', () => {
    expect(normalizeBase32Crockford('O')).toBe('0');
    expect(normalizeBase32Crockford('oOo')).toBe('000');
  });

  test('replaces I and L with 1', () => {
    expect(normalizeBase32Crockford('I')).toBe('1');
    expect(normalizeBase32Crockford('L')).toBe('1');
    expect(normalizeBase32Crockford('iLl')).toBe('111');
  });

  test('returns empty string for empty/falsy input', () => {
    expect(normalizeBase32Crockford('')).toBe('');
  });

  test('handles mixed normalizations', () => {
    expect(normalizeBase32Crockford('a-b O I L')).toBe('AB011');
  });
});

describe('encodeBase32Crockford', () => {
  test('returns empty string for empty array', () => {
    expect(encodeBase32Crockford(new Uint8Array([]))).toBe('');
  });

  test('returns empty string for null/undefined', () => {
    expect(encodeBase32Crockford(null as any)).toBe('');
    expect(encodeBase32Crockford(undefined as any)).toBe('');
  });

  test('encodes single byte', () => {
    const result = encodeBase32Crockford(new Uint8Array([0]));
    expect(result).toBe('00');
  });

  test('encodes known byte sequences', () => {
    const bytes = new Uint8Array([0xff]);
    const encoded = encodeBase32Crockford(bytes);
    expect(encoded).toBe('ZW');

    const hello = new TextEncoder().encode('Hello');
    const helloEncoded = encodeBase32Crockford(hello);
    expect(typeof helloEncoded).toBe('string');
    expect(helloEncoded.length).toBeGreaterThan(0);
    expect(/^[0-9A-Z]+$/.test(helloEncoded)).toBe(true);
  });

  test('output contains only Crockford alphabet characters', () => {
    const bytes = new Uint8Array(16).map((_, i) => i * 17);
    const encoded = encodeBase32Crockford(bytes);
    expect(/^[0-9A-HJKMNP-TV-Z]+$/.test(encoded)).toBe(true);
  });
});

describe('decodeBase32Crockford', () => {
  test('returns empty array for empty string', () => {
    const result = decodeBase32Crockford('');
    expect(result).toEqual(new Uint8Array(0));
  });

  test('roundtrips with encode', () => {
    const original = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    const encoded = encodeBase32Crockford(original);
    const decoded = decodeBase32Crockford(encoded);
    expect(decoded).toEqual(original);
  });

  test('handles normalization during decode (O->0, I/L->1)', () => {
    const encoded = encodeBase32Crockford(new Uint8Array([0]));
    const withSubstitutions = encoded.replace(/0/g, 'O');
    const decoded = decodeBase32Crockford(withSubstitutions);
    expect(decoded).toEqual(new Uint8Array([0]));
  });

  test('handles spaces and hyphens', () => {
    const original = new Uint8Array([10, 20, 30]);
    const encoded = encodeBase32Crockford(original);
    const withSpaces = encoded.slice(0, 2) + ' ' + encoded.slice(2);
    const decoded = decodeBase32Crockford(withSpaces);
    expect(decoded).toEqual(original);
  });

  test('throws on invalid characters', () => {
    expect(() => decodeBase32Crockford('U')).toThrow(/Invalid Base32 Crockford character/);
  });

  test('roundtrips 32-byte array', () => {
    const bytes = new Uint8Array(32).map((_, i) => i);
    const encoded = encodeBase32Crockford(bytes);
    const decoded = decodeBase32Crockford(encoded);
    expect(decoded).toEqual(bytes);
  });
});

describe('encodeBase32Crockford32', () => {
  test('encodes exactly 32 bytes', () => {
    const bytes = new Uint8Array(32).fill(0xab);
    const result = encodeBase32Crockford32(bytes);
    expect(typeof result).toBe('string');
    expect(result.length).toBeGreaterThan(0);
  });

  test('throws for non-32-byte input', () => {
    expect(() => encodeBase32Crockford32(new Uint8Array(31))).toThrow('exactly 32 bytes');
    expect(() => encodeBase32Crockford32(new Uint8Array(33))).toThrow('exactly 32 bytes');
    expect(() => encodeBase32Crockford32(new Uint8Array(0))).toThrow('exactly 32 bytes');
  });

  test('throws for non-Uint8Array', () => {
    expect(() => encodeBase32Crockford32('hello' as any)).toThrow('exactly 32 bytes');
    expect(() => encodeBase32Crockford32(null as any)).toThrow('exactly 32 bytes');
  });
});

describe('decodeBase32Crockford32', () => {
  test('roundtrips with encodeBase32Crockford32', () => {
    const original = new Uint8Array(32).map((_, i) => (i * 7) & 0xff);
    const encoded = encodeBase32Crockford32(original);
    const decoded = decodeBase32Crockford32(encoded);
    expect(decoded).toEqual(original);
  });

  test('throws if decoded result is not 32 bytes', () => {
    const short = encodeBase32Crockford(new Uint8Array([1, 2, 3]));
    expect(() => decodeBase32Crockford32(short)).toThrow('exactly 32 bytes');
  });
});

describe('bytesToBase32CrockfordPrefix', () => {
  test('returns empty for non-Uint8Array', () => {
    expect(bytesToBase32CrockfordPrefix(null as any, 4)).toBe('');
    expect(bytesToBase32CrockfordPrefix('hello' as any, 4)).toBe('');
  });

  test('returns empty for zero maxBytes', () => {
    expect(bytesToBase32CrockfordPrefix(new Uint8Array([1, 2, 3]), 0)).toBe('');
  });

  test('returns empty for negative maxBytes', () => {
    expect(bytesToBase32CrockfordPrefix(new Uint8Array([1, 2, 3]), -1)).toBe('');
  });

  test('returns prefix of encoded bytes', () => {
    const bytes = new Uint8Array(64).map((_, i) => i);
    const result = bytesToBase32CrockfordPrefix(bytes, 4);
    expect(typeof result).toBe('string');
    expect(result.length).toBeGreaterThan(0);
    expect(result.length).toBeLessThanOrEqual(40);
  });

  test('clamps maxBytes to array length', () => {
    const bytes = new Uint8Array([0xaa, 0xbb]);
    const full = bytesToBase32CrockfordPrefix(bytes, 100);
    const clamped = bytesToBase32CrockfordPrefix(bytes, 2);
    expect(full).toBe(clamped);
  });

  test('output is capped at 40 characters', () => {
    const bytes = new Uint8Array(128).fill(0xff);
    const result = bytesToBase32CrockfordPrefix(bytes, 128);
    expect(result.length).toBeLessThanOrEqual(40);
  });
});
