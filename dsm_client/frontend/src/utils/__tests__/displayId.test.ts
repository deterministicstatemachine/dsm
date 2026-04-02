/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// eslint-env jest
declare const describe: any;
declare const test: any;
declare const expect: any;

import { displayIdentifier, shortId } from '../displayId';

describe('displayIdentifier', () => {
  test('returns a Base32 Crockford string for 32 bytes', () => {
    const id = new Uint8Array(32).fill(0);
    const result = displayIdentifier(id);
    expect(typeof result).toBe('string');
    expect(result.length).toBeGreaterThan(0);
    expect(/^[0-9A-HJKMNP-TV-Z]+$/.test(result)).toBe(true);
  });

  test('produces different output for different inputs', () => {
    const a = new Uint8Array(32).fill(0);
    const b = new Uint8Array(32).fill(1);
    expect(displayIdentifier(a)).not.toBe(displayIdentifier(b));
  });

  test('throws for non-Uint8Array', () => {
    expect(() => displayIdentifier('hello' as any)).toThrow('must be a Uint8Array');
    expect(() => displayIdentifier(null as any)).toThrow('must be a Uint8Array');
    expect(() => displayIdentifier(undefined as any)).toThrow('must be a Uint8Array');
    expect(() => displayIdentifier(42 as any)).toThrow('must be a Uint8Array');
  });

  test('throws for wrong byte length', () => {
    expect(() => displayIdentifier(new Uint8Array(31))).toThrow('exactly 32 bytes');
    expect(() => displayIdentifier(new Uint8Array(33))).toThrow('exactly 32 bytes');
    expect(() => displayIdentifier(new Uint8Array(0))).toThrow('exactly 32 bytes');
  });

  test('is deterministic', () => {
    const id = new Uint8Array(32).map((_, i) => (i * 13) & 0xff);
    expect(displayIdentifier(id)).toBe(displayIdentifier(id));
  });
});

describe('shortId', () => {
  test('returns first 8 characters of the full identifier', () => {
    const id = new Uint8Array(32).map((_, i) => (i * 7) & 0xff);
    const full = displayIdentifier(id);
    const short = shortId(id);
    expect(short).toBe(full.substring(0, 8));
    expect(short.length).toBe(8);
  });

  test('throws for invalid input (delegates to displayIdentifier)', () => {
    expect(() => shortId(null as any)).toThrow();
    expect(() => shortId(new Uint8Array(16))).toThrow();
  });
});
