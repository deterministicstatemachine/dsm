// SPDX-License-Identifier: Apache-2.0
import {
  decodeBase32Crockford,
  decodeBase32Crockford32,
  encodeBase32Crockford,
  encodeBase32Crockford32,
  normalizeBase32Crockford,
} from '../textId';

function u8(n: number, fill: number): Uint8Array {
  return new Uint8Array(n).fill(fill & 0xff);
}

describe('base32Crockford centralized module', () => {
  test('round-trips arbitrary bytes', () => {
    const bytes = new Uint8Array([0, 1, 2, 3, 250, 251, 252, 253, 254, 255]);
    const s = encodeBase32Crockford(bytes);
    const back = decodeBase32Crockford(s);
    expect(Array.from(back)).toEqual(Array.from(bytes));
  });

  test('normalization strips separators and maps O/I/L', () => {
    const bytes32 = u8(32, 7);
    const enc = encodeBase32Crockford32(bytes32);

    // Introduce lowercase + separators and ambiguous chars.
    // Replace a couple of chars with ambiguous variants while preserving decoded value:
    // 0 -> O, 1 -> I
    const messy = enc
      .replace(/0/g, 'o')
      .replace(/1/g, 'l')
      .replace(/A/g, 'a')
      .replace(/B/g, 'b')
      .replace(/C/g, 'c')
      .split('')
      .map((ch, i) => (i % 5 === 0 ? ch + '-' : ch))
      .join(' ');

    const normalized = normalizeBase32Crockford(messy);
    expect(normalized).toEqual(
      enc
        .toUpperCase()
        .replace(/[\s-]/g, '')
        .replace(/O/g, '0')
        .replace(/[IL]/g, '1')
    );

    const back = decodeBase32Crockford32(messy);
    expect(Array.from(back)).toEqual(Array.from(bytes32));
  });

  test('decode32 throws if not exactly 32 bytes', () => {
    expect(() => decodeBase32Crockford32(encodeBase32Crockford(u8(31, 1)))).toThrow();
    expect(() => decodeBase32Crockford32(encodeBase32Crockford(u8(33, 1)))).toThrow();
  });
});
