/// <reference types="jest" />
/* eslint-disable @typescript-eslint/no-explicit-any */
import {
  decodeBase32Crockford,
  decodeBase32Crockford32,
  encodeBase32Crockford,
  encodeBase32Crockford32,
  normalizeBase32Crockford,
} from "../textId";

function randomBytes(n: number): Uint8Array {
  const u = new Uint8Array(n);
  for (let i = 0; i < n; i++) u[i] = Math.floor(Math.random() * 256);
  return u;
}

describe('base32 property tests', () => {
  test('roundtrip for 32-byte payload (100 samples)', () => {
    for (let i = 0; i < 100; i++) {
      const original = randomBytes(32);
      const encoded = encodeBase32Crockford32(original);
      expect(encoded).toMatch(/^[0-9A-HJKMNP-TV-Z]+$/);
      const decoded = decodeBase32Crockford32(encoded);
      expect(decoded).toEqual(original);
    }
  });

  test('decoder accepts lowercase via normalization (O/I/L mapping)', () => {
    const original = randomBytes(32);
    const encodedUpper = encodeBase32Crockford32(original);
    const encodedLower = encodedUpper.toLowerCase();
    expect(normalizeBase32Crockford(encodedLower)).toBe(encodedUpper);
    expect(decodeBase32Crockford32(encodedLower)).toEqual(original);

    // If the encoded string contains 0 or 1, verify ambiguous character mapping.
    const mutated = encodedUpper.replace(/0/g, "O").replace(/1/g, "L");
    expect(decodeBase32Crockford32(mutated)).toEqual(original);
  });

  test('length growth bounds for various input sizes', () => {
    for (let n = 1; n <= 64; n++) {
      const buf = randomBytes(n);
      const encoded = encodeBase32Crockford(buf);
      // Base32 length == ceil(n*8/5)
      const expected = Math.ceil((n * 8) / 5);
      expect(encoded.length).toBe(expected);
      expect(encoded).toMatch(/^[0-9A-HJKMNP-TV-Z]+$/);
      expect(decodeBase32Crockford(encoded)).toEqual(buf);
    }
  });
});
