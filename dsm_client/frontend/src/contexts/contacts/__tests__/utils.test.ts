// SPDX-License-Identifier: Apache-2.0
import { toBase32Crockford } from '../../../dsm/decoding';
import { bytesToDisplay, parseBinary32, parseBinary64 } from '../utils';

describe('contacts utils', () => {
  const bytes32 = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) bytes32[i] = i;

  describe('parseBinary32', () => {
    it('accepts Uint8Array of length 32', () => {
      expect(parseBinary32(bytes32, 'id')).toBe(bytes32);
    });

    it('rejects Uint8Array with wrong length', () => {
      expect(() => parseBinary32(new Uint8Array(31), 'id')).toThrow(/must be 32 bytes/);
    });

    it('parses base32 string of 32 bytes', () => {
      const b32 = toBase32Crockford(bytes32);
      const out = parseBinary32(b32, 'id');
      expect(out).toEqual(bytes32);
    });

    it('rejects empty string', () => {
      expect(() => parseBinary32('', 'label')).toThrow(/empty/);
    });
  });

  describe('parseBinary64', () => {
    const b64 = new Uint8Array(64);
    b64[0] = 0xff;
    b64[63] = 0x01;

    it('accepts Uint8Array of length 64', () => {
      expect(parseBinary64(b64, 'h')).toBe(b64);
    });

    it('rejects wrong Uint8Array length', () => {
      expect(() => parseBinary64(new Uint8Array(63), 'h')).toThrow(/must be 64 bytes/);
    });

    it('parses base32 string of 64 bytes', () => {
      const s = toBase32Crockford(b64);
      expect(parseBinary64(s, 'h')).toEqual(b64);
    });
  });

  describe('bytesToDisplay', () => {
    it('returns crockford base32 for Uint8Array', () => {
      expect(bytesToDisplay(bytes32)).toBe(toBase32Crockford(bytes32));
    });

    it('returns empty string for non-Uint8Array', () => {
      expect(bytesToDisplay(null as unknown as Uint8Array)).toBe('');
    });
  });
});
