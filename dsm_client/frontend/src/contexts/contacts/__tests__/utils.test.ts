// SPDX-License-Identifier: Apache-2.0
import { toBase32Crockford } from '../../../dsm/decoding';
import { bytesToDisplay } from '../utils';

describe('contacts utils', () => {
  const bytes32 = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) bytes32[i] = i;

  describe('bytesToDisplay', () => {
    it('returns crockford base32 for Uint8Array', () => {
      expect(bytesToDisplay(bytes32)).toBe(toBase32Crockford(bytes32));
    });

    it('returns UPPERCASE Base32 from the Crockford alphabet', () => {
      const disp = bytesToDisplay(new Uint8Array([0, 1, 2, 254, 255]));
      // Crockford alphabet: 0-9 and A-Z excluding I, L, O, U
      expect(disp).toMatch(/^[0-9A-HJKMNP-TV-Z]+$/);
    });

    it('returns empty string for non-Uint8Array', () => {
      expect(bytesToDisplay(null as unknown as Uint8Array)).toBe('');
      expect(bytesToDisplay(undefined as unknown as Uint8Array)).toBe('');
      expect(bytesToDisplay('not-bytes' as unknown as Uint8Array)).toBe('');
    });
  });
});
