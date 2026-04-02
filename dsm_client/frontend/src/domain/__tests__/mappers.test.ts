// SPDX-License-Identifier: Apache-2.0
import {
  mapBalanceList,
  mapIdentity,
  mapTransactions,
  normalizeBleAddress,
  toBigint,
} from '../mappers';

describe('domain mappers', () => {
  describe('toBigint', () => {
    it('passes through bigint', () => {
      expect(toBigint(7n)).toBe(7n);
    });

    it('truncates numbers', () => {
      expect(toBigint(3.9)).toBe(3n);
    });

    it('parses decimal strings', () => {
      expect(toBigint('  42  ')).toBe(42n);
    });

    it('returns 0n for empty or invalid', () => {
      expect(toBigint('')).toBe(0n);
      expect(toBigint(undefined)).toBe(0n);
    });
  });

  describe('normalizeBleAddress', () => {
    it('uppercases colon-separated MAC', () => {
      expect(normalizeBleAddress('aa:bb:cc:dd:ee:ff')).toBe('AA:BB:CC:DD:EE:FF');
    });

    it('formats 12 hex chars without colons', () => {
      expect(normalizeBleAddress('aabbccddeeff')).toBe('AA:BB:CC:DD:EE:FF');
    });

    it('returns undefined for invalid input', () => {
      expect(normalizeBleAddress('')).toBeUndefined();
      expect(normalizeBleAddress('not-mac')).toBeUndefined();
      expect(normalizeBleAddress(undefined)).toBeUndefined();
    });
  });

  describe('mapIdentity', () => {
    it('maps camelCase protobuf fields', () => {
      const id = {
        genesisHash: new Uint8Array(32).fill(1),
        deviceId: new Uint8Array(32).fill(2),
      };
      const out = mapIdentity(id);
      expect(out).not.toBeNull();
      expect(out!.genesisHash.length).toBeGreaterThan(0);
      expect(out!.deviceId.length).toBeGreaterThan(0);
    });

    it('returns null when required fields missing', () => {
      expect(mapIdentity({ genesisHash: '', deviceId: '' })).toBeNull();
    });
  });

  describe('mapBalanceList', () => {
    it('rewrites spaced tokenId to ERA', () => {
      const out = mapBalanceList([
        { tokenId: 'bad id', symbol: 'X', balance: 1n, decimals: 0, tokenName: 'T' },
      ]);
      expect(out[0].tokenId).toBe('ERA');
    });
  });

  describe('mapTransactions', () => {
    it('maps numeric txType to domain string', () => {
      const out = mapTransactions([
        {
          txType: 4,
          txId: 'id',
          toDeviceId: new Uint8Array(32),
          amount: 100n,
        },
      ]);
      expect(out[0].txType).toBe('online');
      expect(out[0].type).toBe('online');
    });
  });
});
