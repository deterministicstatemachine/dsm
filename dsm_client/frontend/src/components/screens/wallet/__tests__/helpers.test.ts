// SPDX-License-Identifier: Apache-2.0
import type { DomainContact, DomainTransaction } from '../../../../domain/types';
import {
  buildAliasLookup,
  b32,
  resolveAlias,
  shortStr,
  txTypeDetail,
  txTypeLabel,
  txTypeNumber,
} from '../helpers';

describe('wallet helpers', () => {
  describe('txTypeLabel / txTypeDetail', () => {
    it('maps known numeric types', () => {
      expect(txTypeLabel(1)).toBe('FAUCET');
      expect(txTypeLabel(2)).toBe('OFFLINE');
      expect(txTypeLabel(4)).toBe('ONLINE');
      expect(txTypeLabel(5)).toBe('dBTC MINT');
      expect(txTypeDetail(5)).toContain('Deposit');
    });

    it('returns UNKNOWN for unrecognized codes', () => {
      expect(txTypeLabel(99)).toBe('UNKNOWN');
      expect(txTypeDetail(99)).toBe('Unknown');
    });
  });

  describe('txTypeNumber', () => {
    it('maps domain txType strings to proto numbers', () => {
      const base = {
        txId: 'x',
        type: 'online' as const,
        amount: 0n,
        recipient: '',
        status: 'confirmed',
      };
      expect(txTypeNumber({ ...base, txType: 'faucet' } as DomainTransaction)).toBe(1);
      expect(txTypeNumber({ ...base, txType: 'online' } as DomainTransaction)).toBe(4);
      expect(txTypeNumber({ ...base, txType: 'dbtc_mint' } as DomainTransaction)).toBe(5);
    });
  });

  describe('b32', () => {
    it('passes through non-empty strings', () => {
      expect(b32('already_b32')).toBe('already_b32');
    });

    it('encodes Uint8Array', () => {
      const u = new Uint8Array([0, 1, 2]);
      expect(b32(u).length).toBeGreaterThan(0);
    });

    it('returns empty for empty input', () => {
      expect(b32(new Uint8Array(0))).toBe('');
    });
  });

  describe('shortStr', () => {
    it('returns short strings unchanged', () => {
      expect(shortStr('abc')).toBe('abc');
    });

    it('truncates long strings with ellipsis', () => {
      const s = 'a'.repeat(40);
      expect(shortStr(s, 4, 4)).toBe('aaaa...aaaa');
    });
  });

  describe('resolveAlias / buildAliasLookup', () => {
    it('resolves alias from map', () => {
      const m = new Map([['dev1', 'Alice']]);
      expect(resolveAlias('dev1', m)).toBe('Alice');
    });

    it('falls back to shortened id', () => {
      const longId = 'B'.repeat(30);
      const r = resolveAlias(longId, new Map());
      expect(r).toContain('...');
    });

    it('buildAliasLookup collects deviceId → alias', () => {
      const contacts: DomainContact[] = [
        {
          alias: 'Bob',
          deviceId: 'd1',
          genesisHash: 'g',
          chainTip: '',
        } as DomainContact,
      ];
      const map = buildAliasLookup(contacts);
      expect(map.get('d1')).toBe('Bob');
    });
  });
});
