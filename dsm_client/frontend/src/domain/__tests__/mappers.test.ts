// SPDX-License-Identifier: Apache-2.0
import {
  mapTransactions,
  normalizeBleAddress,
} from '../mappers';
import { TransactionInfo, TransactionType } from '../../proto/dsm_app_pb';
import { toBase32Crockford } from '../../dsm/decoding';

describe('domain mappers', () => {
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

  describe('mapTransactions', () => {
    const b = (fill: number) => new Uint8Array(32).fill(fill);
    const row = (overrides: Partial<TransactionInfo> = {}) =>
      new TransactionInfo({
        id: 'tx_ROW',
        fromDeviceId: b(0x11),
        toDeviceId: b(0x22),
        tokenId: 'ERA',
        amount: 5n,
        txHash: b(0x33),
        amountSigned: -5n,
        txType: TransactionType.TX_TYPE_ONLINE,
        status: 'confirmed',
        recipient: 'alice',
        memo: 'lunch',
        receiptVerified: false,
        displayAmount: '-5',
        ...overrides,
      });

    it('carries every field exactly as Rust reported it', () => {
      expect(mapTransactions([row()])).toEqual([
        {
          txId: 'tx_ROW',
          txHash: toBase32Crockford(b(0x33)),
          txType: 'online',
          type: 'online',
          amount: -5n,
          displayAmount: '-5',
          tokenId: 'ERA',
          recipient: 'alice',
          status: 'confirmed',
          fromDeviceId: toBase32Crockford(b(0x11)),
          toDeviceId: toBase32Crockford(b(0x22)),
          memo: 'lunch',
          stitchedReceipt: undefined,
          receiptVerified: false,
        },
      ]);
    });

    it('names the transport of a transfer and none for a dBTC row', () => {
      const [offline, mint] = mapTransactions([
        row({ txType: TransactionType.TX_TYPE_BILATERAL_OFFLINE }),
        row({ txType: TransactionType.TX_TYPE_DBTC_MINT }),
      ]);
      expect(offline.txType).toBe('bilateral_offline');
      expect(offline.type).toBe('offline');
      expect(mint.txType).toBe('dbtc_mint');
      expect(mint.type).toBeUndefined();
    });

    it('refuses a type the wire does not name, never guessing one', () => {
      expect(() => mapTransactions([row({ txType: TransactionType.TX_TYPE_UNSPECIFIED })])).toThrow(
        /tx_ROW has type 0/,
      );
      expect(() => mapTransactions([row({ txType: 3 as TransactionType })])).toThrow(/tx_ROW has type 3/);
    });

    // A faucet claim's source is the ERA reserve: Rust names no sender device,
    // labels the source, and a faucet row that names a sender is corrupt.
    it('maps a faucet claim with no sender device and no transport', () => {
      const [claim] = mapTransactions([
        row({
          txType: TransactionType.TX_TYPE_FAUCET,
          fromDeviceId: new Uint8Array(0),
          recipient: 'ERA reserve (faucet)',
          amountSigned: 100n,
          displayAmount: '100',
        }),
      ]);
      expect(claim.txType).toBe('faucet');
      expect(claim.type).toBeUndefined();
      expect(claim.fromDeviceId).toBeUndefined();
      expect(claim.recipient).toBe('ERA reserve (faucet)');
      expect(claim.amount).toBe(100n);
    });

    it('refuses a faucet claim that names a sender device', () => {
      expect(() => mapTransactions([row({ txType: TransactionType.TX_TYPE_FAUCET })])).toThrow(
        /faucet claim tx_ROW names a sender device/,
      );
    });

    it('refuses a row missing a field Rust always writes', () => {
      expect(() => mapTransactions([row({ status: '' })])).toThrow(/carries no status/);
      expect(() => mapTransactions([row({ tokenId: '' })])).toThrow(/carries no token id/);
      expect(() => mapTransactions([row({ recipient: '' })])).toThrow(/carries no counterparty label/);
      expect(() => mapTransactions([row({ displayAmount: '' })])).toThrow(/carries no display amount/);
      expect(() => mapTransactions([row({ fromDeviceId: new Uint8Array(0) })])).toThrow(
        /sender device id that is not 32 bytes/,
      );
    });
  });
});
