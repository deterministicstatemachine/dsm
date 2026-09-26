// SPDX-License-Identifier: Apache-2.0
import type { DomainTransaction } from '../../../../domain/types';
import { formatTxAmount, txTypeDetail, txTypeLabel } from '../helpers';

describe('wallet helpers', () => {
  it('labels every history type Rust writes', () => {
    expect(txTypeLabel('bilateral_offline')).toBe('OFFLINE');
    expect(txTypeLabel('online')).toBe('ONLINE');
    expect(txTypeLabel('dbtc_mint')).toBe('dBTC MINT');
    expect(txTypeLabel('dbtc_burn')).toBe('dBTC BURN');
    expect(txTypeDetail('bilateral_offline')).toBe('Bilateral Offline (BLE)');
    expect(txTypeDetail('online')).toBe('Online');
    expect(txTypeDetail('dbtc_mint')).toContain('Deposit');
    expect(txTypeDetail('dbtc_burn')).toContain('Withdrawal');
  });

  it("shows the magnitude of Rust's signed display form", () => {
    expect(formatTxAmount({ displayAmount: '-12.50' } as DomainTransaction)).toBe('12.50');
    expect(formatTxAmount({ displayAmount: '3' } as DomainTransaction)).toBe('3');
  });
});
