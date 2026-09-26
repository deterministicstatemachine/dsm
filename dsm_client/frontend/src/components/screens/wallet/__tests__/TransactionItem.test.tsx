// SPDX-License-Identifier: MIT OR Apache-2.0

import React from 'react';
import { render } from '@testing-library/react';
import TransactionItem from '../TransactionItem';
import type { DomainTransaction } from '../../../../domain/types';

function buildTx(overrides: Partial<DomainTransaction> = {}): DomainTransaction {
  return {
    txId: 'tx_7NA3Y3KGQV3SABCDEFT8ER8Q8R',
    txHash: '7NA3Y3KGQV3SABCDEFT8ER8Q8R',
    txType: 'bilateral_offline',
    type: 'offline',
    amount: BigInt(25),
    displayAmount: '25',
    tokenId: 'ERA',
    recipient: 'Bob',
    status: 'completed',
    fromDeviceId: '8796V9AXD123456789NQ83EXG',
    toDeviceId: 'AQP2VDM3DJABCDEF57C6G2R0',
    receiptVerified: true,
    ...overrides,
  };
}

describe('TransactionItem renders the row Rust reported', () => {
  test('collapsed view places amount on its own row outside transaction-main', () => {
    const { container } = render(
      <TransactionItem tx={buildTx()} expandedTxId={null} onToggle={() => {}} />,
    );
    const item = container.querySelector('.transaction-item');
    expect(item).not.toBeNull();
    const amountLine = item!.querySelector(':scope > .transaction-amount-line');
    expect(amountLine).not.toBeNull();
    expect(item!.querySelector('.transaction-main .transaction-amount-line')).toBeNull();
    expect(amountLine!.querySelector('.transaction-amount-value')!.textContent).toBe('+25');
    expect(amountLine!.querySelector('.transaction-amount-token')!.textContent).toBe('ERA');
  });

  test("the counterparty is Rust's label and the status is Rust's word", () => {
    const { container } = render(
      <TransactionItem tx={buildTx()} expandedTxId={null} onToggle={() => {}} />,
    );
    expect(container.querySelector('.transaction-recipient-value')!.textContent).toBe('Bob');
    expect(container.querySelector('.transaction-status')!.textContent).toBe('completed');
  });

  test("an outgoing row shows the magnitude of Rust's display form with its own sign", () => {
    const tx = buildTx({ amount: BigInt(-1250), displayAmount: '-12.50', tokenId: 'USDX' });
    const { container } = render(<TransactionItem tx={tx} expandedTxId={null} onToggle={() => {}} />);
    expect(container.querySelector('.transaction-amount-line')!.className).toContain('outgoing');
    expect(container.querySelector('.transaction-amount-value')!.textContent).toBe('-12.50');
    expect(container.querySelector('.transaction-recipient-label')!.textContent).toBe('To');
  });

  test('a dBTC row carries no transport badge', () => {
    const tx = buildTx({ txType: 'dbtc_mint', type: undefined });
    const { container } = render(<TransactionItem tx={tx} expandedTxId={null} onToggle={() => {}} />);
    expect(container.querySelector('.transaction-type')!.textContent).toBe('dBTC MINT');
    expect(container.querySelector('.bilateral-badge')).toBeNull();
  });

  test('expanded view shows full (un-truncated) from/to/txhash', () => {
    const tx = buildTx();
    const { container } = render(
      <TransactionItem tx={tx} expandedTxId={tx.txId} onToggle={() => {}} />,
    );
    const hashValues = Array.from(
      container.querySelectorAll('.transaction-expanded-details .detail-value-hash'),
    ).map((el) => el.textContent!);
    expect(hashValues).toEqual([tx.fromDeviceId, tx.toDeviceId, tx.txHash]);
  });
});
