/* eslint-disable @typescript-eslint/no-explicit-any */
import React from 'react';
import { render } from '@testing-library/react';
import TransactionItem from '../TransactionItem';
import type { DomainTransaction } from '../../../../domain/types';

function buildTx(overrides: Partial<DomainTransaction> = {}): DomainTransaction {
  return {
    txId: 'tx:test:1',
    type: 'offline',
    amount: BigInt(25),
    amountSigned: BigInt(25),
    recipient: '',
    status: 'confirmed',
    txType: 'bilateral_offline',
    fromDeviceId: '8796V9AXD123456789NQ83EXG',
    toDeviceId: 'AQP2VDM3DJABCDEF57C6G2R0',
    txHash: '7NA3Y3KGQV3SABCDEFT8ER8Q8O',
    tokenId: 'ERA',
    receiptVerified: true,
    ...overrides,
  };
}

describe('TransactionItem visual contract', () => {
  test('collapsed view places amount on its own row outside transaction-main', () => {
    const tx = buildTx();
    const aliasLookup = new Map<string, string>();
    const { container } = render(
      <TransactionItem tx={tx} idx={0} expandedTxId={null} onToggle={() => {}} aliasLookup={aliasLookup} />,
    );
    // Amount line exists as a direct child of .transaction-item.
    const item = container.querySelector('.transaction-item');
    expect(item).not.toBeNull();
    const amountLine = item!.querySelector(':scope > .transaction-amount-line');
    expect(amountLine).not.toBeNull();
    // And the amount is NOT inside .transaction-main anymore.
    const amountInsideMain = item!.querySelector('.transaction-main .transaction-amount-line');
    expect(amountInsideMain).toBeNull();
    // The amount-value contains sign+magnitude; token is shown separately.
    expect(amountLine!.querySelector('.transaction-amount-value')!.textContent).toMatch(/\+25/);
    expect(amountLine!.querySelector('.transaction-amount-token')!.textContent).toBe('ERA');
  });

  test('collapsed view shows alias when counterparty is in aliasLookup', () => {
    const tx = buildTx();
    const aliasLookup = new Map<string, string>([[tx.fromDeviceId!, 'Bob']]);
    const { container } = render(
      <TransactionItem tx={tx} idx={0} expandedTxId={null} onToggle={() => {}} aliasLookup={aliasLookup} />,
    );
    const recipientValue = container.querySelector('.transaction-recipient-value');
    expect(recipientValue).not.toBeNull();
    expect(recipientValue!.textContent).toBe('Bob');
  });

  test('collapsed view falls back to short hash when no alias exists', () => {
    const tx = buildTx();
    const aliasLookup = new Map<string, string>();
    const { container } = render(
      <TransactionItem tx={tx} idx={0} expandedTxId={null} onToggle={() => {}} aliasLookup={aliasLookup} />,
    );
    const recipientValue = container.querySelector('.transaction-recipient-value');
    expect(recipientValue).not.toBeNull();
    // shortStr(fromDeviceId, 8, 6) for 25-char string => first 8 + '...' + last 6
    expect(recipientValue!.textContent).toMatch(/\.\.\./);
  });

  test('alias-first priority: aliasLookup wins even when tx.recipient is set (the bug-fix regression)', () => {
    const tx = buildTx({ recipient: 'RAW_RECIPIENT_HASH_SHOULD_NOT_WIN' });
    const aliasLookup = new Map<string, string>([[tx.fromDeviceId!, 'Alice']]);
    const { container } = render(
      <TransactionItem tx={tx} idx={0} expandedTxId={null} onToggle={() => {}} aliasLookup={aliasLookup} />,
    );
    const recipientValue = container.querySelector('.transaction-recipient-value')!.textContent;
    expect(recipientValue).toBe('Alice');
    expect(recipientValue).not.toContain('RAW_RECIPIENT_HASH_SHOULD_NOT_WIN');
  });

  test('expanded view shows full (un-truncated) from/to/txhash', () => {
    const tx = buildTx();
    const aliasLookup = new Map<string, string>();
    const { container } = render(
      <TransactionItem tx={tx} idx={0} expandedTxId={tx.txId!} onToggle={() => {}} aliasLookup={aliasLookup} />,
    );
    const hashValues = Array.from(
      container.querySelectorAll('.transaction-expanded-details .detail-value-hash'),
    ).map((el) => el.textContent!);
    expect(hashValues).toContain(tx.fromDeviceId);
    expect(hashValues).toContain(tx.toDeviceId);
    expect(hashValues).toContain(tx.txHash);
    // None of them should contain an ellipsis (no shortStr truncation in expanded).
    for (const v of hashValues) {
      expect(v).not.toMatch(/\.\.\./);
    }
  });

  test('expanded view shows alias rows when contacts have aliases for from/to', () => {
    const tx = buildTx();
    const aliasLookup = new Map<string, string>([
      [tx.fromDeviceId!, 'Bob'],
      [tx.toDeviceId!, 'Carol'],
    ]);
    const { container } = render(
      <TransactionItem tx={tx} idx={0} expandedTxId={tx.txId!} onToggle={() => {}} aliasLookup={aliasLookup} />,
    );
    const text = container.querySelector('.transaction-expanded-details')!.textContent!;
    expect(text).toContain('From (alias)');
    expect(text).toContain('Bob');
    expect(text).toContain('To (alias)');
    expect(text).toContain('Carol');
  });
});
