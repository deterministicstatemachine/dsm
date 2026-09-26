// SPDX-License-Identifier: MIT OR Apache-2.0

/* eslint-disable @typescript-eslint/no-explicit-any */
import { renderHook, act, waitFor } from '@testing-library/react';
import { useTransactions } from '../useTransactions';
import { dsmClient } from '../../services/dsmClient';
import type { DomainTransaction } from '../../domain/types';

describe('useTransactions', () => {
  const original = {
    getWalletHistory: dsmClient.getWalletHistory,
    isReady: (dsmClient as any).isReady,
  };

  const row: DomainTransaction = {
    txId: 'tx_ROW',
    txHash: 'ROWHASH',
    txType: 'online',
    type: 'online',
    amount: -5n,
    displayAmount: '-5',
    tokenId: 'ERA',
    recipient: 'alice',
    status: 'confirmed',
    fromDeviceId: 'FROM',
    toDeviceId: 'TO',
    receiptVerified: false,
  };

  beforeEach(() => {
    (dsmClient as any).isReady = async () => true;
  });

  afterEach(() => {
    (dsmClient as any).getWalletHistory = original.getWalletHistory;
    (dsmClient as any).isReady = original.isReady;
  });

  async function renderTransactionsHook() {
    const hook = renderHook(() => useTransactions());
    await act(async () => {
      await Promise.resolve();
    });
    return hook;
  }

  test('holds the rows exactly as the history reported them', async () => {
    (dsmClient as any).getWalletHistory = async () => ({ transactions: [row] });

    const { result } = await renderTransactionsHook();

    await waitFor(() => {
      expect(result.current.transactions).toEqual([row]);
    });
  });

  test("shows the history's own error", async () => {
    (dsmClient as any).getWalletHistory = async () => {
      throw new Error('STRICT: transaction tx_ROW carries no status');
    };

    const { result } = await renderTransactionsHook();

    await waitFor(() => {
      expect(result.current.error).toBe('STRICT: transaction tx_ROW carries no status');
    });
  });

  test('does not ask for history before the device has an identity', async () => {
    (dsmClient as any).isReady = async () => false;
    const history = jest.fn();
    (dsmClient as any).getWalletHistory = history;

    const { result } = await renderTransactionsHook();

    expect(history).not.toHaveBeenCalled();
    expect(result.current.transactions).toEqual([]);
    expect(result.current.error).toBeNull();
  });
});
