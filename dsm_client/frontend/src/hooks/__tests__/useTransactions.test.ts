// SPDX-License-Identifier: MIT OR Apache-2.0

/* eslint-disable @typescript-eslint/no-explicit-any */
import { renderHook, act, waitFor } from '@testing-library/react';

jest.mock('../../utils/identity', () => ({
  checkIdentityState: jest.fn(),
}));

import { useTransactions } from '../useTransactions';
import { dsmClient } from '../../services/dsmClient';
import { checkIdentityState } from '../../utils/identity';
import type { DomainTransaction } from '../../domain/types';

const identityState = checkIdentityState as jest.Mock;

describe('useTransactions', () => {
  const original = {
    getWalletHistory: dsmClient.getWalletHistory,
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
    identityState.mockResolvedValue('READY');
  });

  afterEach(() => {
    (dsmClient as any).getWalletHistory = original.getWalletHistory;
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

  // The native session is Rust's word on whether there is an identity: no
  // history is asked for while it reports none, or is not yet ready.
  test.each(['NO_IDENTITY', 'RUNTIME_NOT_READY'])(
    'does not ask for history while the native session reports %s',
    async (state) => {
      identityState.mockResolvedValue(state);
      const history = jest.fn();
      (dsmClient as any).getWalletHistory = history;

      const { result } = await renderTransactionsHook();

      expect(history).not.toHaveBeenCalled();
      expect(result.current.transactions).toEqual([]);
      expect(result.current.error).toBeNull();
    },
  );
});
