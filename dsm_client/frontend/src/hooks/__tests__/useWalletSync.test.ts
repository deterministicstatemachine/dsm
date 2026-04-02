/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import { renderHook, act } from '@testing-library/react';

const bridgeHandlers = new Map<string, Set<Function>>();
jest.mock('../../bridge/bridgeEvents', () => ({
  bridgeEvents: {
    on: jest.fn((event: string, handler: Function) => {
      const set = bridgeHandlers.get(event) ?? new Set();
      set.add(handler);
      bridgeHandlers.set(event, set);
      return () => { set.delete(handler); };
    }),
    emit: jest.fn((event: string, payload: any) => {
      const set = bridgeHandlers.get(event);
      if (set) set.forEach(fn => fn(payload));
    }),
  },
}));

import { useWalletSync, type WalletSyncHandlers } from '../useWalletSync';

function emitBridge(event: string, payload?: any) {
  const set = bridgeHandlers.get(event);
  if (set) set.forEach(fn => fn(payload));
}

beforeEach(() => {
  bridgeHandlers.clear();
  jest.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  jest.restoreAllMocks();
});

describe('useWalletSync', () => {
  it('subscribes to wallet.historyUpdated and calls onRefreshTransactions', () => {
    const onRefreshTransactions = jest.fn();
    const handlers: WalletSyncHandlers = {
      onRefreshAll: jest.fn(),
      onRefreshTransactions,
    };

    renderHook(() => useWalletSync(handlers));

    act(() => { emitBridge('wallet.historyUpdated'); });

    expect(onRefreshTransactions).toHaveBeenCalledTimes(1);
  });

  it('subscribes to wallet.balancesUpdated and calls onRefreshBalances', () => {
    const onRefreshBalances = jest.fn();
    const handlers: WalletSyncHandlers = {
      onRefreshAll: jest.fn(),
      onRefreshBalances,
    };

    renderHook(() => useWalletSync(handlers));

    act(() => { emitBridge('wallet.balancesUpdated'); });

    expect(onRefreshBalances).toHaveBeenCalledTimes(1);
  });

  it('subscribes to wallet.sendCommitted and calls onRefreshAll', () => {
    const onRefreshAll = jest.fn();
    const handlers: WalletSyncHandlers = { onRefreshAll };

    renderHook(() => useWalletSync(handlers));

    act(() => { emitBridge('wallet.sendCommitted'); });

    expect(onRefreshAll).toHaveBeenCalledTimes(1);
  });

  it('subscribes to identity.ready and calls onIdentityReady', () => {
    const onIdentityReady = jest.fn();
    const handlers: WalletSyncHandlers = {
      onRefreshAll: jest.fn(),
      onIdentityReady,
    };

    renderHook(() => useWalletSync(handlers));

    act(() => { emitBridge('identity.ready'); });

    expect(onIdentityReady).toHaveBeenCalledTimes(1);
  });

  it('skips onRefreshTransactions when not provided', () => {
    const handlers: WalletSyncHandlers = { onRefreshAll: jest.fn() };

    renderHook(() => useWalletSync(handlers));

    // Should not throw
    act(() => { emitBridge('wallet.historyUpdated'); });
  });

  it('skips onRefreshBalances when not provided', () => {
    const handlers: WalletSyncHandlers = { onRefreshAll: jest.fn() };

    renderHook(() => useWalletSync(handlers));

    act(() => { emitBridge('wallet.balancesUpdated'); });
  });

  it('handles async handler rejection gracefully', async () => {
    const onRefreshAll = jest.fn().mockRejectedValue(new Error('refresh boom'));
    const handlers: WalletSyncHandlers = { onRefreshAll };

    renderHook(() => useWalletSync(handlers));

    act(() => { emitBridge('wallet.sendCommitted'); });

    // Wait for the rejected promise to be caught
    await act(async () => { await new Promise(r => setTimeout(r, 10)); });

    expect(console.error).toHaveBeenCalledWith(
      expect.stringContaining('wallet.sendCommitted'),
      expect.any(Error),
    );
  });

  it('unsubscribes on unmount', () => {
    const onRefreshAll = jest.fn();
    const handlers: WalletSyncHandlers = { onRefreshAll };

    const { unmount } = renderHook(() => useWalletSync(handlers));
    unmount();

    act(() => { emitBridge('wallet.sendCommitted'); });

    expect(onRefreshAll).not.toHaveBeenCalled();
  });
});
