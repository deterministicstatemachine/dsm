/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import { renderHook, act } from '@testing-library/react';

jest.mock('../../services/dsmClient', () => ({
  dsmClient: {
    getIdentity: jest.fn(),
    getAllBalances: jest.fn(),
    getWalletHistory: jest.fn(),
  },
}));

jest.mock('../../bridge/bridgeEvents', () => ({
  bridgeEvents: {
    emit: jest.fn(),
  },
}));

import { dsmClient } from '../../services/dsmClient';
import { bridgeEvents } from '../../bridge/bridgeEvents';

const mockedClient = dsmClient as jest.Mocked<typeof dsmClient>;
const mockedBridgeEvents = bridgeEvents as jest.Mocked<typeof bridgeEvents>;

// Fresh store for each test — avoids cross-test contamination of singleton state
function freshModule() {
  jest.resetModules();
  jest.doMock('../../services/dsmClient', () => ({
    dsmClient: {
      getIdentity: jest.fn(),
      getAllBalances: jest.fn(),
      getWalletHistory: jest.fn(),
    },
  }));
  jest.doMock('../../bridge/bridgeEvents', () => ({
    bridgeEvents: { emit: jest.fn() },
  }));
  const mod = require('../walletStore');
  const client = require('../../services/dsmClient').dsmClient;
  const events = require('../../bridge/bridgeEvents').bridgeEvents;
  return { ...mod, client, events };
}

describe('WalletStore', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('initial state', () => {
    it('has correct defaults', () => {
      const { walletStore } = freshModule();
      const state = walletStore.getSnapshot();
      expect(state).toEqual({
        genesisHash: null,
        deviceId: null,
        balances: [],
        transactions: [],
        isInitialized: false,
        isLoading: false,
        error: null,
      });
    });
  });

  describe('subscribe / emit', () => {
    it('notifies listeners on state change', () => {
      const { walletStore } = freshModule();
      const listener = jest.fn();
      walletStore.subscribe(listener);
      walletStore.setError('boom');
      expect(listener).toHaveBeenCalledTimes(1);
      expect(walletStore.getSnapshot().error).toBe('boom');
    });

    it('unsubscribes correctly', () => {
      const { walletStore } = freshModule();
      const listener = jest.fn();
      const unsub = walletStore.subscribe(listener);
      unsub();
      walletStore.setError('ignored');
      expect(listener).not.toHaveBeenCalled();
    });
  });

  describe('initialize()', () => {
    it('sets identity and isInitialized when both genesisHash and deviceId present', async () => {
      const { walletStore, client } = freshModule();
      client.getIdentity.mockResolvedValue({ genesisHash: 'abc', deviceId: 'dev1' });
      client.getAllBalances.mockResolvedValue([]);
      client.getWalletHistory.mockResolvedValue({ transactions: [] });

      await walletStore.initialize();
      const s = walletStore.getSnapshot();

      expect(s.genesisHash).toBe('abc');
      expect(s.deviceId).toBe('dev1');
      expect(s.isInitialized).toBe(true);
      expect(s.isLoading).toBe(false);
      expect(s.error).toBeNull();
    });

    // No identity on this device is a state Rust reports, not a failure: the
    // store stays uninitialized, reads nothing, and shows no error. It used to
    // be the same null as a failed read.
    it('a missing identity leaves the store uninitialized, with no error and no reads', async () => {
      const { walletStore, client } = freshModule();
      client.getIdentity.mockRejectedValue(
        Object.assign(new Error('no identity on this device (native session: missing)'), {
          name: 'IdentityUnavailableError',
          state: 'missing',
        }),
      );

      await walletStore.initialize();
      const s = walletStore.getSnapshot();
      expect(s.isInitialized).toBe(false);
      expect(s.error).toBeNull();
      expect(s.isLoading).toBe(false);
      expect(client.getAllBalances).not.toHaveBeenCalled();
      expect(client.getWalletHistory).not.toHaveBeenCalled();
    });

    it('a runtime that is not ready in time is an error, as reported', async () => {
      const { walletStore, client } = freshModule();
      client.getIdentity.mockRejectedValue(
        Object.assign(new Error('native session not ready after 5750 ms (no session state received)'), {
          name: 'IdentityUnavailableError',
          state: 'runtime_not_ready',
        }),
      );

      await walletStore.initialize();
      const s = walletStore.getSnapshot();
      expect(s.isInitialized).toBe(false);
      expect(s.error).toMatch(/native session not ready after 5750 ms/);
    });

    it('stores error message on failure', async () => {
      const { walletStore, client } = freshModule();
      client.getIdentity.mockRejectedValue(new Error('network down'));

      await walletStore.initialize();
      const s = walletStore.getSnapshot();
      expect(s.error).toBe('network down');
      expect(s.isLoading).toBe(false);
    });

    it('falls back to default error message for non-Error throws', async () => {
      const { walletStore, client } = freshModule();
      client.getIdentity.mockRejectedValue('oops');

      await walletStore.initialize();
      expect(walletStore.getSnapshot().error).toBe('Failed to initialize wallet');
    });

  });

  describe('refreshBalances()', () => {
    it('fetches and stores balances', async () => {
      const { walletStore, client } = freshModule();
      const balances = [{ tokenId: 'DSM', baseUnits: 100n, tokenName: 'DSM', decimals: 0, symbol: 'DSM' }];
      client.getAllBalances.mockResolvedValue(balances);

      await walletStore.refreshBalances();
      const s = walletStore.getSnapshot();
      expect(s.balances).toEqual(balances);
      expect(s.isLoading).toBe(false);
      expect(s.error).toBeNull();
    });

    it('filters out BTC_CHAIN entries', async () => {
      const { walletStore, client } = freshModule();
      client.getAllBalances.mockResolvedValue([
        { tokenId: 'BTC_CHAIN', baseUnits: 10n },
        { tokenId: 'DSM', baseUnits: 50n },
      ]);

      await walletStore.refreshBalances();
      const ids = walletStore.getSnapshot().balances.map((b: any) => b.tokenId);
      expect(ids).toEqual(['DSM']);
    });

    it('reports a failed balance refresh', async () => {
      const { walletStore, client } = freshModule();
      jest.spyOn(console, 'error').mockImplementation(() => {});
      client.getAllBalances.mockRejectedValue(new Error('balances down'));

      await walletStore.refreshBalances();
      const s = walletStore.getSnapshot();
      expect(s.error).toBe('Failed to refresh balances');
      expect(s.isLoading).toBe(false);
    });

    it('emits wallet.creditReceived when balance increases after first observation', async () => {
      const { walletStore, client, events } = freshModule();
      client.getAllBalances.mockResolvedValue([{ tokenId: 'DSM', baseUnits: 100n }]);
      await walletStore.refreshBalances(); // first call → sets hasObservedBalances

      client.getAllBalances.mockResolvedValue([{ tokenId: 'DSM', baseUnits: 200n }]);
      await walletStore.refreshBalances();

      expect(events.emit).toHaveBeenCalledWith('wallet.creditReceived', expect.objectContaining({
        tokenId: 'DSM',
        amount: '100',
        creditCount: 1,
      }));
    });

    it('does not emit creditReceived on first observation', async () => {
      const { walletStore, client, events } = freshModule();
      client.getAllBalances.mockResolvedValue([{ tokenId: 'DSM', baseUnits: 100n }]);
      await walletStore.refreshBalances();
      expect(events.emit).not.toHaveBeenCalled();
    });

    it('does not emit creditReceived when balance decreases', async () => {
      const { walletStore, client, events } = freshModule();
      client.getAllBalances.mockResolvedValue([{ tokenId: 'DSM', baseUnits: 200n }]);
      await walletStore.refreshBalances();

      client.getAllBalances.mockResolvedValue([{ tokenId: 'DSM', baseUnits: 100n }]);
      await walletStore.refreshBalances();
      expect(events.emit).not.toHaveBeenCalled();
    });

    it('handles error in refreshBalances gracefully', async () => {
      const { walletStore, client } = freshModule();
      jest.spyOn(console, 'error').mockImplementation(() => {});
      client.getAllBalances.mockImplementation(() => { throw new Error('crash'); });

      await walletStore.refreshBalances();
      const s = walletStore.getSnapshot();
      expect(s.error).toBe('crash');
      expect(s.isLoading).toBe(false);
    });
  });

  describe('refreshTransactions()', () => {
    it('fetches and stores transactions', async () => {
      const { walletStore, client } = freshModule();
      const txns = [{ txId: 'tx1', type: 'online', amount: 10n, recipient: 'r', status: 'confirmed' }];
      client.getWalletHistory.mockResolvedValue({ transactions: txns });

      await walletStore.refreshTransactions();
      expect(walletStore.getSnapshot().transactions).toEqual(txns);
      expect(walletStore.getSnapshot().isLoading).toBe(false);
    });

    it('stores empty array when history has no transactions field', async () => {
      const { walletStore, client } = freshModule();
      client.getWalletHistory.mockResolvedValue({});

      await walletStore.refreshTransactions();
      expect(walletStore.getSnapshot().transactions).toEqual([]);
    });

    it('sets error on failure', async () => {
      const { walletStore, client } = freshModule();
      jest.spyOn(console, 'error').mockImplementation(() => {});
      client.getWalletHistory.mockRejectedValue(new Error('tx fail'));

      await walletStore.refreshTransactions();
      expect(walletStore.getSnapshot().error).toBe('tx fail');
    });
  });

  describe('refreshAll()', () => {
    it('calls both refreshBalances and refreshTransactions', async () => {
      const { walletStore, client } = freshModule();
      client.getAllBalances.mockResolvedValue([]);
      client.getWalletHistory.mockResolvedValue({ transactions: [] });

      await walletStore.refreshAll();
      expect(client.getAllBalances).toHaveBeenCalled();
      expect(client.getWalletHistory).toHaveBeenCalled();
    });
  });

  describe('concurrent loading tracking', () => {
    it('keeps isLoading true while any concurrent operation is still running', async () => {
      const { walletStore, client } = freshModule();
      let resolveBalances!: (v: any) => void;
      let resolveTx!: (v: any) => void;
      client.getAllBalances.mockReturnValue(new Promise(r => { resolveBalances = r; }));
      client.getWalletHistory.mockReturnValue(new Promise(r => { resolveTx = r; }));

      const allPromise = walletStore.refreshAll();
      expect(walletStore.getSnapshot().isLoading).toBe(true);

      resolveBalances([]);
      // Wait for microtask queue to settle
      await new Promise(r => setTimeout(r, 0));
      // Transactions still pending → isLoading should be true
      expect(walletStore.getSnapshot().isLoading).toBe(true);

      resolveTx({ transactions: [] });
      await allPromise;
      expect(walletStore.getSnapshot().isLoading).toBe(false);
    });
  });

  describe('setError()', () => {
    it('updates error field', () => {
      const { walletStore } = freshModule();
      walletStore.setError('test error');
      expect(walletStore.getSnapshot().error).toBe('test error');
    });

    it('clears error with null', () => {
      const { walletStore } = freshModule();
      walletStore.setError('x');
      walletStore.setError(null);
      expect(walletStore.getSnapshot().error).toBeNull();
    });
  });
});

// Hook tests use static imports (same React instance as @testing-library/react)
import { useWalletStore } from '../walletStore';

describe('wallet store hooks', () => {
  it('useWalletStore returns full snapshot', () => {
    const { result } = renderHook(() => useWalletStore());
    expect(result.current).toHaveProperty('genesisHash');
    expect(result.current).toHaveProperty('balances');
    expect(result.current).toHaveProperty('transactions');
    expect(result.current).toHaveProperty('isInitialized');
  });
});
