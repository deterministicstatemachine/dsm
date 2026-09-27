/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import { renderHook } from '@testing-library/react';
import type { StorageStatus } from '../../dsm/types';

const mockGetStorageStatus = jest.fn();
const mockListVaults = jest.fn();

function freshModule() {
  jest.resetModules();
  jest.doMock('../../dsm/storage', () => ({
    getStorageStatus: (...args: any[]) => mockGetStorageStatus(...args),
  }));
  jest.doMock('../../services/bitcoinTap', () => ({
    listVaults: (...args: any[]) => mockListVaults(...args),
  }));
  return require('../storageStore');
}

const reported: StorageStatus = {
  networkId: 'dsm-testnet',
  storageSetIdB32: '7GBBB51DM8XP433F6H896G4R88W6RJZATZ3CT0WTRAFZ2EHYZ9D0',
  members: [
    {
      memberId: 'dsm-node-1',
      registerIncarnationB32: 'B6DZ4TFJ2Y1GSJ8X57CE8BWX0QM5JRVAJP08JRQTV65DEQ53DYKG',
      endpoint: 'https://node-1:8080',
      answer: { kind: 'noCycle' },
      answeredAs: 'dsm-node-1',
    },
  ],
  completedSyncs: 3n,
  databaseBytes: 8192n,
};

beforeEach(() => {
  jest.clearAllMocks();
});

describe('StorageStore', () => {
  it('starts loading, with no status and no error', () => {
    const { storageStore } = freshModule();
    const s = storageStore.getSnapshot();
    expect(s.status).toBeNull();
    expect(s.statusLoading).toBe(true);
    expect(s.statusError).toBeNull();
    expect(s.dlvs).toEqual([]);
    expect(s.dlvLoading).toBe(true);
  });

  it('notifies listeners and unsubscribes cleanly', async () => {
    const { storageStore } = freshModule();
    mockGetStorageStatus.mockResolvedValue(reported);
    const listener = jest.fn();
    const unsub = storageStore.subscribe(listener);

    await storageStore.refreshStatus();
    const calls = listener.mock.calls.length;
    expect(calls).toBeGreaterThan(0);

    unsub();
    await storageStore.refreshStatus();
    expect(listener).toHaveBeenCalledTimes(calls);
  });

  describe('refreshStatus()', () => {
    it('holds exactly what the SDK reported', async () => {
      const { storageStore } = freshModule();
      mockGetStorageStatus.mockResolvedValue(reported);

      await storageStore.refreshStatus();
      const s = storageStore.getSnapshot();
      expect(s.status).toBe(reported);
      expect(s.statusLoading).toBe(false);
      expect(s.statusError).toBeNull();
    });

    it("shows the SDK's own error and holds no status", async () => {
      const { storageStore } = freshModule();
      mockGetStorageStatus.mockResolvedValueOnce(reported);
      await storageStore.refreshStatus();

      mockGetStorageStatus.mockRejectedValueOnce(
        new Error('getStorageStatus: storage.status: no pinned storage set: fail closed'),
      );
      await storageStore.refreshStatus();
      const s = storageStore.getSnapshot();
      expect(s.status).toBeNull();
      expect(s.statusError).toBe('getStorageStatus: storage.status: no pinned storage set: fail closed');
      expect(s.statusLoading).toBe(false);
    });
  });

  describe('refreshDlvsAndPresence()', () => {
    it('loads vaults from bitcoinTap.listVaults', async () => {
      const { storageStore } = freshModule();
      const vault = { vaultId: 'v1', state: 'active', amountSats: 100000n, direction: 'btc_to_dbtc', htlcAddress: 'bc1q...', entryHeader: new Uint8Array(0) };
      mockListVaults.mockResolvedValue([vault]);

      await storageStore.refreshDlvsAndPresence();
      const s = storageStore.getSnapshot();
      expect(s.dlvs).toEqual([vault]);
      expect(s.dlvLoading).toBe(false);
    });

    it('handles empty vault list', async () => {
      const { storageStore } = freshModule();
      mockListVaults.mockResolvedValue([]);

      await storageStore.refreshDlvsAndPresence();
      expect(storageStore.getSnapshot().dlvs).toEqual([]);
    });

    it('handles error gracefully', async () => {
      const { storageStore } = freshModule();
      jest.spyOn(console, 'warn').mockImplementation(() => {});
      mockListVaults.mockRejectedValue(new Error('fail'));

      await storageStore.refreshDlvsAndPresence();
      expect(storageStore.getSnapshot().dlvLoading).toBe(false);
    });
  });
});

// Hook tests use static imports (same React instance as @testing-library/react)
import { useStorageStore } from '../storageStore';

describe('useStorageStore hook', () => {
  it('returns the full snapshot', () => {
    const { result } = renderHook(() => useStorageStore());
    expect(result.current).toHaveProperty('status');
    expect(result.current).toHaveProperty('statusLoading');
    expect(result.current).toHaveProperty('statusError');
    expect(result.current).toHaveProperty('dlvs');
  });
});
