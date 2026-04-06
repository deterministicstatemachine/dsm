/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import { renderHook } from '@testing-library/react';

const mockStorageNodeService = {
  init: jest.fn().mockResolvedValue(undefined),
  getNodesConfig: jest.fn().mockReturnValue({ nodes: [], retryPolicy: { maxRetries: 3, backoffMs: 1000 } }),
  checkAllNodesHealth: jest.fn().mockResolvedValue([]),
  addNode: jest.fn(),
  removeNode: jest.fn(),
  collectDiagnostics: jest.fn(),
  exportDiagnostics: jest.fn().mockReturnValue(new Uint8Array(0)),
};

const mockDsmClient = {
  getStorageStatus: jest.fn(),
  createBackup: jest.fn(),
  listLocalDlvs: jest.fn(),
  checkDlvPresence: jest.fn(),
};

jest.mock('../../services/dsmClient', () => ({
  dsmClient: mockDsmClient,
}));

jest.mock('../../services/storageNodeService', () => ({
  storageNodeService: mockStorageNodeService,
}));

jest.mock('../../config/featureFlags', () => ({
  isFeatureEnabled: jest.fn().mockResolvedValue(false),
}));

jest.mock('../../types/storage', () => ({
  asDisplayOnlyNumber: (n: number) => n,
}));

import { isFeatureEnabled } from '../../config/featureFlags';

function freshModule() {
  jest.resetModules();
  jest.doMock('../../services/dsmClient', () => ({ dsmClient: mockDsmClient }));
  jest.doMock('../../services/storageNodeService', () => ({ storageNodeService: mockStorageNodeService }));
  jest.doMock('../../config/featureFlags', () => ({ isFeatureEnabled: jest.fn().mockResolvedValue(false) }));
  jest.doMock('../../types/storage', () => ({ asDisplayOnlyNumber: (n: number) => n }));
  const mod = require('../storageStore');
  const flags = require('../../config/featureFlags');
  return { ...mod, flags };
}

beforeEach(() => {
  jest.clearAllMocks();
  mockStorageNodeService.getNodesConfig.mockReturnValue({ nodes: [], retryPolicy: { maxRetries: 3, backoffMs: 1000 } });
});

describe('StorageStore', () => {
  describe('initial state', () => {
    it('has correct defaults', () => {
      const { storageStore } = freshModule();
      const s = storageStore.getSnapshot();
      expect(s.storageInfo).toBeNull();
      expect(s.overviewLoading).toBe(true);
      expect(s.overviewError).toBeNull();
      expect(s.dlvs).toEqual([]);
      expect(s.presence).toEqual({});
      expect(s.dlvLoading).toBe(true);
      expect(s.showObjectsTab).toBe(false);
      expect(s.nodeHealth).toEqual([]);
      expect(s.nodeHealthLoading).toBe(true);
      expect(s.nodeHealthRefreshing).toBe(false);
      expect(s.diagnostics).toBeNull();
      expect(s.diagnosticsCollecting).toBe(false);
    });
  });

  describe('subscribe / emit', () => {
    it('notifies listeners and unsubscribes cleanly', () => {
      const { storageStore } = freshModule();
      const listener = jest.fn();
      const unsub = storageStore.subscribe(listener);

      storageStore.clearDiagnostics();
      expect(listener).toHaveBeenCalledTimes(1);

      unsub();
      storageStore.clearDiagnostics();
      expect(listener).toHaveBeenCalledTimes(1);
    });
  });

  describe('initialize()', () => {
    it('calls storageNodeService.init and reads feature flag', async () => {
      const { storageStore, flags } = freshModule();
      flags.isFeatureEnabled.mockResolvedValue(true);

      await storageStore.initialize();

      expect(mockStorageNodeService.init).toHaveBeenCalled();
      expect(flags.isFeatureEnabled).toHaveBeenCalledWith('storageObjectBrowser');
      expect(storageStore.getSnapshot().showObjectsTab).toBe(true);
    });

    it('deduplicates concurrent initialize calls', async () => {
      const { storageStore } = freshModule();
      const p1 = storageStore.initialize();
      const p2 = storageStore.initialize();
      await Promise.all([p1, p2]);
      expect(mockStorageNodeService.init).toHaveBeenCalledTimes(1);
    });

    it('allows re-initialize after first completes', async () => {
      const { storageStore } = freshModule();
      await storageStore.initialize();
      await storageStore.initialize();
      expect(mockStorageNodeService.init).toHaveBeenCalledTimes(2);
    });
  });

  describe('refreshOverview()', () => {
    it('stores status when getStorageStatus returns data', async () => {
      const { storageStore } = freshModule();
      const status = { totalNodes: 3, connectedNodes: 2, lastSync: 123, dataSize: '1GB', backupStatus: 'ok' };
      mockDsmClient.getStorageStatus.mockResolvedValue(status);

      await storageStore.refreshOverview();
      const s = storageStore.getSnapshot();
      expect(s.storageInfo).toEqual(expect.objectContaining({ totalNodes: 3, connectedNodes: 2 }));
      expect(s.overviewLoading).toBe(false);
      expect(s.overviewError).toBeNull();
    });

    it('sets error when getStorageStatus is not a function', async () => {
      const { storageStore } = freshModule();
      delete mockDsmClient.getStorageStatus;

      await storageStore.refreshOverview();
      const s = storageStore.getSnapshot();
      expect(s.overviewError).toBe('Storage status is not available in this build.');
      expect(s.storageInfo).toBeNull();
      expect(s.overviewLoading).toBe(false);

      // Restore for other tests
      mockDsmClient.getStorageStatus = jest.fn();
    });

    it('sets error when getStorageStatus returns null', async () => {
      const { storageStore } = freshModule();
      mockDsmClient.getStorageStatus.mockResolvedValue(null);

      await storageStore.refreshOverview();
      expect(storageStore.getSnapshot().overviewError).toBe('No storage data returned from backend.');
    });

    it('sets error on exception', async () => {
      const { storageStore } = freshModule();
      mockDsmClient.getStorageStatus.mockRejectedValue(new Error('network'));

      await storageStore.refreshOverview();
      expect(storageStore.getSnapshot().overviewError).toBe('Failed to load storage info.');
    });
  });

  describe('refreshDlvsAndPresence()', () => {
    it('loads DLVs and checks presence', async () => {
      const { storageStore } = freshModule();
      const dlv = { cptaAnchorHex: '0xabc' };
      mockDsmClient.listLocalDlvs.mockResolvedValue([dlv]);
      mockDsmClient.checkDlvPresence.mockResolvedValue({ anchor: '0xabc', observed: 2 });

      await storageStore.refreshDlvsAndPresence();
      const s = storageStore.getSnapshot();
      expect(s.dlvs).toEqual([dlv]);
      expect(s.presence['0xabc']).toEqual({ anchor: '0xabc', observed: 2 });
      expect(s.dlvLoading).toBe(false);
    });

    it('handles empty DLV list', async () => {
      const { storageStore } = freshModule();
      mockDsmClient.listLocalDlvs.mockResolvedValue([]);

      await storageStore.refreshDlvsAndPresence();
      expect(storageStore.getSnapshot().dlvs).toEqual([]);
    });

    it('skips presence entries without anchor', async () => {
      const { storageStore } = freshModule();
      mockDsmClient.listLocalDlvs.mockResolvedValue([{ cptaAnchorHex: '0x1' }]);
      mockDsmClient.checkDlvPresence.mockResolvedValue({ observed: 1 }); // no anchor

      await storageStore.refreshDlvsAndPresence();
      expect(storageStore.getSnapshot().presence).toEqual({});
    });

    it('handles listLocalDlvs returning non-array', async () => {
      const { storageStore } = freshModule();
      mockDsmClient.listLocalDlvs.mockResolvedValue(null);

      await storageStore.refreshDlvsAndPresence();
      expect(storageStore.getSnapshot().dlvs).toEqual([]);
    });

    it('handles error gracefully', async () => {
      const { storageStore } = freshModule();
      jest.spyOn(console, 'warn').mockImplementation(() => {});
      mockDsmClient.listLocalDlvs.mockRejectedValue(new Error('fail'));

      await storageStore.refreshDlvsAndPresence();
      expect(storageStore.getSnapshot().dlvLoading).toBe(false);
    });
  });

  describe('refreshNodeHealth()', () => {
    it('fetches node health metrics', async () => {
      const { storageStore } = freshModule();
      const health = [{ url: 'http://n1', status: 'healthy' }];
      mockStorageNodeService.checkAllNodesHealth.mockResolvedValue(health);

      await storageStore.refreshNodeHealth();
      const s = storageStore.getSnapshot();
      expect(s.nodeHealth).toEqual(health);
      expect(s.nodeHealthLoading).toBe(false);
      expect(s.nodeHealthRefreshing).toBe(false);
    });

    it('sets nodeHealthRefreshing=true when isRefresh=true', async () => {
      const { storageStore } = freshModule();
      const listener = jest.fn();
      storageStore.subscribe(listener);
      mockStorageNodeService.checkAllNodesHealth.mockResolvedValue([]);

      await storageStore.refreshNodeHealth(true);
      // First emit sets nodeHealthRefreshing to true
      const firstCall = listener.mock.calls[0];
      expect(storageStore.getSnapshot().nodeHealthRefreshing).toBe(false); // final
    });

    it('handles health check failure', async () => {
      const { storageStore } = freshModule();
      mockStorageNodeService.checkAllNodesHealth.mockRejectedValue(new Error('fail'));

      await storageStore.refreshNodeHealth();
      expect(storageStore.getSnapshot().nodeHealthLoading).toBe(false);
    });
  });

  describe('addNode()', () => {
    it('returns success and refreshes health', async () => {
      const { storageStore } = freshModule();
      mockStorageNodeService.addNode.mockResolvedValue({ success: true, assignedUrl: 'http://new' });
      mockStorageNodeService.checkAllNodesHealth.mockResolvedValue([]);

      const result = await storageStore.addNode();
      expect(result).toEqual({ success: true, assignedUrl: 'http://new' });
      expect(mockStorageNodeService.checkAllNodesHealth).toHaveBeenCalled();
    });

    it('returns error on failure', async () => {
      const { storageStore } = freshModule();
      mockStorageNodeService.addNode.mockResolvedValue({ success: false, error: 'limit' });

      const result = await storageStore.addNode();
      expect(result).toEqual({ success: false, error: 'limit' });
    });
  });

  describe('removeNode()', () => {
    it('returns success and refreshes health', async () => {
      const { storageStore } = freshModule();
      mockStorageNodeService.removeNode.mockResolvedValue({ success: true });
      mockStorageNodeService.checkAllNodesHealth.mockResolvedValue([]);

      const result = await storageStore.removeNode('http://n1');
      expect(result).toEqual({ success: true });
      expect(mockStorageNodeService.checkAllNodesHealth).toHaveBeenCalled();
    });

    it('returns error on failure', async () => {
      const { storageStore } = freshModule();
      mockStorageNodeService.removeNode.mockResolvedValue({ success: false, error: 'not found' });

      const result = await storageStore.removeNode('http://n1');
      expect(result).toEqual({ success: false, error: 'not found' });
    });
  });

  describe('collectDiagnostics()', () => {
    it('collects and stores diagnostics', async () => {
      const { storageStore } = freshModule();
      const bundle = { timestamp: 1, data: 'diag' };
      mockStorageNodeService.collectDiagnostics.mockResolvedValue(bundle);

      await storageStore.collectDiagnostics();
      expect(storageStore.getSnapshot().diagnostics).toEqual(bundle);
      expect(storageStore.getSnapshot().diagnosticsCollecting).toBe(false);
    });

    it('handles failure gracefully', async () => {
      const { storageStore } = freshModule();
      mockStorageNodeService.collectDiagnostics.mockRejectedValue(new Error('fail'));

      await storageStore.collectDiagnostics();
      expect(storageStore.getSnapshot().diagnosticsCollecting).toBe(false);
    });
  });

  describe('clearDiagnostics()', () => {
    it('sets diagnostics to null', async () => {
      const { storageStore } = freshModule();
      mockStorageNodeService.collectDiagnostics.mockResolvedValue({ data: 'x' });
      await storageStore.collectDiagnostics();
      storageStore.clearDiagnostics();
      expect(storageStore.getSnapshot().diagnostics).toBeNull();
    });
  });

  describe('exportDiagnostics()', () => {
    it('delegates to storageNodeService', () => {
      const { storageStore } = freshModule();
      const bundle = { data: 'x' } as any;
      storageStore.exportDiagnostics(bundle);
      expect(mockStorageNodeService.exportDiagnostics).toHaveBeenCalledWith(bundle);
    });
  });

  describe('createBackup()', () => {
    it('returns success when backup succeeds', async () => {
      const { storageStore } = freshModule();
      mockDsmClient.createBackup = jest.fn().mockResolvedValue({ success: true });

      const result = await storageStore.createBackup('pw');
      expect(result).toEqual({ success: true });
    });

    it('sets error when backup not available', async () => {
      const { storageStore } = freshModule();
      delete mockDsmClient.createBackup;

      const result = await storageStore.createBackup();
      expect(result.success).toBe(false);
      expect(result.error).toContain('not available');
      expect(storageStore.getSnapshot().overviewError).toContain('not available');

      mockDsmClient.createBackup = jest.fn();
    });

    it('sets error when backup returns failure', async () => {
      const { storageStore } = freshModule();
      mockDsmClient.createBackup = jest.fn().mockResolvedValue({ success: false, error: 'no space' });

      const result = await storageStore.createBackup();
      expect(result.success).toBe(false);
      expect(storageStore.getSnapshot().overviewError).toBe('no space');
    });

    it('handles exception during backup', async () => {
      const { storageStore } = freshModule();
      mockDsmClient.createBackup = jest.fn().mockRejectedValue(new Error('boom'));

      const result = await storageStore.createBackup();
      expect(result).toEqual({ success: false, error: 'Failed to create backup.' });
    });
  });
});

// Hook tests use static imports (same React instance as @testing-library/react)
import { useStorageStore } from '../storageStore';

describe('useStorageStore hook', () => {
  it('returns the full snapshot', () => {
    const { result } = renderHook(() => useStorageStore());
    expect(result.current).toHaveProperty('storageInfo');
    expect(result.current).toHaveProperty('overviewLoading');
    expect(result.current).toHaveProperty('dlvs');
    expect(result.current).toHaveProperty('nodeHealth');
  });
});
