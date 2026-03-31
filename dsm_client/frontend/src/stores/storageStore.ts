/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import { useSyncExternalStore } from 'react';
import { dsmClient } from '../services/dsmClient';
import type { DlvIndexEntry } from '../dsm/index';
import { storageNodeService } from '../services/storageNodeService';
import { isFeatureEnabled } from '../config/featureFlags';
import type {
  DiagnosticsBundle,
  NodeHealthMetrics,
  StorageNodesConfig,
  DisplayOnlyNumber,
} from '../types/storage';
import { asDisplayOnlyNumber } from '../types/storage';

export type StorageOverviewStatus = {
  totalNodes: number;
  connectedNodes: number;
  lastSync: DisplayOnlyNumber;
  dataSize: string;
  backupStatus: string;
};

export type DlvPresenceNode = {
  node: string;
  reachable: boolean;
  hasDescriptor: boolean | 'unknown';
  hasState: boolean | 'unknown';
};

export type DlvPresenceSummary = {
  anchor?: string;
  observed: number;
  nodes?: DlvPresenceNode[];
};

type StorageStoreSnapshot = {
  storageInfo: StorageOverviewStatus | null;
  overviewLoading: boolean;
  overviewError: string | null;
  dlvs: DlvIndexEntry[];
  presence: Record<string, DlvPresenceSummary>;
  dlvLoading: boolean;
  showObjectsTab: boolean;
  nodesConfig: StorageNodesConfig;
  nodeHealth: NodeHealthMetrics[];
  nodeHealthLoading: boolean;
  nodeHealthRefreshing: boolean;
  diagnostics: DiagnosticsBundle | null;
  diagnosticsCollecting: boolean;
};

type BackupResult = { success: boolean; error?: string };

type DsmStorageApi = {
  getStorageStatus?: () => Promise<StorageOverviewStatus | null | undefined>;
  createBackup?: (password?: string) => Promise<BackupResult>;
  listLocalDlvs?: () => Promise<DlvIndexEntry[]>;
  checkDlvPresence?: (entry: DlvIndexEntry) => Promise<DlvPresenceSummary | null | undefined>;
};

const client = dsmClient as unknown as DsmStorageApi;

class StorageStore {
  private snapshot: StorageStoreSnapshot = {
    storageInfo: null,
    overviewLoading: true,
    overviewError: null,
    dlvs: [],
    presence: {},
    dlvLoading: true,
    showObjectsTab: false,
    nodesConfig: storageNodeService.getNodesConfig(),
    nodeHealth: [],
    nodeHealthLoading: true,
    nodeHealthRefreshing: false,
    diagnostics: null,
    diagnosticsCollecting: false,
  };

  private listeners = new Set<() => void>();

  private initPromise: Promise<void> | null = null;

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  getSnapshot = (): StorageStoreSnapshot => this.snapshot;

  getServerSnapshot = (): StorageStoreSnapshot => this.snapshot;

  initialize = async (): Promise<void> => {
    if (this.initPromise) return this.initPromise;
    this.initPromise = (async () => {
      await storageNodeService.init();
      this.setState({ nodesConfig: storageNodeService.getNodesConfig() });
      const showObjectsTab = await isFeatureEnabled('storageObjectBrowser');
      this.setState({ showObjectsTab });
    })().finally(() => {
      this.initPromise = null;
    });

    return this.initPromise;
  };

  refreshOverview = async (): Promise<void> => {
    this.setState({ overviewLoading: true, overviewError: null });
    try {
      if (typeof client.getStorageStatus !== 'function') {
        this.setState({
          overviewError: 'Storage status is not available in this build.',
          storageInfo: null,
          overviewLoading: false,
        });
        return;
      }

      const result = await client.getStorageStatus();
      if (!result) {
        this.setState({
          overviewError: 'No storage data returned from backend.',
          storageInfo: null,
          overviewLoading: false,
        });
        return;
      }

      this.setState({
        storageInfo: {
          ...result,
          lastSync: asDisplayOnlyNumber((result as any).lastSync ?? 0),
        },
        overviewLoading: false,
      });
    } catch {
      this.setState({
        overviewError: 'Failed to load storage info.',
        storageInfo: null,
        overviewLoading: false,
      });
    }
  };

  refreshDlvsAndPresence = async (): Promise<void> => {
    this.setState({ dlvLoading: true });
    try {
      const list = await client.listLocalDlvs?.();
      const dlvs = Array.isArray(list) ? list : [];
      const presence: Record<string, DlvPresenceSummary> = {};

      for (const entry of dlvs) {
        try {
          const summary = await client.checkDlvPresence?.(entry);
          if (summary?.anchor) {
            presence[entry.cptaAnchorHex] = summary;
          }
        } catch {}
      }

      this.setState({ dlvs, presence, dlvLoading: false });
    } catch (error: any) {
      console.warn('[StorageStore] refreshDlvsAndPresence error:', error?.message || error);
      this.setState({ dlvLoading: false });
    }
  };

  refreshNodeHealth = async (isRefresh = false): Promise<void> => {
    this.setState({
      nodesConfig: storageNodeService.getNodesConfig(),
      nodeHealthLoading: isRefresh ? this.snapshot.nodeHealthLoading : true,
      nodeHealthRefreshing: isRefresh,
    });

    try {
      const nodeHealth = await storageNodeService.checkAllNodesHealth();
      this.setState({
        nodesConfig: storageNodeService.getNodesConfig(),
        nodeHealth,
        nodeHealthLoading: false,
        nodeHealthRefreshing: false,
      });
    } catch {
      this.setState({
        nodesConfig: storageNodeService.getNodesConfig(),
        nodeHealthLoading: false,
        nodeHealthRefreshing: false,
      });
    }
  };

  addNode = async (): Promise<{ success: boolean; error?: string; assignedUrl?: string }> => {
    const result = await storageNodeService.addNode();
    this.setState({ nodesConfig: storageNodeService.getNodesConfig() });
    if (result.success) {
      await this.refreshNodeHealth(true);
      return { success: true, assignedUrl: result.assignedUrl };
    }
    return { success: false, error: result.error };
  };

  removeNode = async (url: string): Promise<{ success: boolean; error?: string }> => {
    const result = await storageNodeService.removeNode(url);
    this.setState({ nodesConfig: storageNodeService.getNodesConfig() });
    if (result.success) {
      await this.refreshNodeHealth(true);
      return { success: true };
    }
    return { success: false, error: result.error };
  };

  collectDiagnostics = async (): Promise<void> => {
    this.setState({ diagnosticsCollecting: true });
    try {
      const diagnostics = await storageNodeService.collectDiagnostics();
      this.setState({ diagnostics, diagnosticsCollecting: false });
    } catch {
      this.setState({ diagnosticsCollecting: false });
    }
  };

  clearDiagnostics = (): void => {
    this.setState({ diagnostics: null });
  };

  exportDiagnostics = (bundle: DiagnosticsBundle): Uint8Array => {
    return storageNodeService.exportDiagnostics(bundle);
  };

  createBackup = async (password?: string): Promise<BackupResult> => {
    this.setState({ overviewError: null });
    if (typeof client.createBackup !== 'function') {
      const result = { success: false, error: 'Backup is not available in this build.' };
      this.setState({ overviewError: result.error });
      return result;
    }

    try {
      const result = await client.createBackup(password);
      if (!result.success) {
        this.setState({ overviewError: result.error ?? 'Backup failed.' });
      }
      return result;
    } catch {
      const result = { success: false, error: 'Failed to create backup.' };
      this.setState({ overviewError: result.error });
      return result;
    }
  };

  private setState(patch: Partial<StorageStoreSnapshot>): void {
    this.snapshot = {
      ...this.snapshot,
      ...patch,
    };
    this.emit();
  }

  private emit(): void {
    this.listeners.forEach((listener) => listener());
  }
}

export const storageStore = new StorageStore();

export function useStorageStore(): StorageStoreSnapshot {
  return useSyncExternalStore(
    storageStore.subscribe,
    storageStore.getSnapshot,
    storageStore.getServerSnapshot,
  );
}
