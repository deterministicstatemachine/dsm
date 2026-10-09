/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import { useSyncExternalStore } from 'react';
import { getStorageStatus } from '../dsm/storage';
import type { StorageStatus } from '../dsm/types';
import { listVaults, type VaultSummary } from '../services/bitcoinTap';
import { vaults as listSofiVaults, type OwnedVault } from '../dsm/sofi';

/** The owner's liquidity vaults at their walked heads (sofi.vaults). */
export type SofiVaultsView =
  | { state: 'loading' }
  | { state: 'ready'; vaults: OwnedVault[] }
  | { state: 'error'; message: string };

type StorageStoreSnapshot = {
  status: StorageStatus | null;
  statusLoading: boolean;
  statusError: string | null;
  dlvs: VaultSummary[];
  dlvLoading: boolean;
  sofiVaults: SofiVaultsView;
};

class StorageStore {
  private snapshot: StorageStoreSnapshot = {
    status: null,
    statusLoading: true,
    statusError: null,
    dlvs: [],
    dlvLoading: true,
    sofiVaults: { state: 'loading' },
  };

  private listeners = new Set<() => void>();

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  getSnapshot = (): StorageStoreSnapshot => this.snapshot;

  getServerSnapshot = (): StorageStoreSnapshot => this.snapshot;

  /** Ask the SDK for the storage set and each member's answer. */
  refreshStatus = async (): Promise<void> => {
    this.setState({ statusLoading: true, statusError: null });
    try {
      const status = await getStorageStatus();
      this.setState({ status, statusLoading: false });
    } catch (e: any) {
      this.setState({
        status: null,
        statusError: e?.message || 'storage.status failed',
        statusLoading: false,
      });
    }
  };

  refreshDlvsAndPresence = async (): Promise<void> => {
    this.setState({ dlvLoading: true });
    try {
      const dlvs = await listVaults();
      this.setState({ dlvs, dlvLoading: false });
    } catch (error: any) {
      console.warn('[StorageStore] refreshDlvsAndPresence error:', error?.message || error);
      this.setState({ dlvLoading: false });
    }
  };

  /**
   * Ask the SDK for this device's liquidity vaults, each at its head. Either
   * outcome lands in the snapshot: the vaults, or why they are not in hand.
   */
  refreshSofiVaults = (): void => {
    this.setState({ sofiVaults: { state: 'loading' } });
    listSofiVaults().then(
      (vaults) => this.setState({ sofiVaults: { state: 'ready', vaults } }),
      (e: unknown) =>
        this.setState({
          sofiVaults: { state: 'error', message: e instanceof Error ? e.message : String(e) },
        }),
    );
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
