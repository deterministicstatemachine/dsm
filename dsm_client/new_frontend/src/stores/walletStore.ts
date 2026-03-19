/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import { useSyncExternalStore } from 'react';
import { dsmClient } from '../services/dsmClient';
import { getDbtcBalance } from '../services/bitcoinTap';
import type { Transaction } from '@/hooks/useTransactions';
import { toBase32Crockford } from '../dsm/decoding';
import type { WalletBalance, WalletState } from '../contexts/WalletContext';

type ImmediateSenderUpdate = {
  success?: boolean;
  tokenId?: string;
  newBalance?: bigint | string | number;
  transactionHash?: Uint8Array;
  toDeviceId?: Uint8Array;
  amount?: bigint | string | number;
};

const initialState: WalletState = {
  genesisHash: null,
  deviceId: null,
  balances: [],
  transactions: [],
  isInitialized: false,
  isLoading: false,
  error: null,
};

class WalletStore {
  private snapshot: WalletState = initialState;

  private listeners = new Set<() => void>();

  // Track concurrent in-flight refresh calls so isLoading stays true
  // until ALL concurrent operations complete (prevents race where
  // refreshBalances finishes first and clears isLoading while
  // refreshTransactions is still in flight).
  private loadingCount = 0;

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  getSnapshot = (): WalletState => this.snapshot;

  getServerSnapshot = (): WalletState => this.snapshot;

  setError = (error: string | null): void => {
    this.setState({ error });
  };

  private setState(patch: Partial<WalletState>): void {
    this.snapshot = {
      ...this.snapshot,
      ...patch,
    };
    this.emit();
  }

  private setImmediateBalance(tokenId: string, balance: bigint): void {
    this.setState({
      balances: this.snapshot.balances.map((entry) =>
        entry.tokenId === tokenId ? { ...entry, balance } : entry,
      ),
    });
  }

  private appendTransaction(tx: Transaction): void {
    this.setState({
      transactions: [tx, ...this.snapshot.transactions],
    });
  }

  initialize = async (): Promise<void> => {
    try {
      this.setState({ isLoading: true, error: null });

      const identity = await dsmClient.getIdentity();
      const genesisHash = identity?.genesisHash ?? null;
      const deviceId = identity?.deviceId ?? null;

      this.setState({
        genesisHash,
        deviceId,
        isInitialized: Boolean(genesisHash && deviceId),
        isLoading: false,
        error: null,
      });

      if (genesisHash && deviceId) {
        await this.refreshAll();
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to initialize wallet';
      this.setState({ isLoading: false, error: message });
    }
  };

  refreshBalances = async (): Promise<void> => {
    this.loadingCount++;
    this.setState({ isLoading: true });
    try {
      const [eraResult, dbtcResult] = await Promise.allSettled([
        dsmClient.getAllBalances(),
        getDbtcBalance(),
      ]);

      // Use ERA balances if that fetch succeeded; keep previous balances on failure
      let balances: WalletBalance[];
      if (eraResult.status === 'fulfilled') {
        balances = (eraResult.value as any[])
          .filter((entry: any) => String(entry.tokenId || '').toUpperCase() !== 'BTC_CHAIN')
          .slice();
      } else {
        console.error('WalletStore: ERA balance fetch failed:', eraResult.reason);
        balances = this.snapshot.balances.filter((b) => b.tokenId.toUpperCase() !== 'DBTC');
      }

      // Merge dBTC if that fetch succeeded
      if (dbtcResult.status === 'fulfilled' && dbtcResult.value !== null) {
        const dbtcBalance = dbtcResult.value;
        const available = typeof dbtcBalance.available === 'bigint'
          ? dbtcBalance.available
          : BigInt(0);
        const index = balances.findIndex((entry) => entry.tokenId.toUpperCase() === 'DBTC');
        const nextEntry: WalletBalance = {
          tokenId: 'dBTC',
          tokenName: 'dBTC',
          balance: available,
          decimals: 8,
          symbol: 'dBTC',
        };
        if (index >= 0) {
          balances[index] = nextEntry;
        } else {
          balances.unshift(nextEntry);
        }
      } else if (dbtcResult.status === 'rejected') {
        console.error('WalletStore: dBTC balance fetch failed:', dbtcResult.reason);
        // Preserve existing dBTC entry from previous snapshot if any
        const prevDbtc = this.snapshot.balances.find((b) => b.tokenId.toUpperCase() === 'DBTC');
        if (prevDbtc && !balances.some((b) => b.tokenId.toUpperCase() === 'DBTC')) {
          balances.unshift(prevDbtc);
        }
      }

      // Report partial failures as a non-blocking error
      const failedParts: string[] = [];
      if (eraResult.status === 'rejected') failedParts.push('ERA');
      if (dbtcResult.status === 'rejected') failedParts.push('dBTC');
      const error = failedParts.length > 0
        ? `Failed to refresh ${failedParts.join(' & ')} balances`
        : null;

      this.setState({ balances, error });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to refresh balances';
      console.error('WalletStore: refreshBalances failed:', message);
      this.setState({ error: message });
    } finally {
      this.loadingCount = Math.max(0, this.loadingCount - 1);
      if (this.loadingCount === 0) this.setState({ isLoading: false });
    }
  };

  refreshTransactions = async (): Promise<void> => {
    this.loadingCount++;
    this.setState({ isLoading: true });
    try {
      const history = await dsmClient.getWalletHistory();
      const transactions = Array.isArray((history as any)?.transactions)
        ? (history as any).transactions
        : [];
      this.setState({ transactions: transactions as Transaction[] });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to refresh transactions';
      console.error('WalletStore: refreshTransactions failed:', message);
      this.setState({ error: message });
    } finally {
      this.loadingCount = Math.max(0, this.loadingCount - 1);
      if (this.loadingCount === 0) this.setState({ isLoading: false });
    }
  };

  refreshAll = async (): Promise<void> => {
    await Promise.all([this.refreshBalances(), this.refreshTransactions()]);
  };

  applyImmediateSenderUpdate = (detail: ImmediateSenderUpdate): void => {
    const hasNewBalance = detail?.newBalance !== undefined && detail?.newBalance !== null;
    const tokenId = String(detail?.tokenId ?? 'ERA');
    if (!detail?.success || !hasNewBalance) return;

    try {
      const immediateBalance = BigInt(String(detail.newBalance));
      this.setImmediateBalance(tokenId, immediateBalance);
    } catch (error) {
      console.warn('WalletStore: immediate balance reflect failed, will refresh from SDK', error);
    }

    try {
      const txHash = detail?.transactionHash;
      const txId = txHash instanceof Uint8Array && txHash.length === 32
        ? toBase32Crockford(txHash)
        : 'LOCAL_TX';
      const toDeviceId = detail?.toDeviceId;
      const recipient = toDeviceId instanceof Uint8Array ? toBase32Crockford(toDeviceId) : '';
      const amount = BigInt(String(detail?.amount ?? 0));
      this.appendTransaction({
        txId,
        type: 'online',
        amount,
        recipient,
        createdAt: Math.floor(Date.now() / 1000),
        status: 'confirmed',
        syncStatus: 'synced',
      } as any);
    } catch (error) {
      console.warn('WalletStore: immediate history append failed (non-fatal)', error);
    }

    queueMicrotask(() => {
      try {
        void this.refreshBalances();
      } catch (error) {
        console.warn('WalletStore: refreshBalances failed:', error);
      }
    });
  };

  private emit(): void {
    this.listeners.forEach((listener) => listener());
  }
}

export const walletStore = new WalletStore();

export function useWalletStore(): WalletState {
  return useSyncExternalStore(
    walletStore.subscribe,
    walletStore.getSnapshot,
    walletStore.getServerSnapshot,
  );
}

export function useWalletBalances(): WalletBalance[] {
  return useSyncExternalStore(
    walletStore.subscribe,
    () => walletStore.getSnapshot().balances,
    () => walletStore.getServerSnapshot().balances,
  );
}

export function useWalletTransactions(): Transaction[] {
  return useSyncExternalStore(
    walletStore.subscribe,
    () => walletStore.getSnapshot().transactions,
    () => walletStore.getServerSnapshot().transactions,
  );
}

// Memoized identity selector — avoids creating a new object reference on every
// unrelated store change (e.g. transaction updates) which would cause needless
// re-renders in all useWalletIdentity() consumers.
let _cachedIdentity: { genesisHash: string | null; deviceId: string | null } = {
  genesisHash: null,
  deviceId: null,
};

function getIdentitySnapshot(): { genesisHash: string | null; deviceId: string | null } {
  const s = walletStore.getSnapshot();
  if (s.genesisHash !== _cachedIdentity.genesisHash || s.deviceId !== _cachedIdentity.deviceId) {
    _cachedIdentity = { genesisHash: s.genesisHash, deviceId: s.deviceId };
  }
  return _cachedIdentity;
}

export function useWalletIdentity(): { genesisHash: string | null; deviceId: string | null } {
  return useSyncExternalStore(
    walletStore.subscribe,
    getIdentitySnapshot,
    getIdentitySnapshot,
  );
}

export function useWalletInitialized(): boolean {
  return useSyncExternalStore(
    walletStore.subscribe,
    () => walletStore.getSnapshot().isInitialized,
    () => walletStore.getServerSnapshot().isInitialized,
  );
}

export function useWalletLoading(): boolean {
  return useSyncExternalStore(
    walletStore.subscribe,
    () => walletStore.getSnapshot().isLoading,
    () => walletStore.getServerSnapshot().isLoading,
  );
}

export function useWalletError(): string | null {
  return useSyncExternalStore(
    walletStore.subscribe,
    () => walletStore.getSnapshot().error,
    () => walletStore.getServerSnapshot().error,
  );
}
