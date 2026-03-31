/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import { useSyncExternalStore } from 'react';
import { dsmClient } from '../services/dsmClient';
import { bridgeEvents } from '../bridge/bridgeEvents';
import type { Transaction } from '@/hooks/useTransactions';
import type { WalletBalance, WalletState } from '../contexts/WalletContext';

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

  private hasObservedBalances = false;

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

  private balanceKey(entry: WalletBalance): string {
    return String(entry.tokenId || entry.symbol || entry.tokenName || 'UNKNOWN');
  }

  private coerceBalance(value: unknown): bigint {
    if (typeof value === 'bigint') return value;
    if (typeof value === 'number') return BigInt(Number.isFinite(value) ? Math.trunc(value) : 0);
    if (typeof value === 'string') {
      try {
        return BigInt(value);
      } catch {
        return 0n;
      }
    }
    return 0n;
  }

  private detectPositiveCredits(previous: WalletBalance[], next: WalletBalance[]): Array<{
    tokenId: string;
    delta: bigint;
    nextBalance: bigint;
  }> {
    const previousByToken = new Map<string, bigint>();
    previous.forEach((entry) => {
      previousByToken.set(this.balanceKey(entry), this.coerceBalance(entry.balance));
    });

    return next.flatMap((entry) => {
      const tokenId = this.balanceKey(entry);
      const nextBalance = this.coerceBalance(entry.balance);
      const previousBalance = previousByToken.get(tokenId) ?? 0n;
      const delta = nextBalance - previousBalance;
      return delta > 0n ? [{ tokenId, delta, nextBalance }] : [];
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
      const previousBalances = this.snapshot.balances.slice();
      const [eraResult] = await Promise.allSettled([
        dsmClient.getAllBalances(),
      ]);

      // Wallet balances are canonical from the local SMT/hash-chain state.
      // Do not overwrite dBTC with the separate Bitcoin chain-wallet endpoint.
      let balances: WalletBalance[];
      if (eraResult.status === 'fulfilled') {
        balances = (eraResult.value as any[])
          .filter((entry: any) => String(entry.tokenId || '').toUpperCase() !== 'BTC_CHAIN')
          .slice();
      } else {
        console.error('WalletStore: ERA balance fetch failed:', eraResult.reason);
        balances = this.snapshot.balances.slice();
      }

      // Report partial failures as a non-blocking error
      const failedParts: string[] = [];
      if (eraResult.status === 'rejected') failedParts.push('ERA');
      const error = failedParts.length > 0
        ? `Failed to refresh ${failedParts.join(' & ')} balances`
        : null;

      this.setState({ balances, error });

      const positiveCredits = this.hasObservedBalances
        ? this.detectPositiveCredits(previousBalances, balances)
        : [];
      this.hasObservedBalances = true;

      if (positiveCredits.length > 0) {
        const firstCredit = positiveCredits[0];
        bridgeEvents.emit('wallet.creditReceived', {
          source: 'wallet.refreshBalances',
          tokenId: firstCredit.tokenId,
          amount: firstCredit.delta.toString(),
          nextBalance: firstCredit.nextBalance.toString(),
          creditCount: positiveCredits.length,
        });
      }
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
