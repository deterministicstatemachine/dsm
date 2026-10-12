/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import { useSyncExternalStore } from 'react';
import { dsmClient } from '../services/dsmClient';
import { isIdentityUnavailable } from '../dsm/identityUnavailable';
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

  initialize = async (): Promise<void> => {
    try {
      this.setState({ isLoading: true, error: null });

      const identity = await dsmClient.getIdentity();

      this.setState({
        genesisHash: identity.genesisHash,
        deviceId: identity.deviceId,
        isInitialized: true,
        isLoading: false,
        error: null,
      });

      await this.refreshAll();
    } catch (error) {
      // No identity on this device is a state, not a failure: the store stays
      // uninitialized with no error, and the genesis flow is where the app
      // goes. Anything else — the runtime not ready within the window, a read
      // that failed — is reported as what it is.
      if (isIdentityUnavailable(error) && error.state === 'missing') {
        this.setState({ genesisHash: null, deviceId: null, isInitialized: false, isLoading: false, error: null });
        return;
      }
      const message = error instanceof Error ? error.message : 'Failed to initialize wallet';
      this.setState({ isLoading: false, error: message });
    }
  };

  refreshBalances = async (): Promise<void> => {
    this.loadingCount++;
    this.setState({ isLoading: true });
    try {
      const [eraResult] = await Promise.allSettled([
        dsmClient.getAllBalances(),
      ]);

      // Wallet balances are canonical from the local SMT/hash-chain state.
      // Do not overwrite dBTC with the separate Bitcoin chain-wallet endpoint.
      let balances: WalletBalance[];
      if (eraResult.status === 'fulfilled') {
        balances = eraResult.value.filter((entry) => entry.tokenId.toUpperCase() !== 'BTC_CHAIN');
      } else {
        console.error('WalletStore: balance fetch failed:', eraResult.reason);
        balances = this.snapshot.balances.slice();
      }

      // A failed refresh keeps the last list and says so.
      const error = eraResult.status === 'rejected' ? 'Failed to refresh balances' : null;

      // A balance that is higher than the last read is not a credit this
      // store may announce: the last read may have been empty (the runtime
      // still warming up at launch) or stale, and a difference between two
      // reads is not Rust's word that anything arrived. What arrived is
      // announced by Rust — inbox.updated for items it processed, the
      // completion events for a deposit or a sealed transfer.
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
