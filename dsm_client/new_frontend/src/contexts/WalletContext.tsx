/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/contexts/WalletContext.tsx
// SPDX-License-Identifier: Apache-2.0
import React, { createContext, useContext, useEffect, useMemo, type ReactNode } from 'react';
import { useUX } from './UXContext';
import { dsmClient } from '../services/dsmClient';
import { useEventSignal } from '../bridge/useEventSignal';
import { useBridgeEvent } from '@/hooks/useBridgeEvents';
import type { Transaction } from '@/hooks/useTransactions';
import { useWalletSync } from '@/hooks/useWalletSync';
import { walletStore, useWalletStore } from '../stores/walletStore';

export interface WalletBalance {
  tokenId: string;
  tokenName: string;
  balance: bigint;
  decimals: number;
  symbol: string;
}

export interface WalletContact {
  alias: string;
  deviceId: string;
  genesisHash: string;
  chainTip?: string;
  chainTipSmtProof?: Uint8Array;
  bleAddress?: string;
  status?: string;
  needsOnlineReconcile?: boolean;
  genesisVerifiedOnline?: boolean;
  verifyCounter?: number;
  addedCounter?: number;
  verifyingStorageNodes?: number;
}

export interface WalletState {
  genesisHash: string | null;
  deviceId: string | null;
  balances: WalletBalance[];
  transactions: Transaction[];
  isInitialized: boolean;
  isLoading: boolean;
  error: string | null;
}

export interface WalletContextValue extends WalletState {
  refreshBalances: () => Promise<void>;
  refreshTransactions: () => Promise<void>;
  refreshAll: () => Promise<void>;
  setError: (error: string | null) => void;
  dsmClient: typeof dsmClient;
}

const defaultValue: WalletContextValue = {
  genesisHash: null,
  deviceId: null,
  balances: [],
  transactions: [],
  isInitialized: false,
  isLoading: false,
  error: null,
  refreshBalances: async () => {},
  refreshTransactions: async () => {},
  refreshAll: async () => {},
  setError: () => {},
  dsmClient,
};

export const WalletContext = createContext<WalletContextValue>(defaultValue);

export const WalletProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const { notifyToast } = useUX();
  const state = useWalletStore();
  const bilateralSignal = useEventSignal('wallet.bilateralCommitted');

  const refreshWalletProjection = React.useCallback(async () => {
    try {
      await walletStore.refreshAll();
    } catch (error) {
      console.warn('[WalletProvider] projection refresh failed:', error);
    }
  }, []);

  useEffect(() => {
    void walletStore.initialize();
  }, []);

  useWalletSync({
    onRefreshAll: async () => {
      try {
        await walletStore.refreshAll();
      } catch (error) {
        console.warn('[WalletProvider] refreshAll failed:', error);
      }
    },
    onRefreshBalances: async () => {
      try {
        await walletStore.refreshBalances();
      } catch (error) {
        console.warn('[WalletProvider] refreshBalances failed:', error);
      }
    },
    onRefreshTransactions: async () => {
      try {
        await walletStore.refreshTransactions();
      } catch (error) {
        console.warn('[WalletProvider] refreshTransactions failed:', error);
      }
    },
    onIdentityReady: async () => {
      try {
        await walletStore.initialize();
      } catch (error) {
        console.warn('[WalletProvider] identity refresh failed:', error);
      }
    },
  });

  useBridgeEvent('bilateral.transferComplete', () => {
    void refreshWalletProjection();
  }, [refreshWalletProjection]);

  useBridgeEvent('deposit.completed', () => {
    void refreshWalletProjection();
  }, [refreshWalletProjection]);

  useBridgeEvent('wallet.exitCompleted', () => {
    void refreshWalletProjection();
  }, [refreshWalletProjection]);

  useBridgeEvent('inbox.updated', (detail?: { unreadCount?: number; newItems?: number }) => {
    const newItems = typeof detail?.newItems === 'number' ? detail.newItems : 0;
    if (newItems <= 0) return;
    void refreshWalletProjection();
  }, [refreshWalletProjection]);

  useEffect(() => {
    if (bilateralSignal > 0) {
      void walletStore.refreshAll();
      try {
        notifyToast('transfer_accepted', 'Transfer accepted');
      } catch (error) {
        console.warn('[WalletProvider] notifyToast failed:', error);
      }
    }
  }, [bilateralSignal, notifyToast]);

  const value = useMemo<WalletContextValue>(() => ({
    genesisHash: state.genesisHash,
    deviceId: state.deviceId,
    balances: state.balances,
    transactions: state.transactions,
    isInitialized: state.isInitialized,
    isLoading: state.isLoading,
    error: state.error,
    refreshBalances: walletStore.refreshBalances,
    refreshTransactions: walletStore.refreshTransactions,
    refreshAll: walletStore.refreshAll,
    setError: walletStore.setError,
    dsmClient,
  }), [state]);

  return <WalletContext.Provider value={value}>{children}</WalletContext.Provider>;
};

export function useWallet(): WalletContextValue {
  return useContext(WalletContext);
}
