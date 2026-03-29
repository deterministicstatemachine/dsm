/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/hooks/useWalletSync.ts
// Centralized wallet event synchronization hook.
// Subscribes to bridge events and invokes provided callbacks so the provider stays dumb.

import { useCallback } from 'react';
import { useBridgeEvent } from './useBridgeEvents';

export type WalletSyncHandlers = {
  onRefreshAll: () => void | Promise<void>;
  onRefreshBalances?: () => void | Promise<void>;
  onRefreshTransactions?: () => void | Promise<void>;
  onIdentityReady?: () => void | Promise<void>;
};

export function useWalletSync(handlers: WalletSyncHandlers) {
  const { onRefreshAll, onRefreshBalances, onRefreshTransactions, onIdentityReady } = handlers;

  // NOTE: wallet.refresh is handled by useWalletRefreshListener (RAF-coalesced
  // + 120-frame cooldown) inside useWalletScreenData.  We intentionally do NOT
  // subscribe to it here — doing so would create an unthrottled duplicate that
  // floods the bridge with balance/history queries during BLE transfers.

  // Specific sub-stream updates
  useBridgeEvent('wallet.historyUpdated', useCallback(() => {
    if (!onRefreshTransactions) return;
    Promise.resolve(onRefreshTransactions()).catch((e) => {
      console.error('[useWalletSync] wallet.historyUpdated handler failed:', e);
    });
  }, [onRefreshTransactions]));

  useBridgeEvent('wallet.balancesUpdated', useCallback(() => {
    if (!onRefreshBalances) return;
    Promise.resolve(onRefreshBalances()).catch((e) => {
      console.error('[useWalletSync] wallet.balancesUpdated handler failed:', e);
    });
  }, [onRefreshBalances]));

  // Sender-side commit is a projection refresh trigger only.
  useBridgeEvent('wallet.sendCommitted', useCallback(() => {
    Promise.resolve(onRefreshAll()).catch((e) => {
      console.error('[useWalletSync] wallet.sendCommitted refresh failed:', e);
    });
  }, [onRefreshAll]));

  // Identity lifecycle
  useBridgeEvent('identity.ready', useCallback(() => {
    Promise.resolve(onIdentityReady?.()).catch((e) => {
      console.error('[useWalletSync] identity.ready handler failed:', e);
    });
  }, [onIdentityReady]));
}
