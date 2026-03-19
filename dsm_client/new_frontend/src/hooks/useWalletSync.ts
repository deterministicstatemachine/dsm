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
  onImmediateSenderUpdate?: (detail: {
    success?: boolean;
    tokenId?: string;
    newBalance?: bigint | string | number;
    transactionHash?: Uint8Array;
    toDeviceId?: Uint8Array;
    amount?: bigint | string | number;
  }) => void;
  onIdentityReady?: () => void | Promise<void>;
};

export function useWalletSync(handlers: WalletSyncHandlers) {
  const { onRefreshAll: _onRefreshAll, onRefreshBalances, onRefreshTransactions, onImmediateSenderUpdate, onIdentityReady } = handlers;

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

  // Immediate sender-side reflect after online send commit
  useBridgeEvent('wallet.sendCommitted', useCallback((detail) => {
    if (!onImmediateSenderUpdate) return;
    try { onImmediateSenderUpdate(detail as any); } catch (e) {
      console.error('[useWalletSync] wallet.sendCommitted handler failed:', e);
    }
  }, [onImmediateSenderUpdate]));

  // Identity lifecycle
  useBridgeEvent('identity.ready', useCallback(() => {
    Promise.resolve(onIdentityReady?.()).catch((e) => {
      console.error('[useWalletSync] identity.ready handler failed:', e);
    });
  }, [onIdentityReady]));
}
