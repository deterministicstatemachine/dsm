import { bridgeEvents } from '../bridge/bridgeEvents';
import logger from '../utils/logger';
import {
  refreshPendingBilateralFromNative,
} from './pendingBilateralStore';

export interface PendingBilateralSyncOptions {
  /**
   * If true, status updates like ACCEPTED/REJECTED will keep the record but update status.
   * Completion (TRANSFER_COMPLETE) always removes.
   */
  keepNonTerminal?: boolean;
}

export function installPendingBilateralSync(_opts: PendingBilateralSyncOptions = {}): () => void {
  if (typeof window === 'undefined') return () => {};

  type PendingSyncWindow = Window & { __DSM_PENDING_BILATERAL_SYNC_INSTALLED__?: boolean };
  const syncWindow = window as PendingSyncWindow;
  if (syncWindow.__DSM_PENDING_BILATERAL_SYNC_INSTALLED__) return () => {};

  let inFlight = false;
  let pendingRefresh = false;
  const refresh = async (source: string) => {
    if (inFlight) {
      pendingRefresh = true;
      return;
    }
    inFlight = true;
    try {
      await refreshPendingBilateralFromNative();
    } catch (e) {
      logger.warn(`[PendingBilateralSync] refresh failed (${source}):`, e);
    } finally {
      inFlight = false;
      if (pendingRefresh) {
        pendingRefresh = false;
        void refresh('queued');
      }
    }
  };

  const handler = (event: Uint8Array) => {
    // Prior design: used to refresh memory store.
    // New design: PendingBilateralPanel handles its own sync strictly from bridge.
    // We log for debug but do NOT trigger store accumulation.
    logger.debug('[PendingBilateralSync] Event received, ignored by store (panel handles it):', event.length);
  };
  const onVisibilityChange = (detail: { state: DocumentVisibilityState }) => {
    if (detail?.state === 'visible') {
         // Same here - let the components handle foreground refresh directly.
         logger.debug('[PendingBilateralSync] App foreground, store sync skipped.');
    }
  };

  bridgeEvents.on('bilateral.event', handler);
  const offVisibility = bridgeEvents.on('visibility.change', onVisibilityChange);

  void refresh('install');
  syncWindow.__DSM_PENDING_BILATERAL_SYNC_INSTALLED__ = true;
  syncWindow.__DSM_PENDING_BILATERAL_STORE_SYNC__ = true;

  return () => {
    try { bridgeEvents.off('bilateral.event', handler); } catch {}
    try { offVisibility(); } catch {}
    try { delete syncWindow.__DSM_PENDING_BILATERAL_SYNC_INSTALLED__; } catch {}
    try { delete syncWindow.__DSM_PENDING_BILATERAL_STORE_SYNC__; } catch {}
  };
}
