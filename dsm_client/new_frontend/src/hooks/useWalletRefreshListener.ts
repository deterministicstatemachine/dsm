/* eslint-disable @typescript-eslint/no-explicit-any */
// path: dsm_client/new_frontend/src/hooks/useWalletRefreshListener.ts
// SPDX-License-Identifier: Apache-2.0
// Event-driven wallet refresh listener with natural (RAF) smoothing.
// Coalesces rapid dsm-wallet-refresh events onto animation frames to
// avoid janky re-renders while keeping deterministic, event-driven updates.
// Applies a cooldown between refreshes to prevent BLE-envelope-triggered
// polling storms (~50 calls/sec → ~0.5 calls/sec).

import { useEffect } from 'react';
import { bridgeEvents } from '../bridge/bridgeEvents';

type RefreshFn = () => Promise<void> | void;

// Sources that should bypass cooldown and always trigger immediate refresh.
// These represent definitive state changes, not continuous BLE envelope streams.
const PRIORITY_SOURCES = new Set([
  'wallet.send',
  'bilateral.transfer_complete',
  'bilateral_transfer_complete',
  'reconcile.complete',
]);

export function useWalletRefreshListener(refresh: RefreshFn, deps: unknown[] = []): void {
  useEffect(() => {
    let rafId: number | null = null;
    let pending = false;
    let running = false;
    // Cooldown: skip low-priority refresh calls for COOLDOWN_FRAMES
    // animation frames after a refresh completes. At 60fps this is
    // ~2 seconds. Prevents BLE-envelope-driven polling storms while
    // keeping the UI responsive to definitive state changes.
    const COOLDOWN_FRAMES = 120;
    let cooldownRemaining = 0;
    let priorityQueued = false;

    const schedule = (priority: boolean) => {
      if (priority) priorityQueued = true;
      if (pending) return;
      pending = true;
      rafId = requestAnimationFrame(async () => {
        pending = false;
        const isPriority = priorityQueued;
        priorityQueued = false;

        // If a refresh is still running, queue another frame to ensure
        // the latest event is honored without overlapping network calls.
        if (running) {
          schedule(isPriority);
          return;
        }

        // Cooldown: skip non-priority refreshes to avoid flooding
        // the bridge with balance+history queries. Priority events bypass.
        // Schedule a tail refresh so the final event during cooldown is
        // eventually honored once the cooldown expires.
        if (!isPriority && cooldownRemaining > 0) {
          cooldownRemaining--;
          if (cooldownRemaining === 0) {
            // Cooldown just expired — schedule one more refresh
            schedule(false);
          }
          return;
        }

        running = true;
        try {
          await refresh();
        } catch (e) {
          try {
            console.error('[useWalletRefreshListener] refresh failed:', e);
          } catch {}
        } finally {
          running = false;
          cooldownRemaining = COOLDOWN_FRAMES;
        }
      });
    };

    const handler = (data: any) => {
      const source = typeof data?.source === 'string' ? data.source : '';
      const isPriority = PRIORITY_SOURCES.has(source);
      schedule(isPriority);
    };

    const unsubscribe = bridgeEvents.on('wallet.refresh', handler as any);

    return () => {
      unsubscribe();
      if (rafId !== null) cancelAnimationFrame(rafId);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
}
