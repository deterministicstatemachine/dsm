// path: dsm_client/frontend/src/hooks/useWalletRefreshListener.ts
// SPDX-License-Identifier: Apache-2.0
// The one path from a `wallet.refresh` event to a screen's reload.
//
// Events are coalesced onto an animation frame, one reload runs at a time, and
// an event that arrives while a reload is running owes exactly one more reload
// after it — so every event is followed by a reload that started after it, and
// a burst of events costs at most two. There is no cooldown and no priority
// class. The previous "cooldown" counted dropped events rather than frames:
// after any reload the next 119 low-priority events were discarded outright,
// so screens grew direct subscriptions to the raw events to get around it and
// reloaded three to four times per event whenever the gate happened to be open.

import { useEffect } from 'react';
import { bridgeEvents } from '../bridge/bridgeEvents';

type RefreshFn = () => Promise<void> | void;

export function useWalletRefreshListener(refresh: RefreshFn, deps: unknown[] = []): void {
  useEffect(() => {
    let rafId: number | null = null;
    let running = false;
    let owed = false;
    let unmounted = false;

    const run = async () => {
      rafId = null;
      if (running) {
        owed = true;
        return;
      }
      running = true;
      try {
        await refresh();
      } catch (e) {
        console.error('[useWalletRefreshListener] refresh failed:', e);
      } finally {
        running = false;
      }
      if (owed && !unmounted) {
        owed = false;
        schedule();
      }
    };

    const schedule = () => {
      if (rafId !== null) return;
      rafId = requestAnimationFrame(() => {
        void run();
      });
    };

    const unsubscribe = bridgeEvents.on('wallet.refresh', schedule);
    return () => {
      unmounted = true;
      unsubscribe();
      if (rafId !== null) cancelAnimationFrame(rafId);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
}
