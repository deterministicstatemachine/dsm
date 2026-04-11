// SPDX-License-Identifier: Apache-2.0
/**
 * useLockState — presentation-only lock/unlock intents via appRouter.
 * Native session drives lock state; this hook provides UI triggers only.
 */

import { useEffect, useRef, useCallback } from 'react';
import type { AppState } from '../types/app';
import { LOCK_SETUP_COMPLETE_EVENT } from '../services/lock/lockService';
import { lockSessionViaRouter, unlockSessionViaRouter } from '../dsm/WebViewBridge';

interface Args {
  appState: AppState;
}

export function useLockState({ appState }: Args) {
  const lock = useCallback(() => {
    if (appState !== 'wallet_ready') return;
    void lockSessionViaRouter().catch(() => {});
  }, [appState]);

  // Always-current ref so event handlers fired asynchronously get the live callback.
  const lockRef = useRef(lock);
  lockRef.current = lock;

  const unlock = useCallback(() => {
    return unlockSessionViaRouter().catch(() => {});
  }, []);

  // Lock immediately when a new lock is saved — fires after the LockSetupScreen
  // "done" animation finishes so the user lands on the lock screen and can verify
  // their PIN / combo works right away.
  useEffect(() => {
    const lockDelayRef: { id: ReturnType<typeof setTimeout> | undefined } = { id: undefined };
    const handle = () => {
      lockDelayRef.id = setTimeout(() => lockRef.current(), 1300);
    };
    window.addEventListener(LOCK_SETUP_COMPLETE_EVENT, handle);
    return () => {
      window.removeEventListener(LOCK_SETUP_COMPLETE_EVENT, handle);
      clearTimeout(lockDelayRef.id);
    };
  // lockRef is a stable ref object — no deps needed
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return { lock, unlock };
}
