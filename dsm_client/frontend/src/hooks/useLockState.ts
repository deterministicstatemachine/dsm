// SPDX-License-Identifier: Apache-2.0
/**
 * useLockState — the lock intent via appRouter. Rust's session drives the lock
 * state; opening it is the lock screen's, which sends what the user entered.
 */

import { useEffect, useRef, useCallback } from 'react';
import type { AppState } from '../types/app';
import { LOCK_SETUP_COMPLETE_EVENT } from '../services/lock/lockService';
import { lockSessionViaRouter } from '../dsm/WebViewBridge';
import logger from '../utils/logger';

interface Args {
  appState: AppState;
}

export function useLockState({ appState }: Args) {
  const lock = useCallback(() => {
    if (appState !== 'wallet_ready') return;
    lockSessionViaRouter().catch((e: unknown) => logger.warn('[useLockState] session.lock failed:', e));
  }, [appState]);

  // Always-current ref so event handlers fired asynchronously get the live callback.
  const lockRef = useRef(lock);
  lockRef.current = lock;

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

  return { lock };
}
