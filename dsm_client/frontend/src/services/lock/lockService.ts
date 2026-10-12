// SPDX-License-Identifier: Apache-2.0
/**
 * lockService — the lock prompt's one preference. The lock itself (what opens
 * it, its misses, whether it locks on leaving the app) is Rust's: see
 * dsm/WebViewBridge/sessionLock.ts and sdk::app_lock.
 */

import { dsmClient } from '../dsmClient';

export const LOCK_KEYS = {
  PROMPT_DISMISSED: 'lock_prompt_dismissed', // set once the user said "NEVER ASK"
} as const;

/** Fired after a new lock is turned on: useLockState locks the app, and the fx layer arms. */
export const LOCK_SETUP_COMPLETE_EVENT = 'dsm-lock-setup-complete';

export interface LockPrefs {
  promptDismissed: boolean;
}

export async function getLockPrefs(): Promise<LockPrefs> {
  const promptDismissed = await dsmClient.getPreference(LOCK_KEYS.PROMPT_DISMISSED);
  return {
    promptDismissed: promptDismissed === 'true',
  };
}

export async function saveLockPrefs(prefs: LockPrefs): Promise<void> {
  await dsmClient.setPreference(LOCK_KEYS.PROMPT_DISMISSED, String(prefs.promptDismissed));
}
