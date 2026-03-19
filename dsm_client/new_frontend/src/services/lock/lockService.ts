// SPDX-License-Identifier: Apache-2.0
/**
 * lockService — SHA-256 hashing and preference wrappers for wallet lock.
 * All crypto uses the native Web Crypto API (no bundle cost).
 */

import { configureLockViaRouter } from '../../dsm/WebViewBridge';
import { dsmClient } from '../dsmClient';

// ---- Preference keys -------------------------------------------------------

export const LOCK_KEYS = {
  ENABLED: 'lock_enabled',          // 'true' | 'false'
  METHOD: 'lock_method',            // 'pin' | 'combo' | 'biometric'
  PIN_HASH: 'lock_pin_hash',        // "<hex_salt>$<hex_pbkdf2>" (legacy: plain hex sha256)
  COMBO_HASH: 'lock_combo_hash',    // "<hex_salt>$<hex_pbkdf2>" (legacy: plain hex sha256)
  TIMEOUT_MS: 'lock_timeout_ms',    // number as string, 0 = disabled
  LOCK_ON_PAUSE: 'lock_on_pause',   // 'true' | 'false' (default true)
  PROMPT_DISMISSED: 'lock_prompt_dismissed', // 'true' once user said "NEVER ASK"
  FAILED_ATTEMPTS: 'lock_failed_attempts',   // integer string, persisted across restarts
  LOCKED_UNTIL: 'lock_locked_until',         // epoch-ms string (display only, not in protocol)
} as const;

export const LOCK_PREFS_CHANGED_EVENT = 'dsm-lock-prefs-changed';
/** Fired after a new lock is saved with enabled:true — useLockState immediately locks the app. */
export const LOCK_SETUP_COMPLETE_EVENT = 'dsm-lock-setup-complete';

export type LockMethod = 'pin' | 'combo' | 'biometric';

export interface LockPrefs {
  enabled: boolean;
  method: LockMethod;
  pinHash: string;
  comboHash: string;
  timeoutMs: number;
  lockOnPause: boolean;
  promptDismissed: boolean;
}

function dispatchLockPrefsChanged(prefs: LockPrefs): void {
  if (typeof window === 'undefined') return;
  window.dispatchEvent(new CustomEvent<LockPrefs>(LOCK_PREFS_CHANGED_EVENT, { detail: prefs }));
  if (prefs.enabled) {
    window.dispatchEvent(new CustomEvent(LOCK_SETUP_COMPLETE_EVENT));
  }
}

// ---- Crypto helpers --------------------------------------------------------

const PBKDF2_ITERATIONS = 120_000; // ~300ms on mid-range Android; ~800ms brute-force cost per guess on a desktop GPU
const PBKDF2_SALT_LEN   = 16;      // 16 random bytes = 128-bit salt

/** Legacy fast-hash — kept only for migrating old stored values. */
async function sha256hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) out[i >> 1] = parseInt(hex.slice(i, i + 2), 16);
  return out;
}

/** Constant-time byte comparison — prevents timing side-channels. */
function safeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function pbkdf2Derive(input: string, salt: Uint8Array): Promise<Uint8Array> {
  const keyMat = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(input), { name: 'PBKDF2' }, false, ['deriveBits'],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: salt as Uint8Array<ArrayBuffer>, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMat, 256,
  );
  return new Uint8Array(bits);
}

/**
 * Hash a PIN for storage. Stored format: "<hex_salt>$<hex_derived>".
 * PBKDF2-SHA-256, 120k iterations, 16-byte random salt per enrollment.
 */
export async function hashPin(pin: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(PBKDF2_SALT_LEN));
  const derived = await pbkdf2Derive(`dsm-pin:${pin}`, salt);
  return `${toHex(salt)}$${toHex(derived)}`;
}

/** Hash a button combo for storage. Same format as hashPin. */
export async function hashCombo(buttons: string[]): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(PBKDF2_SALT_LEN));
  const derived = await pbkdf2Derive(`dsm-combo:${buttons.join(',')}`, salt);
  return `${toHex(salt)}$${toHex(derived)}`;
}

/**
 * Verify a PIN against a stored hash.
 * Handles both new PBKDF2 format ("<salt>$<key>") and legacy plain SHA-256.
 */
export async function verifyPin(input: string, stored: string): Promise<boolean> {
  if (!stored) return false;
  const parts = stored.split('$');
  if (parts.length === 2) {
    const salt    = fromHex(parts[0]);
    const expected = fromHex(parts[1]);
    const actual   = await pbkdf2Derive(`dsm-pin:${input}`, salt);
    return safeEqual(actual, expected);
  }
  // Legacy: plain SHA-256 (auto-upgrades on next save)
  const h = await sha256hex(`dsm-pin:${input}`);
  return h === stored;
}

/**
 * Verify a button combo against a stored hash.
 * Handles PBKDF2 format and legacy plain SHA-256.
 */
export async function verifyCombo(input: string[], stored: string): Promise<boolean> {
  if (!stored) return false;
  const parts = stored.split('$');
  if (parts.length === 2) {
    const salt     = fromHex(parts[0]);
    const expected = fromHex(parts[1]);
    const actual   = await pbkdf2Derive(`dsm-combo:${input.join(',')}`, salt);
    return safeEqual(actual, expected);
  }
  // Legacy: plain SHA-256 (auto-upgrades on next save)
  const h = await sha256hex(`dsm-combo:${input.join(',')}`);
  return h === stored;
}

// ---- Persisted failed-attempt tracking ------------------------------------
// Stored in preferences so the cooldown survives app restarts, preventing
// unlimited brute-force by killing and relaunching the app.

export const LOCK_MAX_ATTEMPTS  = 3;
export const LOCK_COOLDOWN_MS   = 30_000; // 30s

export async function getFailedAttemptState(): Promise<{ count: number; lockedUntilMs: number }> {
  const [countStr, untilStr] = await Promise.all([
    dsmClient.getPreference(LOCK_KEYS.FAILED_ATTEMPTS).catch(() => null),
    dsmClient.getPreference(LOCK_KEYS.LOCKED_UNTIL).catch(() => null),
  ]);
  return {
    count:         countStr ? parseInt(countStr, 10) : 0,
    lockedUntilMs: untilStr ? parseInt(untilStr, 10) : 0,
  };
}

export async function recordFailedAttempt(): Promise<{ count: number; lockedUntilMs: number }> {
  const { count } = await getFailedAttemptState();
  const next = count + 1;
  const lockedUntilMs = next >= LOCK_MAX_ATTEMPTS ? Date.now() + LOCK_COOLDOWN_MS : 0;
  await Promise.all([
    dsmClient.setPreference(LOCK_KEYS.FAILED_ATTEMPTS, String(next)),
    dsmClient.setPreference(LOCK_KEYS.LOCKED_UNTIL, String(lockedUntilMs)),
  ]);
  return { count: next, lockedUntilMs };
}

export async function clearFailedAttempts(): Promise<void> {
  await Promise.all([
    dsmClient.setPreference(LOCK_KEYS.FAILED_ATTEMPTS, '0'),
    dsmClient.setPreference(LOCK_KEYS.LOCKED_UNTIL, '0'),
  ]);
}

// ---- Preference read/write -------------------------------------------------

// Module-level cache so concurrent callers on startup share one in-flight
// request instead of each firing 6 parallel prefs.get RPCs.
let _lockPrefsCachePromise: Promise<LockPrefs> | null = null;

function _fetchLockPrefs(): Promise<LockPrefs> {
  return Promise.all([
    dsmClient.getPreference(LOCK_KEYS.ENABLED).catch(() => null),
    dsmClient.getPreference(LOCK_KEYS.METHOD).catch(() => null),
    dsmClient.getPreference(LOCK_KEYS.PIN_HASH).catch(() => null),
    dsmClient.getPreference(LOCK_KEYS.COMBO_HASH).catch(() => null),
    dsmClient.getPreference(LOCK_KEYS.TIMEOUT_MS).catch(() => null),
    dsmClient.getPreference(LOCK_KEYS.LOCK_ON_PAUSE).catch(() => null),
    dsmClient.getPreference(LOCK_KEYS.PROMPT_DISMISSED).catch(() => null),
  ]).then(([enabled, method, pinHash, comboHash, timeoutMs, lockOnPause, promptDismissed]) => ({
    enabled: enabled === 'true',
    method: (method as LockMethod) || 'pin',
    pinHash: pinHash || '',
    comboHash: comboHash || '',
    timeoutMs: timeoutMs ? parseInt(timeoutMs, 10) : 5 * 60 * 1000, // default 5 min
    lockOnPause: lockOnPause !== 'false',
    promptDismissed: promptDismissed === 'true',
  }));
}

export function getLockPrefs(): Promise<LockPrefs> {
  if (!_lockPrefsCachePromise) {
    _lockPrefsCachePromise = _fetchLockPrefs().catch((err) => {
      // Clear on failure so the next caller retries rather than getting a
      // permanently rejected promise.
      _lockPrefsCachePromise = null;
      throw err;
    });
  }
  return _lockPrefsCachePromise;
}

export async function saveLockPrefs(prefs: Partial<LockPrefs>): Promise<void> {
  // Invalidate the read cache so the next getLockPrefs() call fetches fresh data.
  _lockPrefsCachePromise = null;
  const tasks: Promise<void>[] = [];
  if (prefs.enabled !== undefined)
    tasks.push(dsmClient.setPreference(LOCK_KEYS.ENABLED, String(prefs.enabled)));
  if (prefs.method !== undefined)
    tasks.push(dsmClient.setPreference(LOCK_KEYS.METHOD, prefs.method));
  if (prefs.pinHash !== undefined)
    tasks.push(dsmClient.setPreference(LOCK_KEYS.PIN_HASH, prefs.pinHash));
  if (prefs.comboHash !== undefined)
    tasks.push(dsmClient.setPreference(LOCK_KEYS.COMBO_HASH, prefs.comboHash));
  if (prefs.timeoutMs !== undefined)
    tasks.push(dsmClient.setPreference(LOCK_KEYS.TIMEOUT_MS, String(prefs.timeoutMs)));
  if (prefs.lockOnPause !== undefined)
    tasks.push(dsmClient.setPreference(LOCK_KEYS.LOCK_ON_PAUSE, String(prefs.lockOnPause)));
  if (prefs.promptDismissed !== undefined)
    tasks.push(dsmClient.setPreference(LOCK_KEYS.PROMPT_DISMISSED, String(prefs.promptDismissed)));
  await Promise.all(tasks);
  const mergedPrefs = await getLockPrefs();
  await configureLockViaRouter({
    enabled: mergedPrefs.enabled,
    method: mergedPrefs.method,
    lockOnPause: mergedPrefs.lockOnPause,
  });
  dispatchLockPrefsChanged(mergedPrefs);
}

export async function disableLock(): Promise<void> {
  await saveLockPrefs({
    enabled: false,
    pinHash: '',
    comboHash: '',
  });
}
