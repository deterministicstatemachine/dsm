// SPDX-License-Identifier: Apache-2.0

/**
 * `backup_phrase`: a new wallet's recovery phrase is on the screen for the user
 * to write down and check; the wallet is created from it after the check.
 */
export type AppState = 'loading' | 'runtime_loading' | 'needs_genesis' | 'backup_phrase' | 'securing_device' | 'publication_pending' | 'wallet_ready' | 'locked' | 'error';

/**
 * Every screen the app has, once. `ScreenType` is derived from this list and
 * the navigation store accepts exactly these targets, so a screen the router
 * renders can never be missing from what navigation allows: the TRADE brick
 * sat dead from #976 to here because the SoFi screen was added back to the
 * type and the router but not to a second, hand-kept allowlist.
 */
export const SCREEN_TYPES = [
  'home',
  'wallet',
  'transactions',
  'contacts',
  'accounts',
  'storage',
  'settings',
  'tokens',
  'qr',
  'mycontact',
  'dev_policy',
  'bluetooth',
  'vault',
  'lock_setup',
  'recovery',
  'nfc_recovery',
  'recovery_pipeline',
  'sofi',
  'apps',
] as const;

export type ScreenType = (typeof SCREEN_TYPES)[number];
