// SPDX-License-Identifier: Apache-2.0

export type AppState = 'loading' | 'runtime_loading' | 'needs_genesis' | 'securing_device' | 'wallet_ready' | 'locked' | 'error';

export type ScreenType =
  | 'home'
  | 'wallet'
  | 'transactions'
  | 'contacts'
  | 'accounts'
  | 'storage'
  | 'settings'
  | 'tokens'
  | 'qr'
  | 'mycontact'
  | 'dev_dlv'
  | 'dev_cdbrw'
  | 'dev_policy'
  | 'dev_detfi_launch'
  | 'defi'
  | 'liquidity'
  | 'mail'
  | 'bluetooth'
  | 'vault'
  | 'lock_setup'
  | 'recovery'
  | 'nfc_recovery'
  | 'recovery_pipeline';
