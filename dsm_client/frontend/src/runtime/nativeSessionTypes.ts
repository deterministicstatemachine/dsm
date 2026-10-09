// SPDX-License-Identifier: Apache-2.0

import type { AppState } from '../types/app';

export type NativeSessionIdentityStatus = 'runtime_not_ready' | 'missing' | 'ready';
export type NativeSessionEnvConfigStatus = 'loading' | 'ready' | 'error';
// `backup_phrase` is the frontend's own: the recovery phrase is on the screen
// before any wallet exists, so the native session never reports it.
export type NativeSessionPhase = Exclude<AppState, 'loading' | 'backup_phrase'>;
export type NativeSessionLockMethod = 'none' | 'pin' | 'combo';

/** The tries Rust's app lock reports (sdk::app_lock). */
export type NativeSessionLockTries = {
  /** Wrong PINs or patterns left before only the recovery phrase opens it. */
  misses_left: number;
  /** Only the recovery phrase opens it: the tries are used up, or nothing is enrolled. */
  phrase_required: boolean;
};

export type NativeSessionLockStatus = {
  enabled: boolean;
  locked: boolean;
  method: NativeSessionLockMethod;
  lock_on_pause: boolean;
  /** Null until Rust has reported them. */
  tries: NativeSessionLockTries | null;
};

export type NativeSessionBleHardwareStatus = {
  enabled: boolean;
  permissions_granted: boolean;
  scanning: boolean;
  advertising: boolean;
};

export type NativeSessionQrHardwareStatus = {
  available: boolean;
  active: boolean;
  camera_permission: boolean;
};

export type NativeSessionHardwareStatus = {
  app_foreground: boolean;
  ble: NativeSessionBleHardwareStatus;
  qr: NativeSessionQrHardwareStatus;
};

export type NativeSessionSnapshot = {
  received: boolean;
  phase: NativeSessionPhase;
  identity_status: NativeSessionIdentityStatus;
  env_config_status: NativeSessionEnvConfigStatus;
  lock_status: NativeSessionLockStatus;
  hardware_status: NativeSessionHardwareStatus;
  fatal_error: string | null;
  wallet_refresh_hint: number;
};

/** A snapshot as Rust sends it; the store adds that one has arrived. */
export type NativeSessionReport = Omit<NativeSessionSnapshot, 'received'>;

export const DEFAULT_NATIVE_SESSION: NativeSessionSnapshot = {
  received: false,
  phase: 'runtime_loading',
  identity_status: 'runtime_not_ready',
  env_config_status: 'loading',
  lock_status: {
    enabled: false,
    locked: false,
    method: 'none',
    lock_on_pause: true,
    tries: null,
  },
  hardware_status: {
    app_foreground: true,
    ble: {
      enabled: false,
      permissions_granted: false,
      scanning: false,
      advertising: false,
    },
    qr: {
      available: true,
      active: false,
      camera_permission: false,
    },
  },
  fatal_error: null,
  wallet_refresh_hint: 0,
};
