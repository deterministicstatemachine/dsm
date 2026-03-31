// SPDX-License-Identifier: Apache-2.0

import type { AppState } from '../types/app';

export type NativeSessionIdentityStatus = 'runtime_not_ready' | 'missing' | 'ready';
export type NativeSessionEnvConfigStatus = 'loading' | 'ready' | 'error';
export type NativeSessionPhase = Exclude<AppState, 'loading'>;
export type NativeSessionLockMethod = 'none' | 'pin' | 'combo' | 'biometric';

export type NativeSessionLockStatus = {
  enabled: boolean;
  locked: boolean;
  method: NativeSessionLockMethod;
  lock_on_pause: boolean;
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

export function isNativeSessionSnapshot(value: unknown): value is NativeSessionSnapshot {
  if (!value || typeof value !== 'object') {
    return false;
  }
  const snapshot = value as Partial<NativeSessionSnapshot>;
  return (
    typeof snapshot.phase === 'string' &&
    typeof snapshot.identity_status === 'string' &&
    typeof snapshot.env_config_status === 'string' &&
    typeof snapshot.lock_status === 'object' &&
    typeof snapshot.hardware_status === 'object'
  );
}
