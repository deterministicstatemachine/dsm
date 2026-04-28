// SPDX-License-Identifier: Apache-2.0

import type { AppState, ScreenType } from '../types/app';

type HomeStatusArgs = {
  appState: AppState;
  soundEnabled: boolean;
  error: string | null;
};

export function buildHomeMenuItems(appState: AppState, currentScreen: ScreenType): string[] {
  switch (appState) {
    case 'needs_genesis':
      return ['INITIALIZE'];
    case 'error':
      return ['RETRY CONNECTION', 'VIEW ERROR LOG'];
    case 'wallet_ready':
      if (currentScreen !== 'home') return ['BACK TO HOME'];
      return ['WALLET', 'TOKENS', 'LIQUIDITY', 'MAIL', 'CONTACTS', 'STORAGE', 'SETTINGS'];
    default:
      return [];
  }
}

export function buildHomeStatusLines({ appState, soundEnabled, error }: HomeStatusArgs): string[] {
  switch (appState) {
    case 'needs_genesis':
      return [
        'GENESIS: NOT INITIALIZED',
        'NETWORK: STANDBY',
        'DEVICE: VERIFIED',
        `SOUND: ${soundEnabled ? 'ON' : 'OFF'}`,
        'VERSION: 1.0.0',
      ];
    case 'wallet_ready':
      return [
        'GENESIS: INITIALIZED',
        'NETWORK: CONNECTED',
        'DEVICE: VERIFIED',
        `SOUND: ${soundEnabled ? 'ON' : 'OFF'}`,
        'VERSION: 1.0.0',
      ];
    case 'error':
      return [
        `ERROR: ${error ?? 'Unknown error'}`,
        'NETWORK: DISCONNECTED',
        'DEVICE: VERIFIED',
        `SOUND: ${soundEnabled ? 'ON' : 'OFF'}`,
        'VERSION: 1.0.0',
      ];
    default:
      return [];
  }
}
