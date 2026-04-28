// SPDX-License-Identifier: Apache-2.0

import { useSyncExternalStore } from 'react';
import type { AppState, ScreenType } from '../types/app';
import logger from '../utils/logger';

type NavigationSnapshot = {
  currentScreen: ScreenType;
  currentMenuIndex: number;
  history: ScreenType[];
};

type MenuIndexUpdate = number | ((prev: number) => number);

// Allowlist of valid navigation targets.  Every entry MUST also be
// routed by `AppScreenRouter.tsx` and present in the `ScreenType`
// union in `types/app.ts`.  Adding a screen anywhere else without
// updating this set causes silent navigation drops (the `navigate`
// early-returns when `to` is not in the set).
const VALID_NAV_TARGETS = new Set<ScreenType>([
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
  'dev_dlv',
  'dev_cdbrw',
  'dev_policy',
  'dev_detfi_launch',
  'defi',
  'liquidity',
  'mail',
  'lock_setup',
  'recovery',
  'nfc_recovery',
  'recovery_pipeline',
  'vault',
  'bluetooth',
]);

class NavigationStore {
  private snapshot: NavigationSnapshot = {
    currentScreen: 'home',
    currentMenuIndex: 0,
    history: [],
  };

  private listeners = new Set<() => void>();

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  getSnapshot = (): NavigationSnapshot => this.snapshot;

  getServerSnapshot = (): NavigationSnapshot => this.snapshot;

  navigate = (to: ScreenType): void => {
    if (!VALID_NAV_TARGETS.has(to)) return;
    if (this.snapshot.currentScreen === to) return;
    this.snapshot = {
      currentScreen: to,
      currentMenuIndex: 0,
      history: [...this.snapshot.history, this.snapshot.currentScreen],
    };
    this.emit();
  };

  setCurrentScreen = (to: ScreenType): void => {
    if (!VALID_NAV_TARGETS.has(to)) return;
    if (this.snapshot.currentScreen === to) return;
    this.snapshot = {
      ...this.snapshot,
      currentScreen: to,
      currentMenuIndex: 0,
    };
    this.emit();
  };

  setCurrentMenuIndex = (update: MenuIndexUpdate): void => {
    const nextIndex = typeof update === 'function'
      ? update(this.snapshot.currentMenuIndex)
      : update;
    if (nextIndex === this.snapshot.currentMenuIndex) return;
    this.snapshot = {
      ...this.snapshot,
      currentMenuIndex: nextIndex,
    };
    this.emit();
  };

  resetMenuIndex = (): void => {
    if (this.snapshot.currentMenuIndex === 0) return;
    this.snapshot = {
      ...this.snapshot,
      currentMenuIndex: 0,
    };
    this.emit();
  };

  goBack = (appState: AppState): void => {
    if (this.snapshot.history.length > 0) {
      const history = this.snapshot.history.slice();
      const previous = history.pop() as ScreenType;
      this.snapshot = {
        currentScreen: previous,
        currentMenuIndex: 0,
        history,
      };
      this.emit();
      return;
    }

    if (this.snapshot.currentScreen !== 'home') {
      this.snapshot = {
        ...this.snapshot,
        currentScreen: 'home',
        currentMenuIndex: 0,
      };
      this.emit();
      return;
    }

    if (appState === 'wallet_ready') {
      logger.debug('Back navigation (no-op at home)');
    }
  };

  installGlobalNavigate = (): (() => void) => {
    const win = window as Window & { dsmNavigate?: (to: string) => void };
    win.dsmNavigate = (to: string) => {
      if (VALID_NAV_TARGETS.has(to as ScreenType)) {
        this.navigate(to as ScreenType);
      }
    };

    return () => {
      try {
        delete win.dsmNavigate;
      } catch {}
    };
  };

  private emit(): void {
    this.listeners.forEach((listener) => listener());
  }
}

export const navigationStore = new NavigationStore();

export function useNavigationStore(): NavigationSnapshot {
  return useSyncExternalStore(
    navigationStore.subscribe,
    navigationStore.getSnapshot,
    navigationStore.getServerSnapshot,
  );
}
