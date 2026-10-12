// SPDX-License-Identifier: Apache-2.0

import { useSyncExternalStore } from 'react';
import { SCREEN_TYPES, type AppState, type ScreenType } from '../types/app';
import logger from '../utils/logger';
import { appRuntimeStore } from './appRuntimeStore';

type NavigationSnapshot = {
  currentScreen: ScreenType;
  currentMenuIndex: number;
  history: ScreenType[];
};

type MenuIndexUpdate = number | ((prev: number) => number);

// The valid navigation targets: exactly the app's screens (`SCREEN_TYPES`,
// from which `ScreenType` is derived). `navigate` refuses anything else — a
// string from an untyped caller — and there is no second list to fall behind.
const VALID_NAV_TARGETS = new Set<ScreenType>(SCREEN_TYPES);

/**
 * The screens Simple mode puts away, in the Modern skin: trading (SoFi), the
 * Bitcoin bridge, storage nodes and the developer tools. Tokens, the faucet,
 * contacts and apps stay. While Simple mode is on nothing reaches them: no
 * menu offers them, and a call that names one, a deep link's included, is
 * refused here. The DGen Game Boy always reaches everything.
 */
export const SIMPLE_MODE_EXCLUDED = new Set<ScreenType>([
  'sofi',
  'vault',
  'storage',
  'dev_policy',
]);

/** Whether Simple mode is in force: the Modern skin, with Simple mode on. */
export function simpleModeOn(): boolean {
  const runtime = appRuntimeStore.getSnapshot();
  return runtime.skin === 'modern' && runtime.simpleMode === 'on';
}

/** Whether the look in use lets navigation reach `to`. */
export function reachable(to: ScreenType): boolean {
  return !simpleModeOn() || !SIMPLE_MODE_EXCLUDED.has(to);
}

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
    if (!reachable(to)) {
      logger.info(`[nav] ${to} is put away in Simple mode`);
      return;
    }
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
    if (!reachable(to)) return;
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
