// SPDX-License-Identifier: Apache-2.0

import { useSyncExternalStore } from 'react';
import type { ThemeName } from '../utils/theme';
import type { AppState } from '../types/app';

type StateUpdate<T> = T | ((prev: T) => T);

/**
 * How the wallet looks: the Game Boy device (`classic`) or the plain wallet
 * (`simple`). `null` until the wallet has read the choice, and while a new
 * wallet has not made one.
 */
export type Skin = 'simple' | 'classic';
/** The Simple skin's colours. */
export type Scheme = 'light' | 'dark';
/** A switch the user sets: the offline appliance in Simple, email receipts. */
export type Switch = 'on' | 'off';

type AppRuntimeSnapshot = {
  appState: AppState;
  error: string | null;
  securingProgress: number;
  showLockPrompt: boolean;
  soundEnabled: boolean;
  theme: ThemeName;
  skin: Skin | null;
  /** Whether the skin preferences were read for this identity: until then `skin` says nothing. */
  skinRead: 'read' | 'unread';
  scheme: Scheme;
  simpleOffline: Switch;
  receiptsEmail: Switch;
};

class AppRuntimeStore {
  private snapshot: AppRuntimeSnapshot = {
    appState: 'loading',
    error: null,
    securingProgress: 0,
    showLockPrompt: false,
    soundEnabled: true,
    theme: 'stateboy',
    skin: null,
    skinRead: 'unread',
    scheme: 'light',
    simpleOffline: 'off',
    receiptsEmail: 'off',
  };

  private listeners = new Set<() => void>();

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  getSnapshot = (): AppRuntimeSnapshot => this.snapshot;

  getServerSnapshot = (): AppRuntimeSnapshot => this.snapshot;

  setAppState = (appState: AppState): void => {
    this.setState({ appState });
  };

  setError = (error: string | null): void => {
    this.setState({ error });
  };

  setSecuringProgress = (securingProgress: number): void => {
    this.setState({ securingProgress });
  };

  setShowLockPrompt = (update: StateUpdate<boolean>): void => {
    this.setState({
      showLockPrompt: typeof update === 'function'
        ? update(this.snapshot.showLockPrompt)
        : update,
    });
  };

  setSoundEnabled = (update: StateUpdate<boolean>): void => {
    this.setState({
      soundEnabled: typeof update === 'function'
        ? update(this.snapshot.soundEnabled)
        : update,
    });
  };

  setTheme = (update: StateUpdate<ThemeName>): void => {
    this.setState({
      theme: typeof update === 'function'
        ? update(this.snapshot.theme)
        : update,
    });
  };

  setSkin = (skin: Skin | null): void => {
    this.setState({ skin });
  };

  setSkinRead = (skinRead: 'read' | 'unread'): void => {
    this.setState({ skinRead });
  };

  setScheme = (scheme: Scheme): void => {
    this.setState({ scheme });
  };

  setSimpleOffline = (simpleOffline: Switch): void => {
    this.setState({ simpleOffline });
  };

  setReceiptsEmail = (receiptsEmail: Switch): void => {
    this.setState({ receiptsEmail });
  };

  private setState(patch: Partial<AppRuntimeSnapshot>): void {
    this.snapshot = {
      ...this.snapshot,
      ...patch,
    };
    this.emit();
  }

  private emit(): void {
    this.listeners.forEach((listener) => listener());
  }
}

export const appRuntimeStore = new AppRuntimeStore();

export function useAppRuntimeStore(): AppRuntimeSnapshot {
  return useSyncExternalStore(
    appRuntimeStore.subscribe,
    appRuntimeStore.getSnapshot,
    appRuntimeStore.getServerSnapshot,
  );
}
