// SPDX-License-Identifier: Apache-2.0

import { useSyncExternalStore } from 'react';
import type { ThemeName } from '../utils/theme';
import type { AppState } from '../types/app';

type StateUpdate<T> = T | ((prev: T) => T);

/**
 * How the wallet looks: the Game Boy device (`dgen`) or the Modern wallet
 * (`modern`). `null` until the wallet has read the choice, and while a new
 * wallet has not made one.
 */
export type Skin = 'modern' | 'dgen';
/** The Modern skin's colours. */
export type Scheme = 'light' | 'dark';
/** A switch the user sets: Simple mode, the offline appliance in it, email receipts. */
export type Switch = 'on' | 'off';

/** A look as the first-run picker shows it behind its box, before OK keeps it. */
export type Look = { skin: Skin; scheme: Scheme; simpleMode: Switch };

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
  /** Simple mode, in the Modern skin only: trading, storage and the Bitcoin bridge put away. */
  simpleMode: Switch;
  simpleOffline: Switch;
  receiptsEmail: Switch;
  /** The look the picker is previewing; `null` when no picker is open. */
  lookPreview: Look | null;
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
    simpleMode: 'off',
    simpleOffline: 'off',
    receiptsEmail: 'off',
    lookPreview: null,
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

  setSimpleMode = (simpleMode: Switch): void => {
    this.setState({ simpleMode });
  };

  setLookPreview = (lookPreview: Look | null): void => {
    this.setState({ lookPreview });
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
