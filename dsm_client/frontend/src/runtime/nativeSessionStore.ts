// SPDX-License-Identifier: Apache-2.0

import { useSyncExternalStore } from 'react';
import { bridgeEvents } from '../bridge/bridgeEvents';
import { DEFAULT_NATIVE_SESSION, type NativeSessionSnapshot } from './nativeSessionTypes';

class NativeSessionStore {
  private snapshot: NativeSessionSnapshot = DEFAULT_NATIVE_SESSION;
  private listeners = new Set<() => void>();

  constructor() {
    // The bus carries whole snapshots (decodeSessionState refuses a partial
    // one); the store adds only its own fact, that one arrived.
    bridgeEvents.on('session.state', (next) => {
      this.snapshot = { ...next, received: true };
      this.emit();
    });
  }

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  getSnapshot = (): NativeSessionSnapshot => this.snapshot;

  getServerSnapshot = (): NativeSessionSnapshot => this.snapshot;

  private emit(): void {
    this.listeners.forEach((listener) => listener());
  }
}

export const nativeSessionStore = new NativeSessionStore();

export function useNativeSessionStore(): NativeSessionSnapshot {
  return useSyncExternalStore(
    nativeSessionStore.subscribe,
    nativeSessionStore.getSnapshot,
    nativeSessionStore.getServerSnapshot,
  );
}
