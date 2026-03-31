// SPDX-License-Identifier: Apache-2.0

import { useSyncExternalStore } from 'react';
import { bridgeEvents } from '../bridge/bridgeEvents';
import {
  DEFAULT_NATIVE_SESSION,
  type NativeSessionSnapshot,
  isNativeSessionSnapshot,
} from './nativeSessionTypes';

class NativeSessionStore {
  private snapshot: NativeSessionSnapshot = DEFAULT_NATIVE_SESSION;
  private listeners = new Set<() => void>();

  constructor() {
    bridgeEvents.on('session.state', (next) => {
      if (!isNativeSessionSnapshot(next)) {
        return;
      }
      this.snapshot = {
        ...DEFAULT_NATIVE_SESSION,
        ...next,
        received: true,
      };
      this.emit();
    });
  }

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  getSnapshot = (): NativeSessionSnapshot => this.snapshot;

  getServerSnapshot = (): NativeSessionSnapshot => this.snapshot;

  setSnapshotForTest(next: NativeSessionSnapshot): void {
    this.snapshot = next;
    this.emit();
  }

  resetForTest(): void {
    this.snapshot = DEFAULT_NATIVE_SESSION;
    this.emit();
  }

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

export function setNativeSessionSnapshotForTest(next: NativeSessionSnapshot): void {
  nativeSessionStore.setSnapshotForTest(next);
}

export function resetNativeSessionStoreForTest(): void {
  nativeSessionStore.resetForTest();
}
