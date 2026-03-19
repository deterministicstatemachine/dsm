// SPDX-License-Identifier: Apache-2.0

import { useSyncExternalStore } from 'react';

type BridgeSessionSnapshot = {
  bridgeBound: boolean;
  bridgeReady: boolean;
  sessionConfirmed: boolean;
  sessionError: string | null;
};

class BridgeSessionStore {
  private snapshot: BridgeSessionSnapshot = {
    bridgeBound: false,
    bridgeReady: false,
    sessionConfirmed: false,
    sessionError: null,
  };

  private listeners = new Set<() => void>();

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  getSnapshot = (): BridgeSessionSnapshot => this.snapshot;

  getServerSnapshot = (): BridgeSessionSnapshot => this.snapshot;

  setBridgeBound = (bridgeBound: boolean): void => {
    this.setState({ bridgeBound });
  };

  markBridgeReady = (): void => {
    this.setState({ bridgeReady: true });
  };

  markSessionConfirmed = (): void => {
    this.setState({ sessionConfirmed: true, sessionError: null });
  };

  markSessionError = (sessionError: string): void => {
    this.setState({ sessionConfirmed: false, sessionError });
  };

  reset = (): void => {
    this.setState({
      bridgeBound: false,
      bridgeReady: false,
      sessionConfirmed: false,
      sessionError: null,
    });
  };

  private setState(patch: Partial<BridgeSessionSnapshot>): void {
    this.snapshot = {
      ...this.snapshot,
      ...patch,
    };
    this.listeners.forEach((listener) => listener());
  }
}

export const bridgeSessionStore = new BridgeSessionStore();

export function useBridgeSessionStore(): BridgeSessionSnapshot {
  return useSyncExternalStore(
    bridgeSessionStore.subscribe,
    bridgeSessionStore.getSnapshot,
    bridgeSessionStore.getServerSnapshot,
  );
}
