/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import { useSyncExternalStore } from 'react';
import { bridgeEvents } from './bridgeEvents';

const counters: Record<string, number> = Object.create(null);
const listeners: Record<string, Set<() => void>> = Object.create(null);

function emit(name: string) {
  counters[name] = (counters[name] ?? 0) + 1;
  const set = listeners[name];
  if (set) {
    for (const l of set) l();
  }
}

function subscribe(name: string, onStoreChange: () => void) {
  if (!listeners[name]) listeners[name] = new Set();
  listeners[name].add(onStoreChange);
  const offBridge = bridgeEvents.on(name as any, () => emit(name));
  return () => {
    listeners[name].delete(onStoreChange);
    offBridge();
  };
}

function getSnapshot(name: string) {
  return counters[name] ?? 0;
}

export function useEventSignal(name: string) {
  return useSyncExternalStore(
    (onStoreChange) => subscribe(name, onStoreChange),
    () => getSnapshot(name)
  );
}
