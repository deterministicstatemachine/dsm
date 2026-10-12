// SPDX-License-Identifier: Apache-2.0
/**
 * A connect code a link handed this wallet (DSM Amendment A11): a game on the
 * same phone opens the wallet with a `dsm:connect/v1:` link. The code waits
 * here for the Apps screen, which shows it for the player to read; Rust parses
 * it when they do. Nothing is fetched or trusted on the link's word.
 */
import { on } from './EventBridge';
import { navigationStore } from '../runtime/navigationStore';

let held: string | null = null;
const listeners = new Set<() => void>();

/** The code the last link handed over, once: whoever takes it shows it. */
export function takeConnectLink(): string | null {
  const code = held;
  held = null;
  return code;
}

/** Called each time a link hands over a code. */
export function onConnectLink(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

on('connect.link', (payload) => {
  held = new TextDecoder().decode(payload);
  navigationStore.navigate('apps');
  listeners.forEach((listener) => listener());
});
