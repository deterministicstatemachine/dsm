// SPDX-License-Identifier: Apache-2.0
/**
 * A connect code a link handed this wallet (DSM Amendment A11): a game on the
 * same phone opens the wallet with a `dsm:connect/v1:` link. The code waits
 * here for the Apps screen, which shows it for the player to read; Rust parses
 * it when they do. Nothing is fetched or trusted on the link's word.
 *
 * Any app or web page can open such a link, so the link comes with the app
 * Android recorded as having opened it (audit 2026-10-15, item 4): the Apps
 * screen says the code came from outside the wallet, and from which app.
 */
import { on } from './EventBridge';
import { navigationStore } from '../runtime/navigationStore';
import logger from '../utils/logger';

export type ConnectLink = {
  /** The link as it came: the code the player reads. */
  code: string;
  /** The package Android recorded as having opened the link; null when it named none. */
  sender: string | null;
};

let held: ConnectLink | null = null;
const listeners = new Set<() => void>();

/**
 * The `connect.link` host event's payload: UTF-8 "sender\nlink", the sender
 * empty when Android named none (MainActivity.deliverConnectLink). A package
 * name holds no newline, so the first one ends it.
 */
export function readConnectLink(payload: Uint8Array): ConnectLink {
  const text = new TextDecoder().decode(payload);
  const cut = text.indexOf('\n');
  if (cut < 0) throw new Error('connect.link: the payload names no sender line');
  const sender = text.slice(0, cut);
  const code = text.slice(cut + 1);
  if (code.length === 0) throw new Error('connect.link: the payload carries no link');
  return { code, sender: sender.length > 0 ? sender : null };
}

/** The link last handed over, once: whoever takes it shows it. */
export function takeConnectLink(): ConnectLink | null {
  const link = held;
  held = null;
  return link;
}

/** Called each time a link hands over a code. */
export function onConnectLink(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

on('connect.link', (payload) => {
  try {
    held = readConnectLink(payload);
  } catch (e: unknown) {
    logger.warn('[connect] a link was not taken:', e);
    return;
  }
  navigationStore.navigate('apps');
  listeners.forEach((listener) => listener());
});
