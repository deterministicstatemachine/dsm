// SPDX-License-Identifier: Apache-2.0
// Where the Simple skin is: one of its four tabs, or a page opened over one
// (Send, Receive, a contact, your card, …). Back closes the page.

import { useSyncExternalStore } from 'react';

export type SimpleTab = 'wallet' | 'people' | 'activity' | 'settings';

export type SimplePage =
  | { kind: 'tab' }
  /** Send, to a contact already chosen or not. */
  | { kind: 'send'; to: string | null }
  | { kind: 'receive' }
  | { kind: 'add_contact' }
  /** One contact, by device id (Base32). */
  | { kind: 'contact'; deviceId: string }
  | { kind: 'my_card' }
  | { kind: 'receipts' };

type Snapshot = { tab: SimpleTab; pages: SimplePage[] };

class SimpleNavStore {
  private snapshot: Snapshot = { tab: 'wallet', pages: [] };
  private listeners = new Set<() => void>();

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  getSnapshot = (): Snapshot => this.snapshot;

  /**
   * A tab, with no page over it. Pages left open are closed in the browser
   * history too, so the phone's back button has nothing stale to step through.
   */
  showTab = (tab: SimpleTab): void => {
    const open = this.snapshot.pages.length;
    this.set({ tab, pages: [] });
    if (open > 0) {
      this.ignorePops += 1;
      window.history.go(-open);
    }
  };

  /**
   * Opens a page over the tab. Each page is a browser history entry: the
   * phone's back button steps the WebView back, which closes the page.
   */
  open = (page: SimplePage): void => {
    window.history.pushState({ simplePage: this.snapshot.pages.length + 1 }, '');
    this.set({ tab: this.snapshot.tab, pages: [...this.snapshot.pages, page] });
  };

  /** Closes the page on top, as the phone's back button does. */
  back = (): void => {
    if (this.snapshot.pages.length === 0) return;
    window.history.back();
  };

  /** The browser stepped back: the page on top closes. */
  onPop = (): void => {
    if (this.ignorePops > 0) {
      this.ignorePops -= 1;
      return;
    }
    if (this.snapshot.pages.length === 0) return;
    this.set({ tab: this.snapshot.tab, pages: this.snapshot.pages.slice(0, -1) });
  };

  private ignorePops = 0;

  private set(next: Snapshot): void {
    this.snapshot = next;
    this.listeners.forEach((l) => l());
  }
}

export const simpleNav = new SimpleNavStore();

export function useSimpleNav(): Snapshot {
  return useSyncExternalStore(simpleNav.subscribe, simpleNav.getSnapshot, simpleNav.getSnapshot);
}

/** The page on top, or the tab itself. */
export function currentPage(s: Snapshot): SimplePage {
  return s.pages.length > 0 ? s.pages[s.pages.length - 1] : { kind: 'tab' };
}
