// SPDX-License-Identifier: Apache-2.0
//
// Guided tour state. Starting the tour switches the wallet into practice mode;
// ending it (finish, skip, or the wallet leaving the ready state) switches it
// back, reloads the real data and returns to the home menu.

import { useSyncExternalStore } from 'react';
import { dsmClient } from '../../services/dsmClient';
import { walletStore } from '../../stores/walletStore';
import { contactsStore } from '../../stores/contactsStore';
import { navigationStore } from '../../runtime/navigationStore';
import logger from '../../utils/logger';
import { practiceMode } from './practiceMode';
import { TOUR_STEPS } from './tourSteps';

export const TOUR_SEEN_PREF = 'ui_tour_seen';

export type TourSnapshot = {
  active: boolean;
  index: number;
};

function reloadStores(): void {
  void walletStore.refreshAll().catch((e: unknown) => logger.warn('tour: wallet reload failed', e));
  void contactsStore.refreshContacts().catch((e: unknown) => logger.warn('tour: contacts reload failed', e));
}

export async function markTourSeen(): Promise<void> {
  try {
    await dsmClient.setPreference(TOUR_SEEN_PREF, 'true');
  } catch (e) {
    logger.warn('tour: could not remember that the tour was seen', e);
  }
}

export async function hasSeenTour(): Promise<boolean> {
  try {
    return (await dsmClient.getPreference(TOUR_SEEN_PREF)) === 'true';
  } catch {
    // Without a readable preference, never nag.
    return true;
  }
}

class TourStore {
  private snapshot: TourSnapshot = { active: false, index: 0 };
  private listeners = new Set<() => void>();

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  getSnapshot = (): TourSnapshot => this.snapshot;

  private set(next: TourSnapshot): void {
    this.snapshot = next;
    this.listeners.forEach((listener) => listener());
  }

  start = (): void => {
    if (this.snapshot.active) return;
    practiceMode.enter();
    reloadStores();
    this.set({ active: true, index: 0 });
  };

  next = (): void => {
    if (!this.snapshot.active) return;
    const index = this.snapshot.index + 1;
    if (index >= TOUR_STEPS.length) {
      this.end();
      return;
    }
    this.set({ active: true, index });
  };

  back = (): void => {
    if (!this.snapshot.active || this.snapshot.index === 0) return;
    this.set({ active: true, index: this.snapshot.index - 1 });
  };

  end = (): void => {
    if (!this.snapshot.active) return;
    this.set({ active: false, index: 0 });
    practiceMode.leave();
    reloadStores();
    navigationStore.navigate('home');
    void markTourSeen();
  };
}

export const tourStore = new TourStore();

export function useTourStore(): TourSnapshot {
  return useSyncExternalStore(tourStore.subscribe, tourStore.getSnapshot, tourStore.getSnapshot);
}
