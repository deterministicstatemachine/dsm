// SPDX-License-Identifier: Apache-2.0
// The owner's own card as the Modern skin shows it: the name from the contact
// card (DSM Amendment A17, carried on the contact code), and the photo and
// banner the owner chose. The pictures are kept on this phone only, as app
// preferences: a contact code is a QR and cannot carry an image.

import { useSyncExternalStore } from 'react';
import { getOwnProfile } from '../../dsm/contacts';
import { dsmClient } from '../../services/dsmClient';

export const PROFILE_PHOTO_PREFERENCE = 'profile_photo';
export const PROFILE_BANNER_PREFERENCE = 'profile_banner';

export type OwnCard =
  | { kind: 'unread' }
  | { kind: 'read'; name: string; photo: string | null; banner: string | null }
  | { kind: 'failed'; message: string };

function picture(value: string | null): string | null {
  return value !== null && value.startsWith('data:image/') ? value : null;
}

class OwnCardStore {
  private snapshot: OwnCard = { kind: 'unread' };
  private listeners = new Set<() => void>();

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  getSnapshot = (): OwnCard => this.snapshot;

  /** Reads the card and the pictures again. */
  load = async (): Promise<void> => {
    try {
      const [profile, photo, banner] = await Promise.all([
        getOwnProfile(),
        dsmClient.getPreference(PROFILE_PHOTO_PREFERENCE),
        dsmClient.getPreference(PROFILE_BANNER_PREFERENCE),
      ]);
      this.set({ kind: 'read', name: profile !== null ? profile.name : '', photo: picture(photo), banner: picture(banner) });
    } catch (e: unknown) {
      this.set({ kind: 'failed', message: e instanceof Error ? e.message : String(e) });
    }
  };

  /** The name after the card is saved. */
  setName = (name: string): void => {
    const now = this.snapshot;
    this.set(now.kind === 'read' ? { ...now, name } : { kind: 'read', name, photo: null, banner: null });
  };

  /** Keeps (or, with `null`, removes) the photo or the banner. */
  setPicture = async (which: 'photo' | 'banner', value: string | null): Promise<void> => {
    await dsmClient.setPreference(which === 'photo' ? PROFILE_PHOTO_PREFERENCE : PROFILE_BANNER_PREFERENCE, value !== null ? value : '');
    const now = this.snapshot;
    const base = now.kind === 'read' ? now : { kind: 'read' as const, name: '', photo: null, banner: null };
    this.set(which === 'photo' ? { ...base, photo: value } : { ...base, banner: value });
  };

  private set(next: OwnCard): void {
    this.snapshot = next;
    this.listeners.forEach((l) => l());
  }
}

export const ownCardStore = new OwnCardStore();

export function useOwnCard(): OwnCard {
  return useSyncExternalStore(ownCardStore.subscribe, ownCardStore.getSnapshot, ownCardStore.getSnapshot);
}
