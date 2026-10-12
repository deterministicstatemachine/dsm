// SPDX-License-Identifier: Apache-2.0
// The photos the owner set for their contacts, kept on this phone as app
// preferences (one per contact, by device id), like the owner's own photo:
// a contact's code carries no picture. Read once per contact, then shared by
// every place the contact's avatar is drawn.

import { useEffect, useSyncExternalStore } from 'react';
import { dsmClient } from '../../services/dsmClient';
import logger from '../../utils/logger';

function key(deviceId: string): string {
  return `contact_photo_${deviceId}`;
}

type Held = { kind: 'reading' } | { kind: 'read'; photo: string | null };

class ContactPhotoStore {
  private held = new Map<string, Held>();
  private listeners = new Set<() => void>();
  private version = 0;

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  getVersion = (): number => this.version;

  /** The photo set for `deviceId`, or `null`: none set, or not read yet (reading starts). */
  photo(deviceId: string): string | null {
    const now = this.held.get(deviceId);
    return now !== undefined && now.kind === 'read' ? now.photo : null;
  }

  /** Reads the photo for `deviceId` once. */
  read(deviceId: string): void {
    if (deviceId.length === 0 || this.held.has(deviceId)) return;
    this.held.set(deviceId, { kind: 'reading' });
    dsmClient.getPreference(key(deviceId)).then(
      (value) => this.set(deviceId, value !== null && value.startsWith('data:image/') ? value : null),
      (e: unknown) => {
        logger.warn('[contacts] a contact photo was not read:', e);
        this.held.delete(deviceId);
      },
    );
  }

  /** Keeps (or, with `null`, removes) the photo for `deviceId`. */
  keep = async (deviceId: string, photo: string | null): Promise<void> => {
    await dsmClient.setPreference(key(deviceId), photo !== null ? photo : '');
    this.set(deviceId, photo);
  };

  private set(deviceId: string, photo: string | null): void {
    this.held.set(deviceId, { kind: 'read', photo });
    this.version += 1;
    this.listeners.forEach((l) => l());
  }
}

export const contactPhotoStore = new ContactPhotoStore();

/** The photo the owner set for a contact, or `null`; `deviceId` empty for a person who is not a contact yet. */
export function useContactPhoto(deviceId: string): string | null {
  useSyncExternalStore(contactPhotoStore.subscribe, contactPhotoStore.getVersion, contactPhotoStore.getVersion);
  useEffect(() => {
    contactPhotoStore.read(deviceId);
  }, [deviceId]);
  return contactPhotoStore.photo(deviceId);
}
