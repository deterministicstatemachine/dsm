/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import { useSyncExternalStore } from 'react';
import { dsmClient } from '../services/dsmClient';
import { parseBinary32, parseBinary64, bytesToDisplay } from '../contexts/contacts/utils';
import type { Contact, ContactsState } from '../contexts/ContactsContext';
import logger from '../utils/logger';


async function awaitWithFrameBudget<T>(promise: Promise<T>, maxFrames = 360): Promise<T> {
  let settled = false;

  const wrapped = promise.then((value) => {
    settled = true;
    return value;
  });

  const watchdog = new Promise<never>((_, reject) => {
    let frames = 0;
    const tick = () => {
      if (settled) return;
      frames += 1;
      if (frames >= maxFrames) {
        reject(new Error('contacts refresh stalled'));
        return;
      }
      requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  });

  return Promise.race([wrapped, watchdog]);
}

const initialState: ContactsState = {
  contacts: [],
  isLoading: false,
  error: null,
};

class ContactsStore {
  private snapshot: ContactsState = initialState;

  private listeners = new Set<() => void>();

  private refreshSeq = 0;

  private refreshPending = false;

  private hasLoadedOnce = false;

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  getSnapshot = (): ContactsState => this.snapshot;

  getServerSnapshot = (): ContactsState => this.snapshot;

  setError = (error: string | null): void => {
    this.setState({ error });
  };

  clearContacts = (): void => {
    this.setState({ contacts: [] });
  };

  private setState(patch: Partial<ContactsState>): void {
    this.snapshot = {
      ...this.snapshot,
      ...patch,
    };
    this.emit();
  }

  private mapContacts(list: any[]): Contact[] {
    return list.map((contact: any) => {
      // Strict proto field names — camelCase from @bufbuild/protobuf codegen.
      // If snake_case fields appear, log an error: the bridge returned raw data.
      if ('genesis_hash' in contact || 'device_id' in contact || 'ble_address' in contact) {
        logger.error('[ContactsStore] snake_case fields detected — bridge returned raw data instead of protobuf');
      }

      const alias = String(contact.alias ?? 'Unknown');
      const genesisRaw = contact.genesisHash;
      const genesisHash = genesisRaw instanceof Uint8Array
        ? bytesToDisplay(genesisRaw)
        : String(genesisRaw ?? '');
      const deviceRaw = contact.deviceId;
      const deviceId = deviceRaw instanceof Uint8Array && deviceRaw.length > 0
        ? bytesToDisplay(deviceRaw)
        : (typeof deviceRaw === 'string' ? deviceRaw : '');
      const id = alias ? `${genesisHash}:${alias}` : genesisHash;

      const chainTipRaw = contact.chainTip?.v;
      const chainTip = chainTipRaw instanceof Uint8Array && chainTipRaw.length > 0
        ? bytesToDisplay(chainTipRaw)
        : undefined;

      const smtRaw = contact.chainTipSmtProof;
      const chainTipSmtProof = smtRaw?.siblings?.length
        ? { siblings: smtRaw.siblings as Uint8Array[] }
        : undefined;

      return {
        id,
        alias,
        genesisHash,
        deviceId: deviceId || undefined,
        publicKey: (() => {
          const signingKey = contact.signingPublicKey;
          if (typeof signingKey === 'string' && signingKey.length > 0) return signingKey;
          const rawKey = contact.publicKey;
          if (rawKey instanceof Uint8Array && rawKey.length > 0) return bytesToDisplay(rawKey);
          return undefined;
        })(),
        lastSeen: undefined,
        isVerified: contact.genesisVerifiedOnline === true,
        isFavorite: false,
        notes: undefined,
        bleAddress: contact.bleAddress || undefined,
        chainTip,
        addedCounter: contact.addedCounter,
        verifyCounter: contact.verifyCounter,
        chainTipSmtProof,
        createdAt: 0,
        updatedAt: 0,
      };
    });
  }

  refreshContacts = async (): Promise<void> => {
    const seq = ++this.refreshSeq;
    try {
      if (!this.hasLoadedOnce) {
        this.setState({ isLoading: true });
      }
      this.setState({ error: null });

      const data = await awaitWithFrameBudget(dsmClient.getContacts());
      const list = Array.isArray((data as any)?.contacts) ? (data as any).contacts : [];
      const mapped = this.mapContacts(list);

      if (seq === this.refreshSeq) {
        const previous = new Map(this.snapshot.contacts.map((contact) => [contact.id, contact]));
        const contacts = mapped.map((contact) => {
          if (!contact.bleAddress) {
            const existing = previous.get(contact.id);
            if (existing?.bleAddress) {
              return { ...contact, bleAddress: existing.bleAddress };
            }
          }
          return contact;
        });

        this.setState({ contacts });
        this.hasLoadedOnce = true;
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to refresh contacts';
      logger.error('ContactsStore: refreshContacts failed:', message);
      this.setState({ error: message });
    } finally {
      if (seq === this.refreshSeq) {
        this.setState({ isLoading: false });
      }
    }
  };

  scheduleRefreshContacts = (reason: string): void => {
    if (this.refreshPending) return;
    this.refreshPending = true;
    queueMicrotask(() => {
      this.refreshPending = false;
      logger.debug(`[ContactsStore] refresh scheduled: ${reason}`);
      void this.refreshContacts();
    });
  };

  handleBleMapped = (_detail: any): void => {
    // Rust is authoritative for contact↔BLE address mapping.
    // Refresh from Rust to get the canonical state — no optimistic mutation.
    this.scheduleRefreshContacts('bleMapped');
  };

  handleBleUpdated = (_detail: any): void => {
    // Rust is authoritative for contact↔BLE address mapping.
    // Refresh from Rust to get the canonical state — no optimistic mutation.
    this.scheduleRefreshContacts('bleUpdated');
  };

  addContact = async (
    alias: string,
    genesisHash: Uint8Array | string,
    deviceId: Uint8Array | string | undefined,
    signingPublicKey: Uint8Array | string | undefined,
  ): Promise<boolean> => {
    try {
      this.setState({ isLoading: true, error: null });

      if (!deviceId || deviceId.length < 1) {
        throw new Error('device_id required (must come from BLE identity)');
      }

      if (!signingPublicKey || signingPublicKey.length < 1) {
        throw new Error('signingPublicKey required (must come from contact QR)');
      }

      const result = await dsmClient.addContact({
        alias,
        genesisHash: parseBinary32(genesisHash, 'genesis_hash'),
        deviceId: parseBinary32(deviceId, 'device_id'),
        signingPublicKey: parseBinary64(signingPublicKey, 'signingPublicKey'),
      });

      if (!result?.accepted) {
        throw new Error(result?.error || 'Failed to add contact');
      }

      await this.refreshContacts();
      return true;
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to add contact';
      logger.error('ContactsStore: addContact failed:', message);
      this.setState({ error: message });
      return false;
    } finally {
      this.setState({ isLoading: false });
    }
  };

  updateContact = async (id: string, updates: Partial<Contact>): Promise<boolean> => {
    try {
      this.setState({ isLoading: true, error: null });

      const api = dsmClient as any;
      if (typeof api.updateContactStrict !== 'function') {
        throw new Error('updateContactStrict is not available on this build');
      }

      const result = await api.updateContactStrict({ id, ...updates });
      if (!result?.success) {
        throw new Error(result?.message || 'Failed to update contact');
      }

      await this.refreshContacts();
      return true;
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to update contact';
      logger.error('ContactsStore: updateContact failed:', message);
      this.setState({ error: message });
      return false;
    } finally {
      this.setState({ isLoading: false });
    }
  };

  deleteContact = async (id: string): Promise<boolean> => {
    try {
      this.setState({ isLoading: true, error: null });

      const api = dsmClient as any;
      if (typeof api.deleteContactStrict !== 'function') {
        throw new Error('deleteContactStrict is not available on this build');
      }

      const result = await api.deleteContactStrict({ id });
      if (!result?.success) {
        throw new Error(result?.message || 'Failed to delete contact');
      }

      await this.refreshContacts();
      return true;
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to delete contact';
      logger.error('ContactsStore: deleteContact failed:', message);
      this.setState({ error: message });
      return false;
    } finally {
      this.setState({ isLoading: false });
    }
  };

  getContactByGenesisHash = (genesisHash: string): Contact | null => {
    const target = String(genesisHash || '').trim().toLowerCase();
    return this.snapshot.contacts.find((contact) => contact.genesisHash.toLowerCase() === target) || null;
  };

  getContactByAlias = (alias: string): Contact | null => {
    return this.snapshot.contacts.find((contact) => contact.alias.toLowerCase() === alias.toLowerCase()) || null;
  };

  private emit(): void {
    this.listeners.forEach((listener) => listener());
  }
}

export const contactsStore = new ContactsStore();

export function useContactsStore(): ContactsState {
  return useSyncExternalStore(
    contactsStore.subscribe,
    contactsStore.getSnapshot,
    contactsStore.getServerSnapshot,
  );
}
