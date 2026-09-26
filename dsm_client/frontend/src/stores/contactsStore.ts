/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import { useSyncExternalStore } from 'react';
import { dsmClient } from '../services/dsmClient';
import { bytesToDisplay } from '../contexts/contacts/utils';
import type { Contact, ContactsState } from '../contexts/ContactsContext';
import type { AddContactResult, BilateralRelationshipDTO, ContactCard } from '../dsm/types';
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

  private mapContacts(list: BilateralRelationshipDTO[]): Contact[] {
    return list.map((c) => {
      const deviceId = bytesToDisplay(c.deviceId);
      return {
        // A contact is its device: the alias is a label and can change.
        id: deviceId,
        alias: c.alias,
        genesisHash: bytesToDisplay(c.genesisHash),
        deviceId,
        publicKey: bytesToDisplay(c.publicKey),
        isVerified: c.genesisVerifiedOnline,
        bleAddress: c.bleAddress,
        chainTip: c.chainTip ? bytesToDisplay(c.chainTip) : undefined,
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
      // Rust's list as it stands: an address Rust no longer holds is not kept.
      const contacts = this.mapContacts(data.contacts);

      if (seq === this.refreshSeq) {
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

  /**
   * Adds the contact a card names under `alias` (empty: Rust names it by its
   * device) and answers what Rust answered.
   */
  addContact = async (alias: string, card: ContactCard): Promise<AddContactResult> => {
    this.setState({ isLoading: true, error: null });
    try {
      const result = await dsmClient.addContact({
        alias,
        deviceId: card.deviceId,
        genesisHash: card.genesisHash,
        signingPublicKey: card.signingPublicKey,
      });
      if (result.accepted) {
        await this.refreshContacts();
      } else {
        logger.error('ContactsStore: addContact refused:', result.error);
        this.setState({ error: result.error });
      }
      return result;
    } finally {
      this.setState({ isLoading: false });
    }
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
