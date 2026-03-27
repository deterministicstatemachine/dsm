/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/contexts/ContactsContext.tsx
// SPDX-License-Identifier: Apache-2.0
import React, { createContext, useContext, useEffect, useMemo, useRef } from 'react';
import { useBridgeEvent } from '@/hooks/useBridgeEvents';
import { hasIdentity } from '../utils/identity';
import { contactsStore, useContactsStore } from '../stores/contactsStore';
import {
  setBleIdentityForAdvertising,
  startBleAdvertisingViaRouter,
} from '../dsm/WebViewBridge';
import { getHeaders } from '../dsm/identity';

export interface Contact {
  id: string;
  alias: string;
  genesisHash: string;
  deviceId?: string;
  publicKey?: string;
  lastSeen?: number;
  isVerified: boolean;
  isFavorite?: boolean;
  notes?: string;
  bleAddress?: string;
  chainTip?: string;
  addedCounter?: number;
  verifyCounter?: number;
  chainTipSmtProof?: { siblings: Uint8Array[] };
  createdAt: number;
  updatedAt: number;
}

export interface ContactsState {
  contacts: Contact[];
  isLoading: boolean;
  error: string | null;
}

export interface ContactsContextValue extends ContactsState {
  refreshContacts: () => Promise<void>;
  addContact: (alias: string, genesisHash: Uint8Array | string, deviceId: Uint8Array | string | undefined, signingPublicKey: Uint8Array | string | undefined) => Promise<boolean>;
  updateContact: (id: string, updates: Partial<Contact>) => Promise<boolean>;
  deleteContact: (id: string) => Promise<boolean>;
  getContactByGenesisHash: (genesisHash: string) => Contact | null;
  getContactByAlias: (alias: string) => Contact | null;
  setError: (error: string | null) => void;
}

const defaultValue: ContactsContextValue = {
  contacts: [],
  isLoading: false,
  error: null,
  refreshContacts: async () => {},
  addContact: async () => false,
  updateContact: async () => false,
  deleteContact: async () => false,
  getContactByGenesisHash: () => null,
  getContactByAlias: () => null,
  setError: () => {},
};

export const ContactsContext = createContext<ContactsContextValue>(defaultValue);

/**
 * Ensure BLE advertising is active so peers can initiate bilateral transfers.
 * Called after identity.ready and whenever a new BLE contact is mapped.
 */
async function ensureBleAdvertisingIfContacts(): Promise<void> {
  try {
    const contacts = contactsStore.getSnapshot().contacts;
    const hasBleContacts = contacts.some((c: any) => c.bleAddress);
    if (!hasBleContacts) return;

    // §2.3-2.4: Device is bound to genesis via DevID ∈ R_G.
    // Fetch the real genesis hash — never advertise all-zeros.
    const headers = await getHeaders();
    const devId = headers.deviceId;
    const genesisHash = headers.genesisHash;
    if (!devId || devId.length !== 32) return;
    if (!genesisHash || genesisHash.length !== 32) return;

    await setBleIdentityForAdvertising(new Uint8Array(genesisHash), new Uint8Array(devId));
    await startBleAdvertisingViaRouter();
  } catch {
    // Best-effort — don't block contacts flow if BLE advertising fails
  }
}

export function ContactsProvider({ children }: { children: React.ReactNode }) {
  const state = useContactsStore();
  const bleAdvertisingStarted = useRef(false);

  useBridgeEvent('contact.bleMapped', (detail) => {
    contactsStore.handleBleMapped(detail);
    // New BLE contact — ensure we're advertising
    if (!bleAdvertisingStarted.current) {
      bleAdvertisingStarted.current = true;
      void ensureBleAdvertisingIfContacts();
    }
  }, []);
  useBridgeEvent('contact.bleUpdated', contactsStore.handleBleUpdated, []);
  useBridgeEvent('contact.added', () => {
    void contactsStore.refreshContacts();
  }, []);
  useBridgeEvent('contact.reconcileNeeded', () => {
    void contactsStore.refreshContacts();
  }, []);
  useBridgeEvent('identity.ready', () => {
    // After identity is ready, refresh contacts then start advertising
    // so peers can discover us for bilateral transfers.
    void contactsStore.refreshContacts().then(() => {
      void ensureBleAdvertisingIfContacts();
    });
  }, []);

  useEffect(() => {
    let mounted = true;

    void (async () => {
      try {
        const ok = await hasIdentity();
        if (!mounted) return;
        if (ok) {
          await contactsStore.refreshContacts();
        } else {
          contactsStore.clearContacts();
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.warn('[ContactsProvider] hasIdentity failed:', message);
        if (mounted) {
          contactsStore.clearContacts();
        }
      }
    })();

    return () => {
      mounted = false;
    };
  }, []);

  const value = useMemo<ContactsContextValue>(() => ({
    contacts: state.contacts,
    isLoading: state.isLoading,
    error: state.error,
    refreshContacts: contactsStore.refreshContacts,
    addContact: contactsStore.addContact,
    updateContact: contactsStore.updateContact,
    deleteContact: contactsStore.deleteContact,
    getContactByGenesisHash: contactsStore.getContactByGenesisHash,
    getContactByAlias: contactsStore.getContactByAlias,
    setError: contactsStore.setError,
  }), [state]);

  return <ContactsContext.Provider value={value}>{children}</ContactsContext.Provider>;
}

export function useContacts(): ContactsContextValue {
  return useContext(ContactsContext);
}
