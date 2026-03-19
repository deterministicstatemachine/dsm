/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/contexts/ContactsContext.tsx
// SPDX-License-Identifier: Apache-2.0
import React, { createContext, useContext, useEffect, useMemo } from 'react';
import { useBridgeEvent } from '@/hooks/useBridgeEvents';
import { hasIdentity } from '../utils/identity';
import { contactsStore, useContactsStore } from '../stores/contactsStore';

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

export function ContactsProvider({ children }: { children: React.ReactNode }) {
  const state = useContactsStore();

  useBridgeEvent('contact.bleMapped', contactsStore.handleBleMapped, []);
  useBridgeEvent('contact.bleUpdated', contactsStore.handleBleUpdated, []);
  useBridgeEvent('contact.added', () => {
    void contactsStore.refreshContacts();
  }, []);
  useBridgeEvent('contact.reconcileNeeded', () => {
    void contactsStore.refreshContacts();
  }, []);
  useBridgeEvent('identity.ready', () => {
    void contactsStore.refreshContacts();
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
