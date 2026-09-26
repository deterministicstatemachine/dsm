/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/contexts/ContactsContext.tsx
// SPDX-License-Identifier: Apache-2.0
import React, { createContext, useContext, useEffect, useMemo } from 'react';
import { useBridgeEvent } from '@/hooks/useBridgeEvents';
import { hasIdentity } from '../utils/identity';
import { contactsStore, useContactsStore } from '../stores/contactsStore';
import type { AddContactResult, ContactCard } from '../dsm/types';
import type { DomainContact } from '../domain/types';

export interface ContactsState {
  /** Rust's list in the one contact shape: a contact is its device, with its send-readiness. */
  contacts: DomainContact[];
  isLoading: boolean;
  error: string | null;
}

export interface ContactsContextValue extends ContactsState {
  refreshContacts: () => Promise<void>;
  /** Adds the contact a card names; empty alias: Rust names it by its device. */
  addContact: (alias: string, card: ContactCard) => Promise<AddContactResult>;
  setError: (error: string | null) => void;
}

const defaultValue: ContactsContextValue = {
  contacts: [],
  isLoading: false,
  error: null,
  refreshContacts: async () => {},
  addContact: async () => { throw new Error('addContact is used outside ContactsProvider'); },
  setError: () => {},
};

export const ContactsContext = createContext<ContactsContextValue>(defaultValue);

export function ContactsProvider({ children }: { children: React.ReactNode }) {
  const state = useContactsStore();

  useBridgeEvent('contact.bleMapped', (detail) => {
    contactsStore.handleBleMapped(detail);
  }, []);
  useBridgeEvent('contact.bleUpdated', contactsStore.handleBleUpdated, []);
  // The list Rust holds once there is an identity. Whether the radio
  // advertises is native policy (it follows the identity), not the screen's.
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
    setError: contactsStore.setError,
  }), [state]);

  return <ContactsContext.Provider value={value}>{children}</ContactsContext.Provider>;
}

export function useContacts(): ContactsContextValue {
  return useContext(ContactsContext);
}
