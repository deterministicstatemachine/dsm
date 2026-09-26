/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/contexts/ContactsContext.tsx
// SPDX-License-Identifier: Apache-2.0
import React, { createContext, useContext, useEffect, useMemo } from 'react';
import { useBridgeEvent } from '@/hooks/useBridgeEvents';
import { hasIdentity } from '../utils/identity';
import { contactsStore, useContactsStore } from '../stores/contactsStore';
import {
  setBleIdentityForAdvertising,
  startBleAdvertisingViaRouter,
} from '../dsm/WebViewBridge';
import { getHeaders } from '../dsm/identity';

/** A contact as Rust lists it, in Base32 Crockford. */
export interface Contact {
  /** The contact's device id: a contact is its device. */
  id: string;
  alias: string;
  genesisHash: string;
  deviceId: string;
  publicKey: string;
  /** Its genesis was verified against the storage nodes. */
  isVerified: boolean;
  bleAddress?: string;
  chainTip?: string;
}

export interface ContactsState {
  contacts: Contact[];
  isLoading: boolean;
  error: string | null;
}

export interface ContactsContextValue extends ContactsState {
  refreshContacts: () => Promise<void>;
  addContact: (alias: string, genesisHash: Uint8Array | string, deviceId: Uint8Array | string | undefined, signingPublicKey: Uint8Array | string | undefined) => Promise<boolean>;
  setError: (error: string | null) => void;
}

const defaultValue: ContactsContextValue = {
  contacts: [],
  isLoading: false,
  error: null,
  refreshContacts: async () => {},
  addContact: async () => false,
  setError: () => {},
};

export const ContactsContext = createContext<ContactsContextValue>(defaultValue);

/**
 * Ensure BLE advertising is active so peers can initiate bilateral transfers.
 * Called by EnhancedWalletScreen on mount/visibility change, and by
 * ContactsProvider on identity.ready and contact.bleMapped events.
 */
export async function ensureBleAdvertisingIfContacts(): Promise<void> {
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

  useBridgeEvent('contact.bleMapped', (detail) => {
    contactsStore.handleBleMapped(detail);
    void ensureBleAdvertisingIfContacts();
  }, []);
  useBridgeEvent('contact.bleUpdated', contactsStore.handleBleUpdated, []);
  useBridgeEvent('contact.added', () => {
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
    setError: contactsStore.setError,
  }), [state]);

  return <ContactsContext.Provider value={value}>{children}</ContactsContext.Provider>;
}

export function useContacts(): ContactsContextValue {
  return useContext(ContactsContext);
}
