// SPDX-License-Identifier: Apache-2.0
// The People tab shows where Bluetooth pairing with each contact stands, as
// Rust's pairing loop states it, and reads the list again while it is open.

import React from 'react';
import { act, render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import ModernPeople from '../ModernPeople';
import { ContactsContext } from '../../../contexts/ContactsContext';
import type { DomainContact } from '../../../domain/types';

function contact(alias: string, deviceId: string, pairing: DomainContact['pairing']): DomainContact {
  const genesisHash = `G-${alias}`;
  return { alias, deviceId, genesisHash, pairing, genesisVerifiedOnline: genesisHash.length > 2, signingPublicKey: `K-${alias}` };
}

describe('pairing on the People tab', () => {
  it('says pairing is under way, names each contact\'s pairing, and reads the list again', async () => {
    const reads: string[] = [];
    const contacts = [contact('ana', 'A'.repeat(52), 'paired'), contact('ben', 'B'.repeat(52), 'searching')];
    const value = {
      contacts, isLoading: contacts.length === 0, error: null,
      refreshContacts: async () => { reads.push('read'); },
      addContact: async () => ({ accepted: contacts.length === 0, error: 'not in this test' }) as never,
      setError: () => undefined,
    };
    await act(async () => {
      render(<ContactsContext.Provider value={value as never}><ModernPeople /></ContactsContext.Provider>);
    });
    expect(screen.getByText('Looking for your contacts nearby')).toBeInTheDocument();
    const list = screen.getByLabelText('Contacts');
    expect(within(list).getByText('Paired')).toBeInTheDocument();
    expect(within(list).getByText('Pairing…')).toBeInTheDocument();
    expect(reads.length).toBeGreaterThan(0);
  });
});
