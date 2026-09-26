// SPDX-License-Identifier: MIT OR Apache-2.0
//! The pairing line states where pairing stands as Rust states it on each
//! contact. The screen used to infer it from raw radio events, and showed
//! "Paired!" when a phone's identity was read, before pairing had completed.

/* eslint-disable @typescript-eslint/no-explicit-any */
import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';

import ContactsTabScreen from '../ContactsTabScreen';
import { bridgeEvents } from '../../../bridge/bridgeEvents';

jest.mock('../../../utils/identity', () => ({
  hasIdentity: jest.fn().mockResolvedValue(false),
}));

jest.mock('../../../hooks/useTransactions', () => ({
  useTransactions: () => ({ transactions: [], refresh: jest.fn() }),
}));

const mockContacts: any[] = [];
jest.mock('../../../contexts/ContactsContext', () => ({
  useContacts: () => ({ contacts: mockContacts, refreshContacts: async () => {}, isLoading: false }),
}));

function contact(alias: string, pairing: string, bleAddress?: string) {
  return { alias, deviceId: `${alias.toUpperCase()}1D`, genesisHash: 'GENES1S', signingPublicKey: 'KEY', genesisVerifiedOnline: true, pairing, bleAddress };
}

async function mount() {
  (globalThis as any).requestAnimationFrame = () => 0;
  await act(async () => {
    render(<ContactsTabScreen />);
    await Promise.resolve();
  });
}

describe('ContactsTabScreen pairing line', () => {
  beforeEach(() => {
    mockContacts.length = 0;
  });

  it('states the furthest a pairing has got, and raw radio events change nothing', async () => {
    mockContacts.push(contact('ann', 'paired', 'AA:BB:CC:DD:EE:01'), contact('bob', 'connected'), contact('cy', 'searching'));
    await mount();
    expect(screen.getByText('Connected')).toBeTruthy();

    await act(async () => {
      bridgeEvents.emit('ble.deviceFound', { address: 'AA:BB:CC:DD:EE:02', name: 'x', rssi: -40 });
      bridgeEvents.emit('ble.deviceDisconnected', { address: 'AA:BB:CC:DD:EE:02' });
      bridgeEvents.emit('contact.bleMapped', { address: 'AA:BB:CC:DD:EE:02', deviceId: 'BOB1D' });
    });
    expect(screen.getByText('Connected')).toBeTruthy();
    expect(screen.queryByText('Paired!')).toBeNull();
    expect(screen.queryByText('Peer Found')).toBeNull();
  });

  it('shows searching for a contact Rust is still looking for, or retrying', async () => {
    mockContacts.push(contact('dee', 'retrying'));
    await mount();
    expect(screen.getByText('Scanning for Peers')).toBeTruthy();
  });

  it('shows no line when no pairing is under way', async () => {
    mockContacts.push(contact('eve', 'paired', 'AA:BB:CC:DD:EE:05'), contact('fay', 'idle'));
    await mount();
    expect(screen.queryByText('Scanning for Peers')).toBeNull();
    expect(screen.queryByText('Connected')).toBeNull();
    fireEvent.click(screen.getByText('eve'));
    expect(screen.getByText('BLE PAIRED')).toBeTruthy();
  });
});
