// SPDX-License-Identifier: MIT OR Apache-2.0
//! A contact row states what Rust listed. A contact that is neither paired over
//! BLE nor verified online used to be labelled "ONLINE".

import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';

import ContactsTabScreen from '../ContactsTabScreen';

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

jest.mock('../../../dsm/WebViewBridge', () => ({
  startPairingAll: jest.fn().mockResolvedValue(undefined),
  stopPairingAll: jest.fn().mockResolvedValue(undefined),
}));

describe('ContactsTabScreen contact row', () => {
  beforeEach(() => {
    (globalThis as any).requestAnimationFrame = () => 0;
    mockContacts.length = 0;
  });

  it('labels a contact neither paired nor verified as not verified, and shows what Rust listed', async () => {
    mockContacts.push({
      alias: 'bob',
      deviceId: 'DEV1CE',
      genesisHash: 'GENES1S',
      signingPublicKey: 'PUBKEY',
      genesisVerifiedOnline: false,
    });

    await act(async () => {
      render(<ContactsTabScreen />);
      await Promise.resolve();
    });
    fireEvent.click(screen.getByText('bob'));

    expect(screen.getByText('NOT VERIFIED')).toBeTruthy();
    expect(screen.queryByText('ONLINE')).toBeNull();
    expect(screen.getByText('DEV1CE')).toBeTruthy();
    expect(screen.getByText('GENES1S')).toBeTruthy();
    expect(screen.getByText('PUBKEY')).toBeTruthy();
  });
});
