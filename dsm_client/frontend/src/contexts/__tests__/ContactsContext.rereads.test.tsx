// SPDX-License-Identifier: Apache-2.0
// The contact list is read again when Rust says something moved — a
// settlement, a release, an arrival (`wallet.refresh`) — or a pairing moves
// on, and on no timer. The Contacts and People screens used to read it every
// five seconds for as long as they were open.

import React from 'react';
import { act, render } from '@testing-library/react';
import * as pb from '../../proto/dsm_app_pb';
import { ContactsProvider } from '../ContactsContext';
import ContactsTabScreen from '../../components/screens/ContactsTabScreen';
import ModernPeople from '../../components/modern/ModernPeople';
import { bridgeEvents } from '../../bridge/bridgeEvents';
import { installScriptedPhone, removeScriptedPhone, settle } from '../../tests/helpers/scriptedPhone';

afterEach(removeScriptedPhone);

/** Lets a read scheduled for the next frame run and its answer arrive. */
async function nextFrame(): Promise<void> {
  await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
  await settle();
}

test('the contact list is read on Rust\'s word and a pairing\'s, not on a clock', async () => {
  let reads = 0;
  installScriptedPhone({
    'contacts.list': () => {
      reads += 1;
      return { case: 'contactsListResponse', value: new pb.ContactsListResponse({ contacts: [] }) };
    },
    'wallet.history': { case: 'walletHistoryResponse', value: new pb.WalletHistoryResponse({}) },
  });
  // Both screens that list contacts, open.
  render(<ContactsProvider><ContactsTabScreen /><ModernPeople /></ContactsProvider>);
  await act(settle);
  const opened = reads;

  await act(async () => { await new Promise((r) => setTimeout(r, 6_000)); });
  expect(reads).toBe(opened);

  await act(async () => {
    bridgeEvents.emit('wallet.refresh', { source: 'native' });
    await nextFrame();
  });
  expect(reads).toBe(opened + 1);

  await act(async () => {
    bridgeEvents.emit('ble.pairingStatus', { deviceId: 'D', status: 'paired', message: '' });
    await settle();
  });
  // The provider reads it, and so may a screen that follows the pairing.
  expect(reads).toBeGreaterThan(opened + 1);
}, 15_000);
