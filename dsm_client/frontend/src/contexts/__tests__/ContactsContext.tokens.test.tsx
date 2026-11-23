// SPDX-License-Identifier: MIT OR Apache-2.0
// What a contact can be sent is in the contact list Rust answers. Rust reads
// each contact's token lists when the wallet opens, after the page has read
// its contacts, and says so with `contact.tokens`: the provider reads the
// list again, so the Send screen offers the contact what it has added.

import React from 'react';
import { act, render, screen, waitFor } from '@testing-library/react';
import * as pb from '../../proto/dsm_app_pb';
import { ContactsProvider, useContacts } from '../ContactsContext';
import { bridgeEvents } from '../../bridge/bridgeEvents';
import { installScriptedPhone, removeScriptedPhone } from '../../tests/helpers/scriptedPhone';

function Sendable(): React.ReactElement {
  const { contacts } = useContacts();
  return <div data-testid="sendable">{contacts.map((c) => c.sendableTokenIds.join(',')).join('|')}</div>;
}

test('a contact whose tokens Rust read after the page loaded is read again', async () => {
  // What the phone keeps as tokens the contact has added, as Rust answers it.
  let kept = ['ERA', 'dBTC'];
  installScriptedPhone({
    'contacts.list': () => ({
      case: 'contactsListResponse',
      value: new pb.ContactsListResponse({
        contacts: [
          new pb.ContactAddResponse({
            alias: 'Peer',
            deviceId: new Uint8Array(32).fill(0x0a),
            genesisHash: new pb.Hash32({ v: new Uint8Array(32).fill(0x0b) }),
            signingPublicKey: new Uint8Array(64).fill(0x0c),
            pairing: pb.ContactPairingPhase.IDLE,
            relationshipState: pb.RelationshipState.ESTABLISHED,
            sendableTokenIds: kept,
          }),
        ],
      }),
    }),
  });
  try {
    render(<ContactsProvider><Sendable /></ContactsProvider>);
    await act(async () => {
      bridgeEvents.emit('identity.ready', undefined);
    });
    await waitFor(() => expect(screen.getByTestId('sendable').textContent).toBe('ERA,dBTC'));

    kept = ['DBUCKS', 'ERA', 'dBTC'];
    await act(async () => {
      bridgeEvents.emit('contact.tokens', undefined);
    });
    await waitFor(() => expect(screen.getByTestId('sendable').textContent).toBe('DBUCKS,ERA,dBTC'));
  } finally {
    removeScriptedPhone();
  }
});
