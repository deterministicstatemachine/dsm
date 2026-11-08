// SPDX-License-Identifier: Apache-2.0
// Audit 2026-10-15, items 3 and 5: the send confirmation names the device paid
// by its fingerprint beside the alias a contact chose, says when another
// contact goes by the same name, and holds the confirm guard (other apps'
// overlay windows hidden) only while it is shown. The contacts and the balance
// come through the wallet's own mapping of what Rust lists.

import React from 'react';
import { act, fireEvent, render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import * as pb from '../../../../proto/dsm_app_pb';
import SendTab from '../SendTab';
import { getContacts } from '../../../../dsm/contacts';
import { balanceView } from '../../../../dsm/wallet';
import { mapContactList } from '../../../../domain/mappers';
import { deviceFingerprint } from '../../../../domain/displayName';
import { encodeBase32Crockford } from '../../../../utils/textId';
import { installScriptedPhone, removeScriptedPhone, settle } from '../../../../tests/helpers/scriptedPhone';

const RLO = '\u202E';
const CONFIRM = 2;

function id(fill: number): Uint8Array<ArrayBuffer> {
  return new Uint8Array(32).fill(fill);
}

function listed(alias: string, deviceId: Uint8Array<ArrayBuffer>): pb.ContactAddResponse {
  return new pb.ContactAddResponse({
    alias,
    deviceId,
    genesisHash: new pb.Hash32({ v: id(0x20) }),
    signingPublicKey: new Uint8Array(64).fill(0x30),
    pairing: pb.ContactPairingPhase.IDLE,
  });
}

const BALANCE = balanceView(
  new pb.BalanceGetResponse({
    tokenId: 'RIGB',
    symbol: 'RIGB',
    tokenName: 'Rig B',
    available: 1000n,
    displayAmount: '1000',
    genesisSupplyDisplay: '1000000',
    permissions: new pb.TokenPolicyPermissions({}),
  }),
);

afterEach(removeScriptedPhone);

describe('the send confirmation', () => {
  it('names the device by its fingerprint, says the name is shared, and guards only while shown', async () => {
    const paid = id(0x41);
    const namesake = id(0x52);
    const phone = installScriptedPhone({
      'contacts.list': {
        case: 'contactsListResponse',
        value: new pb.ContactsListResponse({
          contacts: [listed(`alice${RLO}`, paid), listed('Alice', namesake), listed('bob', id(0x63))],
        }),
      },
    });
    const contacts = mapContactList((await getContacts()).contacts);
    // The alias Rust listed reached the page without its bidi override.
    expect(contacts.map((c) => c.alias)).toEqual(['alice', 'Alice', 'bob']);

    render(
      <SendTab
        contacts={contacts}
        balances={[BALANCE]}
        onCancel={() => undefined}
        onSendComplete={() => undefined}
        loadWalletData={() => Promise.resolve()}
        setError={() => undefined}
      />,
    );
    fireEvent.change(screen.getByLabelText(/recipient/i), { target: { value: encodeBase32Crockford(paid) } });
    fireEvent.change(screen.getByLabelText('Amount'), { target: { value: '5' } });
    expect(screen.getByTestId('send-recipient-confirm')).toHaveTextContent(`To: ${deviceFingerprint(paid)}`);
    await act(settle);
    expect(phone.guards).toEqual([]);

    fireEvent.click(screen.getByRole('button', { name: /^send$/i }));
    const asked = screen.getByText(
      `Send 5 RIGB to alice, device ${deviceFingerprint(paid)}? Also named alice: ${deviceFingerprint(namesake)}.`,
    );
    await act(settle);
    expect(phone.guards).toEqual([CONFIRM]);

    const dialog = asked.closest('.bilateral-transfer-dialog');
    if (!(dialog instanceof HTMLElement)) throw new Error('the confirmation is not in its dialog');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await act(settle);
    expect(phone.guards).toEqual([CONFIRM, 0]);
  });
});
