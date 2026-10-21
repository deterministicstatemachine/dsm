// SPDX-License-Identifier: Apache-2.0
// Audit 2026-10-18, SA-158: the escrow lock form named the parties who decide
// an outcome and the party it pays by alias alone, and locked on one tap. A
// contact can go by another contact's name, or by this device's, in letters
// that read the same. Each party is named with its device's fingerprint, as
// the send flow names the device it pays; a name another party shares is said
// to be shared, by each device; and nothing is locked before a review that
// names every party by device. The contacts come through the wallet's own
// mapping of what Rust lists.

import React from 'react';
import { act, fireEvent, render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import * as pb from '../../../proto/dsm_app_pb';
import EscrowTab from '../sofi/EscrowTab';
import { ContactsContext } from '../../../contexts/ContactsContext';
import { contactsStore } from '../../../stores/contactsStore';
import { getContacts } from '../../../dsm/contacts';
import { mapContactList } from '../../../domain/mappers';
import { deviceFingerprint } from '../../../domain/displayName';
import { installScriptedPhone, removeScriptedPhone, settle } from '../../../tests/helpers/scriptedPhone';

const CYRILLIC_SMALL_A = '\u0430';
const CYRILLIC_TE = '\u0422';
const HANGUL_FILLER = '\u3164';
const CONFIRM = 2;
/** ERA's policy commit, the anchor the wallet's balances carry for it. */
const ERA = 'NNG176RZ6ACTWCDPRNYHXZK2DCZ72SPA9Q6XWGRGQ9JGKZYTESG0';

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

afterEach(removeScriptedPhone);

describe('the escrow lock form (SA-158)', () => {
  it('names every party by device, says which names are shared, and locks only from a review', async () => {
    const me = id(0x11);
    const alice = id(0x41);
    const lookalike = id(0x52);
    const notMe = id(0x63);
    const fp = deviceFingerprint;
    const phone = installScriptedPhone({
      'escrow.party': { case: 'escrowPartyResponse', value: new pb.EscrowPartyResponse({ genesis: id(0x12), deviceId: me }) },
      'escrow.vaults': { case: 'escrowVaultsResponse', value: new pb.EscrowVaultsResponse({}) },
      'contacts.list': {
        case: 'contactsListResponse',
        value: new pb.ContactsListResponse({
          contacts: [
            listed('alice', alice),
            // A Cyrillic a (U+0430), and a Hangul filler that draws as nothing.
            listed(`${CYRILLIC_SMALL_A}lice${HANGUL_FILLER}`, lookalike),
            // This device's own name, with a Cyrillic T (U+0422).
            listed(`${CYRILLIC_TE}his device`, notMe),
          ],
        }),
      },
    });
    const contacts = mapContactList((await getContacts()).contacts);
    const value = {
      ...contactsStore.getSnapshot(),
      contacts,
      refreshContacts: contactsStore.refreshContacts,
      addContact: contactsStore.addContact,
      setError: contactsStore.setError,
    };
    await act(async () => {
      render(
        <ContactsContext.Provider value={value}>
          <EscrowTab tokenOptions={[{ value: ERA, ticker: 'ERA' }]} onMoved={async () => undefined} />
        </ContactsContext.Provider>,
      );
      await settle();
    });
    expect(screen.getByText('No escrow vaults yet.')).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Stake'), { target: { value: '5' } });
    fireEvent.click(screen.getByRole('button', { name: 'Stake token' }));
    const list = await screen.findByRole('listbox', { name: 'Stake token' });
    fireEvent.click(within(list).getByRole('option', { name: /ERA/ }));
    fireEvent.change(screen.getByLabelText('Agreement, exactly as every party has it'), { target: { value: 'terms v1' } });
    fireEvent.change(screen.getByLabelText('Outcome 1'), { target: { value: 'delivered' } });

    // Every party the form offers is named with its device.
    const pays = screen.getByLabelText('Pays');
    expect(within(pays).getAllByRole('option').map((o) => o.textContent)).toEqual([
      'Choose who it pays',
      `This device, device ${fp(me)}`,
      `alice, device ${fp(alice)}`,
      `${CYRILLIC_SMALL_A}lice, device ${fp(lookalike)}`,
      `${CYRILLIC_TE}his device, device ${fp(notMe)}`,
    ]);

    // Each chosen party that shares its name is said to, by every device that goes by it.
    fireEvent.click(screen.getByLabelText(`Outcome 1 decided by alice, device ${fp(alice)}`));
    fireEvent.click(screen.getByLabelText(`Outcome 1 decided by This device, device ${fp(me)}`));
    fireEvent.change(pays, { target: { value: within(pays).getByRole('option', { name: `${CYRILLIC_SMALL_A}lice, device ${fp(lookalike)}` }).getAttribute('value') } });
    expect(screen.getAllByRole('alert').map((a) => a.textContent)).toEqual([
      `Also named alice: ${fp(lookalike)}. You chose device ${fp(alice)}.`,
      `Also named This device: ${fp(notMe)}. You chose device ${fp(me)}.`,
      `Also named ${CYRILLIC_SMALL_A}lice: ${fp(alice)}. You chose device ${fp(lookalike)}.`,
    ]);

    // Lock stake opens the review; nothing is locked from it until Confirm.
    fireEvent.click(screen.getByRole('button', { name: 'Lock stake' }));
    const review = screen.getByText(/^Lock 5 ERA in an escrow vault\?/);
    expect(review).toHaveTextContent(
      `Lock 5 ERA in an escrow vault? Outcome 1, "delivered": decided by alice, device ${fp(alice)} ` +
        `(also named alice: ${fp(lookalike)}) and This device, device ${fp(me)} (also named This device: ${fp(notMe)}); ` +
        `pays ${CYRILLIC_SMALL_A}lice, device ${fp(lookalike)} (also named ${CYRILLIC_SMALL_A}lice: ${fp(alice)}).`,
    );
    expect(phone.guards).toContain(CONFIRM);
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByText(/^Lock 5 ERA in an escrow vault\?/)).not.toBeInTheDocument();
    // No lock was asked for: the status says nothing of one.
    expect(screen.queryByText(/^Lock stake(…| failed)/)).not.toBeInTheDocument();

    // Confirmed, the lock reaches the phone, which answers no escrow.lock here.
    fireEvent.click(screen.getByRole('button', { name: 'Lock stake' }));
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
      await settle();
    });
    expect(screen.getByText(/^Lock stake failed: .*escrow\.lock/)).toBeInTheDocument();
  });
});
