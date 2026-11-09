// SPDX-License-Identifier: Apache-2.0
// "Unpair and pair again" asks Rust to unpair exactly the contact it sits
// under, reads the list again once Rust has unpaired it, and says what Rust
// answered when it refuses. The contacts come through the wallet's own store
// and mapping, over the production transport.

import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import * as pb from '../../../proto/dsm_app_pb';
import ContactsTabScreen from '../ContactsTabScreen';
import { ContactsContext } from '../../../contexts/ContactsContext';
import { contactsStore } from '../../../stores/contactsStore';
import { getContacts } from '../../../dsm/contacts';
import { mapContactList } from '../../../domain/mappers';
import { installScriptedPhone, removeScriptedPhone, settle, type Answer } from '../../../tests/helpers/scriptedPhone';

function id(fill: number): Uint8Array<ArrayBuffer> {
  return new Uint8Array(32).fill(fill);
}

function listed(alias: string, deviceId: Uint8Array<ArrayBuffer>, pairing: pb.ContactPairingPhase): pb.ContactAddResponse {
  return new pb.ContactAddResponse({
    alias,
    deviceId,
    genesisHash: new pb.Hash32({ v: id(0x20) }),
    signingPublicKey: new Uint8Array(64).fill(0x30),
    pairing,
  });
}

type Call = { route: string; args: Uint8Array };
type BridgeHolder = { DsmBridge: { sendMessageBin: (bytes: Uint8Array) => Promise<Uint8Array> } };

/** Records every router route the page reaches, with the argument it carried. */
function recordRoutes(calls: Call[]): void {
  const bridge = (window as unknown as BridgeHolder).DsmBridge;
  const answer = bridge.sendMessageBin;
  bridge.sendMessageBin = async (bytes: Uint8Array) => {
    const request = pb.BridgeRpcRequest.fromBinary(bytes);
    if (request.method === 'nativeBoundaryIngress' && request.payload.case === 'bytes') {
      const operation = pb.IngressRequest.fromBinary(request.payload.value.data).operation;
      if (operation.case === 'routerInvoke') calls.push({ route: operation.value.method, args: operation.value.args });
      if (operation.case === 'routerQuery') calls.push({ route: operation.value.method, args: new Uint8Array(0) });
    }
    return answer(bytes);
  };
}

async function showContacts(unpairAnswer: Answer): Promise<{ calls: Call[]; bob: Uint8Array<ArrayBuffer> }> {
  const bob = id(0x42);
  installScriptedPhone({
    'contacts.list': {
      case: 'contactsListResponse',
      value: new pb.ContactsListResponse({
        contacts: [listed('alice', id(0x41), pb.ContactPairingPhase.IDLE), listed('bob', bob, pb.ContactPairingPhase.IDLE)],
      }),
    },
    'contacts.unpair': unpairAnswer,
    'wallet.history': { case: 'walletHistoryResponse', value: new pb.WalletHistoryResponse({}) },
  });
  const calls: Call[] = [];
  recordRoutes(calls);
  const value = {
    ...contactsStore.getSnapshot(),
    contacts: mapContactList((await getContacts()).contacts),
    refreshContacts: contactsStore.refreshContacts,
    addContact: contactsStore.addContact,
    unpairContact: contactsStore.unpair,
    setError: contactsStore.setError,
  };
  (globalThis as unknown as { requestAnimationFrame: () => number }).requestAnimationFrame = () => 0;
  await act(async () => {
    render(
      <ContactsContext.Provider value={value}>
        <ContactsTabScreen />
      </ContactsContext.Provider>,
    );
    await settle();
  });
  fireEvent.click(screen.getByText('bob'));
  calls.length = 0;
  return { calls, bob };
}

afterEach(removeScriptedPhone);

describe('unpair and pair again', () => {
  it('unpairs the contact it sits under and reads the list again', async () => {
    const { calls, bob } = await showContacts({
      case: 'contactAddResponse',
      value: listed('bob', id(0x42), pb.ContactPairingPhase.IDLE),
    });

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Unpair and pair again' }));
      await settle();
    });

    const unpairs = calls.filter((c) => c.route === 'contacts.unpair');
    expect(unpairs).toHaveLength(1);
    const arg = pb.ArgPack.fromBinary(unpairs[0].args);
    expect(arg.codec).toBe(pb.Codec.PROTO);
    expect(pb.ContactUnpairRequest.fromBinary(arg.body).deviceId).toEqual(bob);
    const unpairAt = calls.findIndex((c) => c.route === 'contacts.unpair');
    expect(calls.slice(unpairAt + 1).map((c) => c.route)).toContain('contacts.list');
    expect(screen.getByRole('button', { name: 'Unpair and pair again' })).toBeEnabled();
  });

  it('says what Rust answered when it refuses the unpair', async () => {
    await showContacts({
      case: 'error',
      value: new pb.Error({ code: 3, message: 'the paired address was not forgotten: no contact changed' }),
    });

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Unpair and pair again' }));
      await settle();
    });

    expect(screen.getByText('the paired address was not forgotten: no contact changed')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Unpair and pair again' })).toBeEnabled();
  });
});
