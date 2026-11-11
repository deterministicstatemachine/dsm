// SPDX-License-Identifier: Apache-2.0
// The Modern skin's contact screen unpairs exactly the contact it shows and
// says what Rust answered, as the StateBoy contacts screen does. The contacts
// come through the wallet's own store and mapping, over the production
// transport.

import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import * as pb from '../../../proto/dsm_app_pb';
import ModernContact from '../ModernContact';
import { ContactsContext } from '../../../contexts/ContactsContext';
import { contactsStore } from '../../../stores/contactsStore';
import { getContacts } from '../../../dsm/contacts';
import { mapContactList } from '../../../domain/mappers';
import { installScriptedPhone, removeScriptedPhone, settle, type Answer } from '../../../tests/helpers/scriptedPhone';

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
    relationshipState: pb.RelationshipState.ESTABLISHED,
  });
}

type BridgeHolder = { DsmBridge: { sendMessageBin: (bytes: Uint8Array) => Promise<Uint8Array> } };

/** Records the argument of every `contacts.unpair` the page sends. */
function recordUnpairs(sent: Uint8Array[]): void {
  const bridge = (window as unknown as BridgeHolder).DsmBridge;
  const answer = bridge.sendMessageBin;
  bridge.sendMessageBin = async (bytes: Uint8Array) => {
    const request = pb.BridgeRpcRequest.fromBinary(bytes);
    if (request.method === 'nativeBoundaryIngress' && request.payload.case === 'bytes') {
      const operation = pb.IngressRequest.fromBinary(request.payload.value.data).operation;
      if (operation.case === 'routerInvoke' && operation.value.method === 'contacts.unpair') sent.push(operation.value.args);
    }
    return answer(bytes);
  };
}

async function showBob(unpairAnswer: Answer): Promise<{ sent: Uint8Array[]; bob: Uint8Array<ArrayBuffer> }> {
  const bob = id(0x42);
  installScriptedPhone({
    'contacts.list': {
      case: 'contactsListResponse',
      value: new pb.ContactsListResponse({ contacts: [listed('alice', id(0x41)), listed('bob', bob)] }),
    },
    'contacts.unpair': unpairAnswer,
  });
  const sent: Uint8Array[] = [];
  recordUnpairs(sent);
  const contacts = mapContactList((await getContacts()).contacts);
  const value = {
    ...contactsStore.getSnapshot(),
    contacts,
    refreshContacts: contactsStore.refreshContacts,
    addContact: contactsStore.addContact,
    unpairContact: contactsStore.unpair,
    terminateContact: async () => { throw new Error('terminateContact is not reached by this test'); },
    setError: contactsStore.setError,
  };
  const shown = contacts.find((c) => c.alias === 'bob');
  if (shown === undefined) throw new Error('bob is not in the mapped list');
  await act(async () => {
    render(
      <ContactsContext.Provider value={value}>
        <ModernContact deviceId={shown.deviceId} />
      </ContactsContext.Provider>,
    );
    await settle();
  });
  return { sent, bob };
}

afterEach(removeScriptedPhone);

describe('unpair and pair again on the Modern skin', () => {
  it('unpairs the contact the screen shows', async () => {
    const { sent, bob } = await showBob({ case: 'contactAddResponse', value: listed('bob', id(0x42)) });

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Unpair and pair again' }));
      await settle();
    });

    expect(sent).toHaveLength(1);
    const arg = pb.ArgPack.fromBinary(sent[0]);
    expect(pb.ContactUnpairRequest.fromBinary(arg.body).deviceId).toEqual(bob);
    expect(screen.getByText('Unpaired. This device reaches theirs to pair again.')).toBeInTheDocument();
  });

  it('says what Rust answered when it refuses the unpair', async () => {
    await showBob({
      case: 'error',
      value: new pb.Error({ code: 3, message: 'the paired address was not forgotten: no contact changed' }),
    });

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Unpair and pair again' }));
      await settle();
    });

    expect(screen.getByText('the paired address was not forgotten: no contact changed')).toBeInTheDocument();
  });
});
