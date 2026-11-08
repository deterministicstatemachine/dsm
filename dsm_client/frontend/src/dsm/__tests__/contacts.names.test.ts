// SPDX-License-Identifier: Apache-2.0
// Audit 2026-10-18, SA-159: every name another person chose reaches the page
// the way the contact list's aliases do, without what renders as nothing: the
// alias Rust answers for a contact just added, and the name of a contact
// picked from the phone. A Hangul filler (U+3164) is a letter that draws as
// blank space, so "alice" padded with one renders as "alice". Each answer
// crosses the production transport from a scripted phone.

import * as pb from '../../proto/dsm_app_pb';
import { addContact, getContacts } from '../contacts';
import { pickPhoneContact } from '../WebViewBridge/phoneContacts';
import { initializeEventBridge } from '../EventBridge';
import { deviceFingerprint } from '../../domain/displayName';
import { encodeBase32Crockford } from '../../utils/textId';
import { installScriptedPhone, removeScriptedPhone, settle } from '../../tests/helpers/scriptedPhone';

const HANGUL_FILLER = '\u3164';
const HALFWIDTH_HANGUL_FILLER = '\uFFA0';

function id(fill: number): Uint8Array<ArrayBuffer> {
  return new Uint8Array(32).fill(fill);
}

function contactAnswer(alias: string, deviceId: Uint8Array<ArrayBuffer>): pb.ContactAddResponse {
  return new pb.ContactAddResponse({
    alias,
    deviceId,
    genesisHash: new pb.Hash32({ v: id(0x20) }),
    signingPublicKey: new Uint8Array(64).fill(0x30),
    pairing: pb.ContactPairingPhase.IDLE,
  });
}

afterEach(removeScriptedPhone);

describe('names at the contact boundary (SA-159)', () => {
  it('lists an alias without its Hangul fillers, and one of nothing else by its device', async () => {
    installScriptedPhone({
      'contacts.list': {
        case: 'contactsListResponse',
        value: new pb.ContactsListResponse({
          contacts: [
            contactAnswer(`alice${HANGUL_FILLER}`, id(0x41)),
            contactAnswer(`${HANGUL_FILLER}${HALFWIDTH_HANGUL_FILLER}`, id(0x52)),
          ],
        }),
      },
    });
    const { contacts } = await getContacts();
    expect(contacts.map((c) => c.alias)).toEqual(['alice', deviceFingerprint(id(0x52))]);
  });

  it('answers the alias Rust stored for a contact just added as names are shown', async () => {
    installScriptedPhone({
      'contacts.addManual': { case: 'contactAddResponse', value: contactAnswer(`alice${HANGUL_FILLER}`, id(0x41)) },
    });
    const added = await addContact({
      alias: 'alice',
      deviceId: id(0x41),
      genesisHash: id(0x20),
      signingPublicKey: new Uint8Array(64).fill(0x30),
    });
    expect(added).toMatchObject({ contactId: encodeBase32Crockford(id(0x41)), alias: 'alice' });
  });

  it('answers a phone contact picked under a filler-padded name by the name it pads', async () => {
    initializeEventBridge();
    installScriptedPhone({}, { pickPhoneContact: new Uint8Array(0) });
    const picked = pickPhoneContact();
    await settle();
    // Kotlin delivers the pick as a native host event.
    const event = new pb.NativeHostEvent({
      kind: pb.NativeHostEventKind.PHONE_CONTACT_PICKED,
      payload: new Uint8Array(new pb.ContactProfileV1({
        displayName: `Alice${HANGUL_FILLER} Smith`,
        email: `alice${HALFWIDTH_HANGUL_FILLER}@example.com`,
        phone: '+1 555 0100',
        phoneLookupKey: 'lookup-1',
      }).toBinary()),
    });
    window.dispatchEvent(new CustomEvent('dsm-native-host-event-bin', { detail: { payload: event.toBinary() } }));
    expect(await picked).toEqual({
      name: 'Alice Smith',
      email: 'alice@example.com',
      phone: '+1 555 0100',
      phoneLookupKey: 'lookup-1',
    });
  });
});
