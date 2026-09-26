// SPDX-License-Identifier: MIT OR Apache-2.0

jest.mock('../WebViewBridge', () => ({
  getContactsStrictBridge: jest.fn(),
  routerInvokeBin: jest.fn(),
  routerQueryBin: jest.fn(),
  requestBlePermissions: jest.fn(),
}));

import * as pb from '../../proto/dsm_app_pb';
import { encodeBase32Crockford } from '../../utils/textId';
import { getContacts, addContact, requestBlePermissions } from '../contacts';
import {
  getContactsStrictBridge,
  routerInvokeBin,
  requestBlePermissions as bridgeRequestBlePermissions,
} from '../WebViewBridge';

function frameEnvelope(envelope: pb.Envelope): Uint8Array {
  const bytes = envelope.toBinary();
  const framed = new Uint8Array(1 + bytes.length);
  framed[0] = 0x03;
  framed.set(bytes, 1);
  return framed;
}

describe('contacts.ts', () => {
  beforeEach(() => jest.clearAllMocks());

  // ── getContacts ────────────────────────────────────────────────────

  describe('getContacts', () => {
    test('maps contacts from ContactsListResponse', async () => {
      const deviceId = new Uint8Array(32).fill(0x01);
      const signingPk = new Uint8Array(64).fill(0x02);
      const gh = new Uint8Array(32).fill(0x03);

      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'contactsListResponse',
          value: new pb.ContactsListResponse({
            contacts: [
              new pb.ContactAddResponse({
                deviceId: deviceId as any,
                alias: 'Alice',
                signingPublicKey: signingPk as any,
                genesisHash: { v: gh } as any,
                bleAddress: 'AA:BB:CC:DD:EE:FF',
                genesisVerifiedOnline: true,
              }),
            ],
          }),
        },
      });
      (getContactsStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await getContacts();
      expect(result.total).toBe(1);
      expect(result.contacts).toHaveLength(1);
      expect(result.contacts[0].alias).toBe('Alice');
      expect(result.contacts[0].deviceId).toEqual(deviceId);
      expect(result.contacts[0].publicKey).toEqual(signingPk);
      expect(result.contacts[0].bleAddress).toBe('AA:BB:CC:DD:EE:FF');
      expect(result.contacts[0].genesisVerifiedOnline).toBe(true);
    });

    test('returns empty contacts list', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'contactsListResponse',
          value: new pb.ContactsListResponse({ contacts: [] }),
        },
      });
      (getContactsStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await getContacts();
      expect(result.total).toBe(0);
      expect(result.contacts).toEqual([]);
    });

    test('a contact without what Rust always writes is refused, never filled in', async () => {
      const answer = (contact: pb.ContactAddResponse) =>
        frameEnvelope(new pb.Envelope({
          version: 3,
          payload: { case: 'contactsListResponse', value: new pb.ContactsListResponse({ contacts: [contact] }) },
        }));
      const complete = {
        deviceId: new Uint8Array(32).fill(0x01),
        alias: 'Alice',
        signingPublicKey: new Uint8Array(64).fill(0x02),
        genesisHash: { v: new Uint8Array(32).fill(0x03) },
      };

      (getContactsStrictBridge as jest.Mock).mockResolvedValue(answer(new pb.ContactAddResponse({})));
      await expect(getContacts()).rejects.toThrow(/STRICT.*0-byte device id/);

      (getContactsStrictBridge as jest.Mock).mockResolvedValue(
        answer(new pb.ContactAddResponse({ ...complete, genesisHash: undefined } as any)),
      );
      await expect(getContacts()).rejects.toThrow(/STRICT.*without its 32-byte genesis/);

      (getContactsStrictBridge as jest.Mock).mockResolvedValue(
        answer(new pb.ContactAddResponse({ ...complete, signingPublicKey: new Uint8Array(0) } as any)),
      );
      await expect(getContacts()).rejects.toThrow(/STRICT.*0-byte signing key/);

      (getContactsStrictBridge as jest.Mock).mockResolvedValue(
        answer(new pb.ContactAddResponse({ ...complete, alias: '' } as any)),
      );
      await expect(getContacts()).rejects.toThrow(/STRICT.*without its alias/);
    });

    test('throws on empty response bytes', async () => {
      (getContactsStrictBridge as jest.Mock).mockResolvedValue(new Uint8Array(0));
      await expect(getContacts()).rejects.toThrow(/empty response/);
    });

    test('throws on error envelope', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'error', value: new pb.Error({ code: 7, message: 'contacts denied' }) },
      });
      (getContactsStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      await expect(getContacts()).rejects.toThrow(/DSM native error.*contacts denied/);
    });

    test('throws on unexpected payload case', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'balancesListResponse', value: new pb.BalancesListResponse() },
      });
      (getContactsStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      await expect(getContacts()).rejects.toThrow(/Unexpected payload case for contacts/);
    });

    test('returns empty contacts when payload serializes as empty message', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'contactsListResponse', value: undefined as any },
      });
      (getContactsStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await getContacts();
      expect(result.contacts).toEqual([]);
      expect(result.total).toBe(0);
    });

    test('maps chainTip when present in nested v format', async () => {
      const tipHash = new Uint8Array(32).fill(0xAA);
      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'contactsListResponse',
          value: new pb.ContactsListResponse({
            contacts: [
              new pb.ContactAddResponse({
                alias: 'Bob',
                deviceId: new Uint8Array(32).fill(0x04) as any,
                signingPublicKey: new Uint8Array(64).fill(0x05) as any,
                genesisHash: { v: new Uint8Array(32).fill(0x06) } as any,
                chainTip: { v: tipHash } as any,
              }),
            ],
          }),
        },
      });
      (getContactsStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await getContacts();
      expect(result.contacts[0].chainTip).toEqual(tipHash);
    });
  });

  // ── addContact ─────────────────────────────────────────────────────

  describe('addContact', () => {
    // No alias or length rule is checked here: Rust names a contact added
    // without an alias by its device, and refuses a card that does not
    // resolve (contacts.manualAdd.test.ts).
    test('returns accepted on success', async () => {
      const deviceId = new Uint8Array(32).fill(1);
      const genesisHash = new Uint8Array(32).fill(2);
      const signingPublicKey = new Uint8Array(64).fill(3);

      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'contactAddResponse',
          value: new pb.ContactAddResponse({ alias: 'TestContact', deviceId: deviceId as any }),
        },
      });
      (routerInvokeBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await addContact({ alias: 'TestContact', deviceId, genesisHash, signingPublicKey });
      expect(result).toEqual({ accepted: true, contactId: encodeBase32Crockford(deviceId), alias: 'TestContact' });
    });

    test('returns error on error envelope', async () => {
      const deviceId = new Uint8Array(32).fill(1);
      const genesisHash = new Uint8Array(32).fill(2);
      const signingPublicKey = new Uint8Array(64).fill(3);

      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'error', value: new pb.Error({ code: 9, message: 'duplicate' }) },
      });
      (routerInvokeBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await addContact({ alias: 'Test', deviceId, genesisHash, signingPublicKey });
      expect(result).toEqual({ accepted: false, error: 'duplicate' });
    });

    test('returns error when bridge throws', async () => {
      const deviceId = new Uint8Array(32).fill(1);
      const genesisHash = new Uint8Array(32).fill(2);
      const signingPublicKey = new Uint8Array(64).fill(3);

      (routerInvokeBin as jest.Mock).mockRejectedValue(new Error('bridge fail'));

      const result = await addContact({ alias: 'Test', deviceId, genesisHash, signingPublicKey });
      expect(result).toEqual({ accepted: false, error: 'bridge fail' });
    });
  });

  // ── requestBlePermissions ──────────────────────────────────────────

  describe('requestBlePermissions', () => {
    test('delegates to bridge', async () => {
      (bridgeRequestBlePermissions as jest.Mock).mockResolvedValue(undefined);
      await requestBlePermissions();
      expect(bridgeRequestBlePermissions).toHaveBeenCalledTimes(1);
    });
  });
});
