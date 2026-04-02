jest.mock('../WebViewBridge', () => ({
  getContactsStrictBridge: jest.fn(),
  normalizeToBytes: jest.fn((data: unknown) => {
    if (data instanceof Uint8Array) return data;
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    if (Array.isArray(data)) return new Uint8Array(data);
    throw new Error('normalizeToBytes: expected Uint8Array or number[]');
  }),
  appRouterInvokeBin: jest.fn(),
  requestBlePermissions: jest.fn(),
}));

import * as pb from '../../proto/dsm_app_pb';
import { getContacts, addContact, requestBlePermissions } from '../contacts';
import {
  getContactsStrictBridge,
  appRouterInvokeBin,
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
                verifyCounter: 5n,
                bleAddress: 'AA:BB:CC:DD:EE:FF',
                genesisVerifiedOnline: true,
                addedCounter: 10n,
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
      expect(result.contacts[0].lastSeenTick).toBe(5n);
      expect(result.contacts[0].bleAddress).toBe('AA:BB:CC:DD:EE:FF');
      expect(result.contacts[0].genesisVerifiedOnline).toBe(true);
      expect(result.contacts[0].addedCounter).toBe(10n);
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

    test('handles contact with missing optional fields', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'contactsListResponse',
          value: new pb.ContactsListResponse({
            contacts: [new pb.ContactAddResponse({})],
          }),
        },
      });
      (getContactsStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await getContacts();
      expect(result.contacts[0].alias).toBe('');
      expect(result.contacts[0].deviceId).toEqual(new Uint8Array());
      expect(result.contacts[0].publicKey).toEqual(new Uint8Array());
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
                chainTip: { v: tipHash } as any,
              }),
            ],
          }),
        },
      });
      (getContactsStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await getContacts();
      expect(result.contacts[0].chainTip).toBeDefined();
      expect(result.contacts[0].chainTip?.tipHash).toEqual(tipHash);
    });
  });

  // ── addContact ─────────────────────────────────────────────────────

  describe('addContact', () => {
    test('throws when alias is missing', async () => {
      await expect(addContact({
        alias: '',
        deviceId: new Uint8Array(32),
        genesisHash: new Uint8Array(32),
        signingPublicKey: new Uint8Array(64),
      })).rejects.toThrow(/alias required/);
    });

    test('throws when genesisHash is not 32 bytes', async () => {
      await expect(addContact({
        alias: 'Test',
        deviceId: new Uint8Array(32),
        genesisHash: new Uint8Array(16),
        signingPublicKey: new Uint8Array(64),
      })).rejects.toThrow(/genesisHash must be 32 bytes/);
    });

    test('throws when signingPublicKey is not 64 bytes', async () => {
      await expect(addContact({
        alias: 'Test',
        deviceId: new Uint8Array(32),
        genesisHash: new Uint8Array(32),
        signingPublicKey: new Uint8Array(32),
      })).rejects.toThrow(/signingPublicKey must be 64 bytes/);
    });

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
      (appRouterInvokeBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await addContact({ alias: 'TestContact', deviceId, genesisHash, signingPublicKey });
      expect(result.accepted).toBe(true);
    });

    test('returns not accepted when response has empty alias', async () => {
      const deviceId = new Uint8Array(32).fill(1);
      const genesisHash = new Uint8Array(32).fill(2);
      const signingPublicKey = new Uint8Array(64).fill(3);

      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'contactAddResponse',
          value: new pb.ContactAddResponse({ alias: '' }),
        },
      });
      (appRouterInvokeBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await addContact({ alias: 'Test', deviceId, genesisHash, signingPublicKey });
      expect(result.accepted).toBe(false);
      expect(result.error).toBe('Empty response or failure');
    });

    test('returns error on error envelope', async () => {
      const deviceId = new Uint8Array(32).fill(1);
      const genesisHash = new Uint8Array(32).fill(2);
      const signingPublicKey = new Uint8Array(64).fill(3);

      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'error', value: new pb.Error({ code: 9, message: 'duplicate' }) },
      });
      (appRouterInvokeBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await addContact({ alias: 'Test', deviceId, genesisHash, signingPublicKey });
      expect(result.accepted).toBe(false);
      expect(result.error).toMatch(/duplicate/);
    });

    test('returns error when bridge throws', async () => {
      const deviceId = new Uint8Array(32).fill(1);
      const genesisHash = new Uint8Array(32).fill(2);
      const signingPublicKey = new Uint8Array(64).fill(3);

      (appRouterInvokeBin as jest.Mock).mockRejectedValue(new Error('bridge fail'));

      const result = await addContact({ alias: 'Test', deviceId, genesisHash, signingPublicKey });
      expect(result.accepted).toBe(false);
      expect(result.error).toBe('bridge fail');
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
