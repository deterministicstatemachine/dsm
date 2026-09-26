// SPDX-License-Identifier: MIT OR Apache-2.0

jest.mock('../WebViewBridge', () => {
  const actual = jest.requireActual('../WebViewBridge');
  return {
    ...actual,
    routerInvokeBin: jest.fn(),
    routerQueryBin: jest.fn(),
  };
});

import { encodeBase32Crockford } from '../../utils/textId';
import * as pb from '../../proto/dsm_app_pb';
import { addContact, getContactCode, readContactCode } from '../contacts';
import { routerInvokeBin, routerQueryBin } from '../WebViewBridge';

function frameEnvelope(payload: pb.Envelope['payload']): Uint8Array {
  const bytes = new pb.Envelope({ version: 3, payload }).toBinary();
  const framed = new Uint8Array(1 + bytes.length);
  framed[0] = 0x03;
  framed.set(bytes, 1);
  return framed;
}

function rustError(message: string): Uint8Array {
  return frameEnvelope({ case: 'error', value: new pb.Error({ code: 400, message }) });
}

const deviceId = new Uint8Array(32).fill(1);
const genesisHash = new Uint8Array(32).fill(2);
const signingPublicKey = new Uint8Array(64).fill(3);

describe('contacts.addManual', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('the add sends the card and alias to Rust and answers the contact Rust added', async () => {
    (routerInvokeBin as jest.Mock).mockImplementation(async (method: string, args: Uint8Array) => {
      expect(method).toBe('contacts.addManual');
      const argPack = pb.ArgPack.fromBinary(args);
      const req = pb.ContactManualAddRequest.fromBinary(argPack.body);
      expect(req.alias).toBe('');
      expect(req.deviceId).toEqual(deviceId);
      expect(req.genesisHash).toEqual(genesisHash);
      expect(req.signingPublicKey).toEqual(signingPublicKey);
      return frameEnvelope({
        case: 'contactAddResponse',
        value: new pb.ContactAddResponse({ alias: '04080G20', deviceId }),
      });
    });

    // An empty alias is Rust's to fill: it names the contact by its device.
    const result = await addContact({ alias: '', deviceId, genesisHash, signingPublicKey });
    expect(result).toEqual({ accepted: true, contactId: encodeBase32Crockford(deviceId), alias: '04080G20' });
  });

  test('a refused add answers Rust’s reason as Rust worded it', async () => {
    (routerInvokeBin as jest.Mock).mockResolvedValue(
      rustError('the device\'s directory entry names another AK than the contact QR presents'),
    );

    const result = await addContact({ alias: 'Bob', deviceId, genesisHash, signingPublicKey });
    expect(result).toEqual({
      accepted: false,
      error: 'the device\'s directory entry names another AK than the contact QR presents',
    });
  });
});

describe('the contact code is Rust’s both ways', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('this device’s code is the text Rust rendered', async () => {
    (routerQueryBin as jest.Mock).mockImplementation(async (path: string, params?: Uint8Array) => {
      expect(path).toBe('identity.contact_code');
      expect(params).toBeUndefined();
      return frameEnvelope({
        case: 'appStateResponse',
        value: new pb.AppStateResponse({ key: 'contact_code', value: 'dsm:contact/v3:RENDERED' }),
      });
    });

    await expect(getContactCode()).resolves.toBe('dsm:contact/v3:RENDERED');
  });

  test('an answer without the code is refused, not rendered', async () => {
    (routerQueryBin as jest.Mock).mockResolvedValue(frameEnvelope({
      case: 'appStateResponse',
      value: new pb.AppStateResponse({ key: 'contact_code' }),
    }));

    await expect(getContactCode()).rejects.toThrow('STRICT');
  });

  test('a scanned code goes to Rust as it was read, and the card is the one Rust read', async () => {
    (routerQueryBin as jest.Mock).mockImplementation(async (path: string, params: Uint8Array) => {
      expect(path).toBe('contacts.readContactCode');
      const pack = pb.ArgPack.fromBinary(params);
      expect(pack.codec).toBe(pb.Codec.PROTO);
      expect(pb.QrScanResultPayload.fromBinary(pack.body).textUtf8).toBe('  dsm:contact/v3:SCANNED\n');
      return frameEnvelope({
        case: 'contactQrResponse',
        value: new pb.ContactQrV3({ deviceId, genesisHash, signingPublicKey, network: 'dsm-testnet' }),
      });
    });

    await expect(readContactCode('  dsm:contact/v3:SCANNED\n')).resolves.toEqual({
      deviceId,
      genesisHash,
      signingPublicKey,
      network: 'dsm-testnet',
      preferredAlias: undefined,
    });
  });

  test('Rust’s refusal of a code is answered as Rust worded it', async () => {
    (routerQueryBin as jest.Mock).mockResolvedValue(
      rustError('contacts.readContactCode: the contact is on network "other"; this device is on "dsm-testnet"'),
    );

    await expect(readContactCode('dsm:contact/v3:X')).rejects.toThrow(
      'contacts.readContactCode: the contact is on network "other"; this device is on "dsm-testnet"',
    );
  });

  test('a card without its identity or network is refused, not shown', async () => {
    (routerQueryBin as jest.Mock).mockResolvedValueOnce(frameEnvelope({
      case: 'contactQrResponse',
      value: new pb.ContactQrV3({ deviceId, genesisHash, network: 'dsm-testnet' }),
    }));
    await expect(readContactCode('dsm:contact/v3:X')).rejects.toThrow('STRICT');

    (routerQueryBin as jest.Mock).mockResolvedValueOnce(frameEnvelope({
      case: 'contactQrResponse',
      value: new pb.ContactQrV3({ deviceId, genesisHash, signingPublicKey }),
    }));
    await expect(readContactCode('dsm:contact/v3:X')).rejects.toThrow('STRICT');
  });
});
