jest.mock('../WebViewBridge', () => {
  const actual = jest.requireActual('../WebViewBridge');
  return {
    ...actual,
    appRouterInvokeBin: jest.fn(),
  };
});

jest.mock('../../services/qr/contactQrService', () => ({
  encodeContactQrV3Payload: jest.fn(),
}));

import * as pb from '../../proto/dsm_app_pb';
import { addContact } from '../contacts';
import { appRouterInvokeBin } from '../WebViewBridge';
import { encodeContactQrV3Payload } from '../../services/qr/contactQrService';

function frameEnvelope(envelope: pb.Envelope): Uint8Array {
  const bytes = envelope.toBinary();
  const framed = new Uint8Array(1 + bytes.length);
  framed[0] = 0x03;
  framed.set(bytes, 1);
  return framed;
}

describe('contacts.addManual', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('manual add routes through contacts.addManual without TS QR authoring', async () => {
    const deviceId = new Uint8Array(32).fill(1);
    const genesisHash = new Uint8Array(32).fill(2);
    const signingPublicKey = new Uint8Array(64).fill(3);

    (appRouterInvokeBin as jest.Mock).mockImplementation(async (method: string, args: Uint8Array) => {
      expect(method).toBe('contacts.addManual');
      const argPack = pb.ArgPack.fromBinary(args);
      const req = pb.ContactManualAddRequest.fromBinary(argPack.body);
      expect(req.alias).toBe('Bob');
      expect(req.deviceId).toEqual(deviceId);
      expect(req.genesisHash).toEqual(genesisHash);
      expect(req.signingPublicKey).toEqual(signingPublicKey);
      return frameEnvelope(new pb.Envelope({
        version: 3,
        payload: {
          case: 'contactAddResponse',
          value: new pb.ContactAddResponse({
            alias: 'Bob',
            deviceId,
          }),
        },
      }));
    });

    const result = await addContact({ alias: 'Bob', deviceId, genesisHash, signingPublicKey });
    expect(result).toEqual({ accepted: true, contactId: undefined, error: undefined });
    expect(encodeContactQrV3Payload).not.toHaveBeenCalled();
  });
});
