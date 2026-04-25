jest.mock('../WebViewBridge', () => ({
  routerInvokeBin: jest.fn(),
  routerQueryBin: jest.fn(),
}));

import * as pb from '../../proto/dsm_app_pb';
import {
  computeExternalCommitment,
  publishExternalCommitment,
  isExternalCommitmentVisible,
  unlockVaultRouted,
} from '../route_commit';
import { routerInvokeBin, routerQueryBin } from '../WebViewBridge';

function frameEnvelope(envelope: pb.Envelope): Uint8Array {
  const bytes = envelope.toBinary();
  const framed = new Uint8Array(1 + bytes.length);
  framed[0] = 0x03;
  framed.set(bytes, 1);
  return framed;
}

function appStateEnvelope(value: string): Uint8Array {
  return frameEnvelope(
    new pb.Envelope({
      version: 3,
      payload: {
        case: 'appStateResponse',
        value: new pb.AppStateResponse({ value }),
      },
    }),
  );
}

function errorEnvelope(message: string): Uint8Array {
  return frameEnvelope(
    new pb.Envelope({
      version: 3,
      payload: { case: 'error', value: new pb.Error({ message }) },
    }),
  );
}

describe('route_commit.ts', () => {
  beforeEach(() => jest.clearAllMocks());

  describe('computeExternalCommitment', () => {
    test('returns the Base32 X on success', async () => {
      (routerQueryBin as jest.Mock).mockResolvedValue(appStateEnvelope('SOMEX_B32'));
      const result = await computeExternalCommitment(new Uint8Array([1, 2, 3]));
      expect(result.success).toBe(true);
      expect(result.xBase32).toBe('SOMEX_B32');
      expect(routerQueryBin).toHaveBeenCalledWith(
        'route.computeExternalCommitment',
        expect.any(Uint8Array),
      );
    });

    test('rejects empty input without round-tripping', async () => {
      const result = await computeExternalCommitment(new Uint8Array(0));
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/required/i);
      expect(routerQueryBin).not.toHaveBeenCalled();
    });

    test('surfaces error envelopes', async () => {
      (routerQueryBin as jest.Mock).mockResolvedValue(errorEnvelope('decode failed'));
      const result = await computeExternalCommitment(new Uint8Array([0xFF]));
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/decode failed/);
    });

    test('handles bridge throws', async () => {
      (routerQueryBin as jest.Mock).mockRejectedValue(new Error('bridge dead'));
      const result = await computeExternalCommitment(new Uint8Array([1]));
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/bridge dead/);
    });
  });

  describe('publishExternalCommitment', () => {
    const validX = new Uint8Array(32).fill(0xA5);
    const validPk = new Uint8Array(64).fill(0x11);

    test('serialises ExternalCommitmentV1 and surfaces the X back on success', async () => {
      (routerInvokeBin as jest.Mock).mockResolvedValue(appStateEnvelope('XBASE32'));
      const result = await publishExternalCommitment({
        x: validX,
        publisherPublicKey: validPk,
        label: 'route-A',
      });
      expect(result.success).toBe(true);
      expect(result.xBase32).toBe('XBASE32');
      // Verify the bridge call carries an ExternalCommitmentV1 inside an
      // ArgPack — round-trip by decoding.
      const [route, body] = (routerInvokeBin as jest.Mock).mock.calls[0];
      expect(route).toBe('route.publishExternalCommitment');
      const argPack = pb.ArgPack.fromBinary(body);
      const anchor = pb.ExternalCommitmentV1.fromBinary(argPack.body);
      expect(Array.from(anchor.x)).toEqual(Array.from(validX));
      expect(anchor.label).toBe('route-A');
    });

    test('rejects wrong-length x', async () => {
      const result = await publishExternalCommitment({
        x: new Uint8Array(16),
        publisherPublicKey: validPk,
      });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/32 bytes/);
      expect(routerInvokeBin).not.toHaveBeenCalled();
    });

    test('rejects empty publisher_public_key', async () => {
      const result = await publishExternalCommitment({
        x: validX,
        publisherPublicKey: new Uint8Array(0),
      });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/publisherPublicKey/i);
    });

    test('omitted label defaults to empty string', async () => {
      (routerInvokeBin as jest.Mock).mockResolvedValue(appStateEnvelope('OK'));
      await publishExternalCommitment({ x: validX, publisherPublicKey: validPk });
      const [, body] = (routerInvokeBin as jest.Mock).mock.calls[0];
      const argPack = pb.ArgPack.fromBinary(body);
      const anchor = pb.ExternalCommitmentV1.fromBinary(argPack.body);
      expect(anchor.label).toBe('');
    });

    test('surfaces error envelopes', async () => {
      (routerInvokeBin as jest.Mock).mockResolvedValue(errorEnvelope('storage down'));
      const result = await publishExternalCommitment({
        x: validX,
        publisherPublicKey: validPk,
      });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/storage down/);
    });
  });

  describe('isExternalCommitmentVisible', () => {
    const validX = new Uint8Array(32).fill(0x42);

    test('returns visible=true when handler reports "true"', async () => {
      (routerQueryBin as jest.Mock).mockResolvedValue(appStateEnvelope('true'));
      const result = await isExternalCommitmentVisible(validX);
      expect(result.success).toBe(true);
      expect(result.visible).toBe(true);
    });

    test('returns visible=false when handler reports "false"', async () => {
      (routerQueryBin as jest.Mock).mockResolvedValue(appStateEnvelope('false'));
      const result = await isExternalCommitmentVisible(validX);
      expect(result.success).toBe(true);
      expect(result.visible).toBe(false);
    });

    test('rejects unexpected value strings', async () => {
      (routerQueryBin as jest.Mock).mockResolvedValue(appStateEnvelope('maybe'));
      const result = await isExternalCommitmentVisible(validX);
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/unexpected value/);
    });

    test('rejects wrong-length x', async () => {
      const result = await isExternalCommitmentVisible(new Uint8Array(31));
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/32 bytes/);
      expect(routerQueryBin).not.toHaveBeenCalled();
    });

    test('surfaces storage errors', async () => {
      (routerQueryBin as jest.Mock).mockResolvedValue(errorEnvelope('storage timeout'));
      const result = await isExternalCommitmentVisible(validX);
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/storage timeout/);
    });
  });

  describe('unlockVaultRouted', () => {
    const vaultId = new Uint8Array(32).fill(0x01);
    const deviceId = new Uint8Array(32).fill(0x02);
    const rcBytes = new Uint8Array([0xAA, 0xBB, 0xCC]);

    test('serialises DlvUnlockRoutedV1 and returns vaultIdBase32 on success', async () => {
      (routerInvokeBin as jest.Mock).mockResolvedValue(appStateEnvelope('VAULTID_B32'));
      const result = await unlockVaultRouted({
        vaultId,
        deviceId,
        routeCommitBytes: rcBytes,
      });
      expect(result.success).toBe(true);
      expect(result.vaultIdBase32).toBe('VAULTID_B32');
      const [route, body] = (routerInvokeBin as jest.Mock).mock.calls[0];
      expect(route).toBe('dlv.unlockRouted');
      const argPack = pb.ArgPack.fromBinary(body);
      const req = pb.DlvUnlockRoutedV1.fromBinary(argPack.body);
      expect(Array.from(req.vaultId)).toEqual(Array.from(vaultId));
      expect(Array.from(req.deviceId)).toEqual(Array.from(deviceId));
      expect(Array.from(req.routeCommitBytes)).toEqual(Array.from(rcBytes));
    });

    test('rejects missing vaultId', async () => {
      const result = await unlockVaultRouted({
        vaultId: new Uint8Array(16),
        deviceId,
        routeCommitBytes: rcBytes,
      });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/vaultId.*32 bytes/);
    });

    test('rejects missing deviceId', async () => {
      const result = await unlockVaultRouted({
        vaultId,
        deviceId: new Uint8Array(8),
        routeCommitBytes: rcBytes,
      });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/deviceId.*32 bytes/);
    });

    test('rejects empty routeCommitBytes', async () => {
      const result = await unlockVaultRouted({
        vaultId,
        deviceId,
        routeCommitBytes: new Uint8Array(0),
      });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/routeCommitBytes/);
    });

    test('surfaces eligibility-rejection error envelopes verbatim', async () => {
      // Mirrors the chunk #4/#5 typed errors the SDK gate produces.
      (routerInvokeBin as jest.Mock).mockResolvedValue(
        errorEnvelope(
          'dlv.unlockRouted: route-commit eligibility rejected: InvalidInitiatorSignature',
        ),
      );
      const result = await unlockVaultRouted({
        vaultId,
        deviceId,
        routeCommitBytes: rcBytes,
      });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/InvalidInitiatorSignature/);
    });
  });
});
