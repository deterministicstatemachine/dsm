jest.mock('../WebViewBridge', () => ({
  routerInvokeBin: jest.fn(),
  routerQueryBin: jest.fn(),
}));

import * as pb from '../../proto/dsm_app_pb';
import {
  signRouteCommit,
  computeExternalCommitment,
  publishExternalCommitment,
  isExternalCommitmentVisible,
  unlockVaultRouted,
  publishRoutingAdvertisement,
  listAdvertisementsForPair,
  syncVaultsForPair,
  findAndBindBestPath,
} from '../route_commit';
import { routerInvokeBin, routerQueryBin } from '../WebViewBridge';
import { encodeBase32Crockford } from '../../utils/textId';

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

  describe('signRouteCommit', () => {
    test('returns the Base32 signed RouteCommit on success', async () => {
      (routerInvokeBin as jest.Mock).mockResolvedValue(
        appStateEnvelope('SIGNED_RC_B32'),
      );
      const result = await signRouteCommit(new Uint8Array([1, 2, 3]));
      expect(result.success).toBe(true);
      expect(result.signedRouteCommitBase32).toBe('SIGNED_RC_B32');
      expect(routerInvokeBin).toHaveBeenCalledWith(
        'route.signRouteCommit',
        expect.any(Uint8Array),
      );
    });

    test('rejects empty input without round-tripping', async () => {
      const result = await signRouteCommit(new Uint8Array(0));
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/required/i);
      expect(routerInvokeBin).not.toHaveBeenCalled();
    });

    test('surfaces signing-error envelopes verbatim', async () => {
      (routerInvokeBin as jest.Mock).mockResolvedValue(
        errorEnvelope('route.signRouteCommit: wallet signing public key is empty'),
      );
      const result = await signRouteCommit(new Uint8Array([0xAA]));
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/wallet signing public key is empty/);
    });

    test('handles bridge throws', async () => {
      (routerInvokeBin as jest.Mock).mockRejectedValue(new Error('bridge dead'));
      const result = await signRouteCommit(new Uint8Array([1]));
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/bridge dead/);
    });
  });

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

  // ───────────────────────────────────────────────────────────────────
  // Track C.3 — trade-flow helpers
  // ───────────────────────────────────────────────────────────────────

  describe('publishRoutingAdvertisement', () => {
    const validInput = {
      vaultId: new Uint8Array(32).fill(0x77),
      tokenA: new TextEncoder().encode('AAA'),
      tokenB: new TextEncoder().encode('BBB'),
      reserveA: 1_000_000n,
      reserveB: 2_000_000n,
      feeBps: 30,
      unlockSpecDigest: new Uint8Array(32).fill(0x88),
      unlockSpecKey: 'defi/spec/test',
      ownerPublicKey: new Uint8Array(64).fill(0x11),
      vaultProtoBytes: new Uint8Array([0xCA, 0xFE, 0xBA, 0xBE]),
    };

    test('round-trips a typed PublishRoutingAdvertisementRequest', async () => {
      (routerInvokeBin as jest.Mock).mockResolvedValue(
        appStateEnvelope(encodeBase32Crockford(validInput.vaultId)),
      );
      const result = await publishRoutingAdvertisement(validInput);
      expect(result.success).toBe(true);
      const [route, body] = (routerInvokeBin as jest.Mock).mock.calls[0];
      expect(route).toBe('route.publishRoutingAdvertisement');
      const argPack = pb.ArgPack.fromBinary(body);
      const req = pb.PublishRoutingAdvertisementRequest.fromBinary(argPack.body);
      expect(Array.from(req.vaultId)).toEqual(Array.from(validInput.vaultId));
      expect(req.feeBps).toBe(30);
      expect(req.reserveAU128.length).toBe(16);
    });

    test('rejects wrong-length vaultId', async () => {
      const result = await publishRoutingAdvertisement({
        ...validInput,
        vaultId: new Uint8Array(16),
      });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/32 bytes/);
    });

    test('rejects empty owner public key', async () => {
      const result = await publishRoutingAdvertisement({
        ...validInput,
        ownerPublicKey: new Uint8Array(0),
      });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/ownerPublicKey/i);
    });

    test('rejects wrong-length unlockSpecDigest', async () => {
      const result = await publishRoutingAdvertisement({
        ...validInput,
        unlockSpecDigest: new Uint8Array(16),
      });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/32 bytes/);
    });

    test('rejects empty vaultProtoBytes', async () => {
      const result = await publishRoutingAdvertisement({
        ...validInput,
        vaultProtoBytes: new Uint8Array(0),
      });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/vaultProtoBytes/);
    });
  });

  describe('listAdvertisementsForPair', () => {
    const tokenA = new TextEncoder().encode('AAA');
    const tokenB = new TextEncoder().encode('BBB');

    test('decodes newline-separated Base32 advertisement protos', async () => {
      const ad = new pb.RoutingVaultAdvertisementV1({
        version: 1,
        vaultId: new Uint8Array(32).fill(0x55) as any,
        tokenA: tokenA as any,
        tokenB: tokenB as any,
        reserveAU128: new Uint8Array(16) as any,
        reserveBU128: new Uint8Array(16) as any,
        feeBps: 30,
        unlockSpecDigest: new Uint8Array(32) as any,
        unlockSpecKey: 'defi/spec/test',
        vaultProtoKey: new Uint8Array(0) as any,
        vaultProtoDigest: new Uint8Array(32) as any,
        ownerPublicKey: new Uint8Array(64).fill(0x11) as any,
        lifecycleState: 'active',
        updatedStateNumber: 7n,
      });
      const adBase32 = encodeBase32Crockford(new Uint8Array(ad.toBinary()));
      (routerQueryBin as jest.Mock).mockResolvedValue(appStateEnvelope(adBase32));
      const result = await listAdvertisementsForPair({ tokenA, tokenB });
      expect(result.success).toBe(true);
      expect(result.advertisements?.length).toBe(1);
      const summary = result.advertisements?.[0];
      expect(summary?.feeBps).toBe(30);
      expect(summary?.stateNumber).toBe(7n);
      expect(Array.from(summary?.tokenA ?? [])).toEqual(Array.from(tokenA));
    });

    test('returns empty list on empty value', async () => {
      (routerQueryBin as jest.Mock).mockResolvedValue(appStateEnvelope(''));
      const result = await listAdvertisementsForPair({ tokenA, tokenB });
      expect(result.success).toBe(true);
      expect(result.advertisements).toEqual([]);
    });

    test('surfaces error envelopes', async () => {
      (routerQueryBin as jest.Mock).mockResolvedValue(errorEnvelope('storage down'));
      const result = await listAdvertisementsForPair({ tokenA, tokenB });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/storage down/);
    });
  });

  describe('syncVaultsForPair', () => {
    const tokenA = new TextEncoder().encode('AAA');
    const tokenB = new TextEncoder().encode('BBB');

    test('returns newly mirrored vault_ids on success', async () => {
      (routerInvokeBin as jest.Mock).mockResolvedValue(
        appStateEnvelope('VAULTID_1\nVAULTID_2'),
      );
      const result = await syncVaultsForPair({ tokenA, tokenB });
      expect(result.success).toBe(true);
      expect(result.newlyMirroredBase32).toEqual(['VAULTID_1', 'VAULTID_2']);
    });

    test('returns empty list when nothing was newly mirrored', async () => {
      (routerInvokeBin as jest.Mock).mockResolvedValue(appStateEnvelope(''));
      const result = await syncVaultsForPair({ tokenA, tokenB });
      expect(result.success).toBe(true);
      expect(result.newlyMirroredBase32).toEqual([]);
    });

    test('surfaces bridge errors', async () => {
      (routerInvokeBin as jest.Mock).mockRejectedValue(new Error('bridge dead'));
      const result = await syncVaultsForPair({ tokenA, tokenB });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/bridge dead/);
    });
  });

  describe('findAndBindBestPath', () => {
    const inputToken = new TextEncoder().encode('AAA');
    const outputToken = new TextEncoder().encode('BBB');
    const nonce = new Uint8Array(32).fill(0xDD);

    test('decodes Base32 unsigned RouteCommit on success', async () => {
      const fakeUnsignedBytes = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
      (routerInvokeBin as jest.Mock).mockResolvedValue(
        appStateEnvelope(encodeBase32Crockford(fakeUnsignedBytes)),
      );
      const result = await findAndBindBestPath({
        inputToken,
        outputToken,
        inputAmount: 10_000n,
        nonce,
      });
      expect(result.success).toBe(true);
      expect(Array.from(result.unsignedRouteCommitBytes ?? [])).toEqual(
        Array.from(fakeUnsignedBytes),
      );
    });

    test('round-trips trade params through the FindAndBindRouteRequest proto', async () => {
      (routerInvokeBin as jest.Mock).mockResolvedValue(
        appStateEnvelope(encodeBase32Crockford(new Uint8Array([0xAA]))),
      );
      await findAndBindBestPath({
        inputToken,
        outputToken,
        inputAmount: 0x0102_0304n,
        nonce,
        maxHops: 3,
      });
      const [, body] = (routerInvokeBin as jest.Mock).mock.calls[0];
      const argPack = pb.ArgPack.fromBinary(body);
      const req = pb.FindAndBindRouteRequest.fromBinary(argPack.body);
      expect(Array.from(req.inputToken)).toEqual(Array.from(inputToken));
      expect(Array.from(req.outputToken)).toEqual(Array.from(outputToken));
      expect(req.maxHops).toBe(3);
      expect(req.nonce.length).toBe(32);
      // big-endian u128 of 0x01020304 in last 4 bytes.
      expect(req.inputAmountU128[12]).toBe(0x01);
      expect(req.inputAmountU128[15]).toBe(0x04);
    });

    test('rejects wrong-length nonce', async () => {
      const result = await findAndBindBestPath({
        inputToken,
        outputToken,
        inputAmount: 100n,
        nonce: new Uint8Array(16),
      });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/nonce.*32 bytes/);
    });

    test('surfaces NoPath errors verbatim', async () => {
      (routerInvokeBin as jest.Mock).mockResolvedValue(
        errorEnvelope('route.findAndBindBestPath: path search rejected: NoPath { .. }'),
      );
      const result = await findAndBindBestPath({
        inputToken,
        outputToken,
        inputAmount: 100n,
        nonce,
      });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/NoPath/);
    });
  });
});
