jest.mock('../WebViewBridge', () => ({
  routerInvokeBin: jest.fn(),
}));

import * as pb from '../../proto/dsm_app_pb';
import { createCustomDlv, buildDlvInstantiateBytes } from '../dlv';
import { routerInvokeBin } from '../WebViewBridge';
import { encodeBase32Crockford } from '../../utils/textId';

function frameEnvelope(envelope: pb.Envelope): Uint8Array {
  const bytes = envelope.toBinary();
  const framed = new Uint8Array(1 + bytes.length);
  framed[0] = 0x03;
  framed.set(bytes, 1);
  return framed;
}

function makeValidInstantiate(): pb.DlvInstantiateV1 {
  return new pb.DlvInstantiateV1({
    spec: new pb.DlvSpecV1({
      policyDigest: new Uint8Array(32).fill(0x02) as any,
      contentDigest: new Uint8Array(32).fill(0x03) as any,
      fulfillmentDigest: new Uint8Array(32).fill(0x04) as any,
      intendedRecipient: new Uint8Array() as any,
      fulfillmentBytes: new Uint8Array([0xaa, 0xbb]) as any,
      content: new Uint8Array([0xcc]) as any,
    }),
    creatorPublicKey: new Uint8Array(64).fill(0x11) as any,
    tokenId: new Uint8Array() as any,
    lockedAmountU128: new Uint8Array(16) as any,
    signature: new Uint8Array(64).fill(0x22) as any,
  });
}

function encodeInstantiateToBase32(req: pb.DlvInstantiateV1): string {
  return encodeBase32Crockford(new Uint8Array(req.toBinary()));
}

describe('dlv.ts', () => {
  beforeEach(() => jest.clearAllMocks());

  describe('createCustomDlv', () => {
    test('returns success with vault id on appStateResponse', async () => {
      const req = makeValidInstantiate();
      const lockB32 = encodeInstantiateToBase32(req);

      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'appStateResponse',
          value: new pb.AppStateResponse({ value: 'VAULT_ID_B32' }),
        },
      });
      (routerInvokeBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await createCustomDlv({ lock: lockB32 });
      expect(result.success).toBe(true);
      expect(result.id).toBe('VAULT_ID_B32');
    });

    test('returns empty id when appStateResponse.value is empty', async () => {
      const req = makeValidInstantiate();
      const lockB32 = encodeInstantiateToBase32(req);

      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'appStateResponse',
          value: new pb.AppStateResponse({ value: '' }),
        },
      });
      (routerInvokeBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await createCustomDlv({ lock: lockB32 });
      expect(result.success).toBe(true);
      expect(result.id).toBe('');
    });

    test('returns empty id when appStateResponse.value is unset', async () => {
      const req = makeValidInstantiate();
      const lockB32 = encodeInstantiateToBase32(req);

      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'appStateResponse',
          value: new pb.AppStateResponse({}),
        },
      });
      (routerInvokeBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await createCustomDlv({ lock: lockB32 });
      expect(result.success).toBe(true);
      expect(result.id).toBe('');
    });

    test('returns error for empty lock string', async () => {
      const result = await createCustomDlv({ lock: '' });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/lock.*required/i);
    });

    test('returns error for whitespace-only lock', async () => {
      const result = await createCustomDlv({ lock: '   ' });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/lock.*required/i);
    });

    test('returns error on error envelope', async () => {
      const req = makeValidInstantiate();
      const lockB32 = encodeInstantiateToBase32(req);

      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'error', value: new pb.Error({ message: 'vault limit reached' }) },
      });
      (routerInvokeBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await createCustomDlv({ lock: lockB32 });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/vault limit reached/);
    });

    test('returns error on unexpected payload case', async () => {
      const req = makeValidInstantiate();
      const lockB32 = encodeInstantiateToBase32(req);

      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'balancesListResponse', value: new pb.BalancesListResponse() },
      });
      (routerInvokeBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await createCustomDlv({ lock: lockB32 });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/Unexpected response payload/);
    });

    test('returns error when DlvSpecV1.policy_digest is wrong length', async () => {
      const req = new pb.DlvInstantiateV1({
        spec: new pb.DlvSpecV1({
          policyDigest: new Uint8Array(16).fill(0x02) as any,
          contentDigest: new Uint8Array(32).fill(0x03) as any,
          fulfillmentDigest: new Uint8Array(32).fill(0x04) as any,
        }),
        creatorPublicKey: new Uint8Array(64).fill(0x11) as any,
        signature: new Uint8Array(64).fill(0x22) as any,
      });
      const lockB32 = encodeInstantiateToBase32(req);

      const result = await createCustomDlv({ lock: lockB32 });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/policy_digest must be 32 bytes/);
    });

    test('returns error when creator_public_key is empty', async () => {
      const req = new pb.DlvInstantiateV1({
        spec: new pb.DlvSpecV1({
          policyDigest: new Uint8Array(32).fill(0x02) as any,
          contentDigest: new Uint8Array(32).fill(0x03) as any,
          fulfillmentDigest: new Uint8Array(32).fill(0x04) as any,
        }),
        creatorPublicKey: new Uint8Array() as any,
        signature: new Uint8Array(64).fill(0x22) as any,
      });
      const lockB32 = encodeInstantiateToBase32(req);

      const result = await createCustomDlv({ lock: lockB32 });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/creator_public_key.*required/);
    });

    test('returns error when bridge throws', async () => {
      const req = makeValidInstantiate();
      const lockB32 = encodeInstantiateToBase32(req);

      (routerInvokeBin as jest.Mock).mockRejectedValue(new Error('network fail'));

      const result = await createCustomDlv({ lock: lockB32 });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/network fail/);
    });
  });

  describe('buildDlvInstantiateBytes', () => {
    // Digests are now auto-computed by the helper, so the base test
    // input deliberately omits them.  Each test that wants to exercise
    // the caller-supplied path computes the correct digest from the
    // BLAKE3 helpers and passes it through.
    const baseInput = {
      policyDigest: new Uint8Array(32).fill(0x02),
      content: new Uint8Array([0xaa, 0xbb]),
      fulfillmentBytes: new Uint8Array([0xcc, 0xdd]),
      creatorPublicKey: new Uint8Array(64).fill(0x11),
      signature: new Uint8Array(64).fill(0x22),
    };

    test('auto-computes contentDigest and fulfillmentDigest when omitted', async () => {
      const { dlvContentDigest, dlvFulfillmentDigest } = await import('../../utils/blake3');
      const bytes = buildDlvInstantiateBytes(baseInput);
      const req = pb.DlvInstantiateV1.fromBinary(bytes);
      expect(req.spec).toBeDefined();
      expect(Array.from(req.spec!.contentDigest)).toEqual(
        Array.from(dlvContentDigest(baseInput.content)),
      );
      expect(Array.from(req.spec!.fulfillmentDigest)).toEqual(
        Array.from(dlvFulfillmentDigest(baseInput.fulfillmentBytes)),
      );
      // No lock supplied → all-zero 16 bytes.
      expect(req.lockedAmountU128.length).toBe(16);
      expect(req.lockedAmountU128.every((b) => b === 0)).toBe(true);
      // No token_id supplied → empty bytes.
      expect(req.tokenId.length).toBe(0);
    });

    test('accepts a matching caller-supplied digest pair', async () => {
      const { dlvContentDigest, dlvFulfillmentDigest } = await import('../../utils/blake3');
      const bytes = buildDlvInstantiateBytes({
        ...baseInput,
        contentDigest: dlvContentDigest(baseInput.content),
        fulfillmentDigest: dlvFulfillmentDigest(baseInput.fulfillmentBytes),
      });
      // Round-trip via the proto.  Content + fulfillment bytes survive intact.
      const req = pb.DlvInstantiateV1.fromBinary(bytes);
      expect(Array.from(req.spec!.content)).toEqual(Array.from(baseInput.content));
      expect(Array.from(req.spec!.fulfillmentBytes)).toEqual(
        Array.from(baseInput.fulfillmentBytes),
      );
    });

    test('rejects a caller-supplied contentDigest that does not match content', () => {
      expect(() =>
        buildDlvInstantiateBytes({
          ...baseInput,
          contentDigest: new Uint8Array(32).fill(0x99),
        }),
      ).toThrow(/contentDigest does not match BLAKE3/);
    });

    test('rejects a caller-supplied fulfillmentDigest that does not match', () => {
      expect(() =>
        buildDlvInstantiateBytes({
          ...baseInput,
          fulfillmentDigest: new Uint8Array(32).fill(0x99),
        }),
      ).toThrow(/fulfillmentDigest does not match BLAKE3/);
    });

    test('encodes lockedAmount big-endian u128', () => {
      const bytes = buildDlvInstantiateBytes({
        ...baseInput,
        tokenId: 'FOOBAR',
        lockedAmount: 0x0102_0304_0506_0708n,
      });
      const req = pb.DlvInstantiateV1.fromBinary(bytes);
      expect(new TextDecoder().decode(req.tokenId)).toBe('FOOBAR');
      // Big-endian encoding of 0x0102030405060708 in 16 bytes.
      const expected = new Uint8Array(16);
      expected[8] = 0x01;
      expected[9] = 0x02;
      expected[10] = 0x03;
      expected[11] = 0x04;
      expected[12] = 0x05;
      expected[13] = 0x06;
      expected[14] = 0x07;
      expected[15] = 0x08;
      expect(Array.from(req.lockedAmountU128)).toEqual(Array.from(expected));
    });

    test.each([
      ['policyDigest', { policyDigest: new Uint8Array(16) }, /policyDigest must be 32 bytes/],
      ['contentDigest', { contentDigest: new Uint8Array(16) }, /contentDigest must be 32 bytes/],
      [
        'fulfillmentDigest',
        { fulfillmentDigest: new Uint8Array(16) },
        /fulfillmentDigest must be 32 bytes/,
      ],
      ['creatorPublicKey', { creatorPublicKey: new Uint8Array(0) }, /creatorPublicKey is required/],
      ['signature', { signature: new Uint8Array(0) }, /signature is required/],
    ])('rejects invalid %s', (_label, override, pattern) => {
      expect(() => buildDlvInstantiateBytes({ ...baseInput, ...override })).toThrow(
        pattern as RegExp,
      );
    });
  });
});
