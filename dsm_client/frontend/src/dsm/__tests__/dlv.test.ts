jest.mock('../WebViewBridge', () => ({
  routerInvokeBin: jest.fn(),
}));

import * as pb from '../../proto/dsm_app_pb';
import { createCustomDlv } from '../dlv';
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
});
