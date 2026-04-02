jest.mock('../WebViewBridge', () => ({
  appRouterInvokeBin: jest.fn(),
}));

import * as pb from '../../proto/dsm_app_pb';
import { createCustomDlv } from '../dlv';
import { appRouterInvokeBin } from '../WebViewBridge';
import { encodeBase32Crockford } from '../../utils/textId';

function frameEnvelope(envelope: pb.Envelope): Uint8Array {
  const bytes = envelope.toBinary();
  const framed = new Uint8Array(1 + bytes.length);
  framed[0] = 0x03;
  framed.set(bytes, 1);
  return framed;
}

function makeValidDlvCreate(): pb.DlvCreateV3 {
  return new pb.DlvCreateV3({
    deviceId: new Uint8Array(32).fill(0x01) as any,
    policyDigest: new Uint8Array(32).fill(0x02) as any,
    precommit: new Uint8Array(32).fill(0x03) as any,
    vaultId: new Uint8Array(32).fill(0x04) as any,
  });
}

function encodeDlvToBase32(dlv: pb.DlvCreateV3): string {
  return encodeBase32Crockford(new Uint8Array(dlv.toBinary()));
}

describe('dlv.ts', () => {
  beforeEach(() => jest.clearAllMocks());

  describe('createCustomDlv', () => {
    test('returns success with vault id on appStateResponse', async () => {
      const dlv = makeValidDlvCreate();
      const lockB32 = encodeDlvToBase32(dlv);

      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'appStateResponse',
          value: new pb.AppStateResponse({ value: 'VAULT_ID_B32' }),
        },
      });
      (appRouterInvokeBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await createCustomDlv({ lock: lockB32 });
      expect(result.success).toBe(true);
      expect(result.id).toBe('VAULT_ID_B32');
    });

    test('uses empty string as id when appStateResponse.value is empty', async () => {
      const dlv = makeValidDlvCreate();
      const lockB32 = encodeDlvToBase32(dlv);

      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'appStateResponse',
          value: new pb.AppStateResponse({ value: '' }),
        },
      });
      (appRouterInvokeBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await createCustomDlv({ lock: lockB32 });
      expect(result.success).toBe(true);
      // `??` doesn't trigger on empty string — returns '' directly
      expect(result.id).toBe('');
    });

    test('falls back to vaultId encoding when appStateResponse.value is nullish', async () => {
      const dlv = makeValidDlvCreate();
      const lockB32 = encodeDlvToBase32(dlv);

      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'appStateResponse',
          value: new pb.AppStateResponse({}),
        },
      });
      (appRouterInvokeBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await createCustomDlv({ lock: lockB32 });
      expect(result.success).toBe(true);
      expect(typeof result.id).toBe('string');
      expect(result.id!.length).toBeGreaterThan(0);
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
      const dlv = makeValidDlvCreate();
      const lockB32 = encodeDlvToBase32(dlv);

      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'error', value: new pb.Error({ message: 'vault limit reached' }) },
      });
      (appRouterInvokeBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await createCustomDlv({ lock: lockB32 });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/vault limit reached/);
    });

    test('returns error on unexpected payload case', async () => {
      const dlv = makeValidDlvCreate();
      const lockB32 = encodeDlvToBase32(dlv);

      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'balancesListResponse', value: new pb.BalancesListResponse() },
      });
      (appRouterInvokeBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await createCustomDlv({ lock: lockB32 });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/Unexpected response payload/);
    });

    test('returns error when DlvCreateV3 has invalid deviceId length', async () => {
      const dlv = new pb.DlvCreateV3({
        deviceId: new Uint8Array(16).fill(0x01) as any,
        policyDigest: new Uint8Array(32).fill(0x02) as any,
        precommit: new Uint8Array(32).fill(0x03) as any,
        vaultId: new Uint8Array(32).fill(0x04) as any,
      });
      const lockB32 = encodeDlvToBase32(dlv);

      const result = await createCustomDlv({ lock: lockB32 });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/device_id must be 32 bytes/);
    });

    test('returns error when DlvCreateV3 has invalid policyDigest', async () => {
      const dlv = new pb.DlvCreateV3({
        deviceId: new Uint8Array(32).fill(0x01) as any,
        policyDigest: new Uint8Array(16).fill(0x02) as any,
        precommit: new Uint8Array(32).fill(0x03) as any,
        vaultId: new Uint8Array(32).fill(0x04) as any,
      });
      const lockB32 = encodeDlvToBase32(dlv);

      const result = await createCustomDlv({ lock: lockB32 });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/policy_digest must be 32 bytes/);
    });

    test('returns error when bridge throws', async () => {
      const dlv = makeValidDlvCreate();
      const lockB32 = encodeDlvToBase32(dlv);

      (appRouterInvokeBin as jest.Mock).mockRejectedValue(new Error('network fail'));

      const result = await createCustomDlv({ lock: lockB32 });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/network fail/);
    });
  });
});
