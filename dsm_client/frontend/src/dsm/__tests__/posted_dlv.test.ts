jest.mock('../WebViewBridge', () => ({
  routerInvokeBin: jest.fn(),
  routerQueryBin: jest.fn(),
}));

import * as pb from '../../proto/dsm_app_pb';
import { listPostedDlvs, syncPostedDlvs } from '../posted_dlv';
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

describe('posted_dlv.ts', () => {
  beforeEach(() => jest.clearAllMocks());

  describe('listPostedDlvs', () => {
    test('parses newline-separated rows into typed summaries', async () => {
      (routerQueryBin as jest.Mock).mockResolvedValue(
        appStateEnvelope('VAULT1B32 PK1B32\nVAULT2B32 PK2B32'),
      );
      const out = await listPostedDlvs();
      expect(out.success).toBe(true);
      expect(out.vaults).toEqual([
        { dlvIdBase32: 'VAULT1B32', creatorPublicKeyBase32: 'PK1B32' },
        { dlvIdBase32: 'VAULT2B32', creatorPublicKeyBase32: 'PK2B32' },
      ]);
    });

    test('returns an empty list for empty AppStateResponse.value', async () => {
      (routerQueryBin as jest.Mock).mockResolvedValue(appStateEnvelope(''));
      const out = await listPostedDlvs();
      expect(out.success).toBe(true);
      expect(out.vaults).toEqual([]);
    });

    test('surfaces error envelopes as success=false', async () => {
      (routerQueryBin as jest.Mock).mockResolvedValue(errorEnvelope('boom'));
      const out = await listPostedDlvs();
      expect(out.success).toBe(false);
      expect(out.error).toMatch(/boom/);
    });

    test('handles thrown bridge errors', async () => {
      (routerQueryBin as jest.Mock).mockRejectedValue(new Error('network down'));
      const out = await listPostedDlvs();
      expect(out.success).toBe(false);
      expect(out.error).toMatch(/network down/);
    });

    test('rejects unexpected payload cases', async () => {
      (routerQueryBin as jest.Mock).mockResolvedValue(
        frameEnvelope(
          new pb.Envelope({
            version: 3,
            payload: {
              case: 'balancesListResponse',
              value: new pb.BalancesListResponse(),
            },
          }),
        ),
      );
      const out = await listPostedDlvs();
      expect(out.success).toBe(false);
      expect(out.error).toMatch(/unexpected payload/);
    });
  });

  describe('syncPostedDlvs', () => {
    test('returns the newly mirrored vault_ids on success', async () => {
      (routerInvokeBin as jest.Mock).mockResolvedValue(
        appStateEnvelope('NEWVAULT1\nNEWVAULT2\nNEWVAULT3'),
      );
      const out = await syncPostedDlvs();
      expect(out.success).toBe(true);
      expect(out.newlyMirroredBase32).toEqual(['NEWVAULT1', 'NEWVAULT2', 'NEWVAULT3']);
    });

    test('returns an empty list when nothing new was mirrored', async () => {
      (routerInvokeBin as jest.Mock).mockResolvedValue(appStateEnvelope(''));
      const out = await syncPostedDlvs();
      expect(out.success).toBe(true);
      expect(out.newlyMirroredBase32).toEqual([]);
    });

    test('surfaces error envelopes', async () => {
      (routerInvokeBin as jest.Mock).mockResolvedValue(errorEnvelope('mirror failed'));
      const out = await syncPostedDlvs();
      expect(out.success).toBe(false);
      expect(out.error).toMatch(/mirror failed/);
    });

    test('handles thrown bridge errors', async () => {
      (routerInvokeBin as jest.Mock).mockRejectedValue(new Error('bridge dead'));
      const out = await syncPostedDlvs();
      expect(out.success).toBe(false);
      expect(out.error).toMatch(/bridge dead/);
    });
  });
});
