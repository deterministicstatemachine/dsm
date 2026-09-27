// SPDX-License-Identifier: MIT OR Apache-2.0

jest.mock('../WebViewBridge', () => ({
  routerQueryBin: jest.fn(),
}));

import * as pb from '../../proto/dsm_app_pb';
import { getStorageStatus } from '../storage';
import { routerQueryBin } from '../WebViewBridge';
import { encodeBase32Crockford } from '../../utils/textId';

function frameEnvelope(envelope: pb.Envelope): Uint8Array {
  const bytes = envelope.toBinary();
  const framed = new Uint8Array(1 + bytes.length);
  framed[0] = 0x03;
  framed.set(bytes, 1);
  return framed;
}

describe('storage.ts', () => {
  beforeEach(() => jest.clearAllMocks());

  // ── getStorageStatus ───────────────────────────────────────────────

  describe('getStorageStatus', () => {
    const text = (s: string) => new TextEncoder().encode(s);
    const setId = new Uint8Array(32).fill(0x11);
    const incarnation = (b: number) => new Uint8Array(32).fill(b);

    function statusEnvelope(members: pb.StorageMemberStatus[]): pb.Envelope {
      return new pb.Envelope({
        version: 3,
        payload: {
          case: 'storageStatusResponse',
          value: new pb.StorageStatusResponse({
            networkId: 'dsm-testnet',
            storageSetId: setId,
            members,
            completedSyncs: 7n,
            databaseBytes: 4096n,
          }),
        },
      });
    }

    const commit = new pb.ByteCommitV4({
      memberId: text('dsm-node-1'),
      cycleIndex: 12n,
      smtRoot: new Uint8Array(32).fill(0x21),
      bytesUsed: 2048n,
      parentDigest: new Uint8Array(32).fill(0x22),
    });
    const digest = new Uint8Array(32).fill(0x23);

    const stated = new pb.StorageMemberStatus({
      memberId: text('dsm-node-1'),
      registerIncarnationId: incarnation(0x31),
      endpoint: 'https://node-1:8080',
      answer: { case: 'latest', value: new pb.StorageMemberByteCommit({ commit, digest }) },
      answeredAs: text('dsm-node-1'),
    });
    const noCycle = new pb.StorageMemberStatus({
      memberId: text('dsm-node-2'),
      registerIncarnationId: incarnation(0x32),
      endpoint: 'https://node-2:8080',
      answer: { case: 'noCycle', value: new pb.StorageMemberNoCycle() },
      answeredAs: text('dsm-node-3'),
    });
    const unanswered = new pb.StorageMemberStatus({
      memberId: text('dsm-node-3'),
      registerIncarnationId: incarnation(0x33),
      endpoint: 'https://node-3:8080',
      answer: { case: 'unanswered', value: 'transport: connection refused' },
    });

    test('renders the set, each member and its answer as the SDK reports them', async () => {
      (routerQueryBin as jest.Mock).mockResolvedValue(
        frameEnvelope(statusEnvelope([stated, noCycle, unanswered])),
      );

      const status = await getStorageStatus();
      expect(routerQueryBin).toHaveBeenCalledWith('storage.status', expect.any(Uint8Array));
      expect(status.networkId).toBe('dsm-testnet');
      expect(status.storageSetIdB32).toBe(encodeBase32Crockford(setId));
      expect(status.completedSyncs).toBe(7n);
      expect(status.databaseBytes).toBe(4096n);
      expect(status.members).toEqual([
        {
          memberId: 'dsm-node-1',
          registerIncarnationB32: encodeBase32Crockford(incarnation(0x31)),
          endpoint: 'https://node-1:8080',
          answer: {
            kind: 'latest',
            cycle: 12n,
            bytesUsed: 2048n,
            rootB32: encodeBase32Crockford(commit.smtRoot),
            parentB32: encodeBase32Crockford(commit.parentDigest),
            digestB32: encodeBase32Crockford(digest),
          },
          answeredAs: 'dsm-node-1',
        },
        {
          memberId: 'dsm-node-2',
          registerIncarnationB32: encodeBase32Crockford(incarnation(0x32)),
          endpoint: 'https://node-2:8080',
          answer: { kind: 'noCycle' },
          answeredAs: 'dsm-node-3',
        },
        {
          memberId: 'dsm-node-3',
          registerIncarnationB32: encodeBase32Crockford(incarnation(0x33)),
          endpoint: 'https://node-3:8080',
          answer: { kind: 'unanswered', why: 'transport: connection refused' },
          answeredAs: undefined,
        },
      ]);
    });

    test('a member that carries no answer is refused, never given one', async () => {
      const silent = new pb.StorageMemberStatus({
        memberId: text('dsm-node-4'),
        registerIncarnationId: incarnation(0x34),
        endpoint: 'https://node-4:8080',
      });
      (routerQueryBin as jest.Mock).mockResolvedValue(frameEnvelope(statusEnvelope([silent])));
      await expect(getStorageStatus()).rejects.toThrow(/dsm-node-4 carries no answer/);
    });

    test('a ByteCommit answer without the commit is refused', async () => {
      const hollow = new pb.StorageMemberStatus({
        memberId: text('dsm-node-5'),
        registerIncarnationId: incarnation(0x35),
        endpoint: 'https://node-5:8080',
        answer: { case: 'latest', value: new pb.StorageMemberByteCommit({ digest }) },
      });
      (routerQueryBin as jest.Mock).mockResolvedValue(frameEnvelope(statusEnvelope([hollow])));
      await expect(getStorageStatus()).rejects.toThrow(/dsm-node-5/);
    });

    test('throws on empty response', async () => {
      (routerQueryBin as jest.Mock).mockResolvedValue(new Uint8Array(0));
      await expect(getStorageStatus()).rejects.toThrow(/empty response/);
    });

    test('throws on error envelope', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'error', value: new pb.Error({ message: 'no pinned storage set' }) },
      });
      (routerQueryBin as jest.Mock).mockResolvedValue(frameEnvelope(env));
      await expect(getStorageStatus()).rejects.toThrow(/no pinned storage set/);
    });

    test('throws on unexpected payload', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'balancesListResponse', value: new pb.BalancesListResponse() },
      });
      (routerQueryBin as jest.Mock).mockResolvedValue(frameEnvelope(env));
      await expect(getStorageStatus()).rejects.toThrow(/unexpected payload/);
    });
  });
});
