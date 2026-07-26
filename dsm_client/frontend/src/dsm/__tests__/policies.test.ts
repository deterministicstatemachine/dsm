// SPDX-License-Identifier: MIT OR Apache-2.0

jest.mock('../WebViewBridge', () => ({
  routerInvokeBin: jest.fn(),
  getTokenPolicyBytes: jest.fn(),
  listCachedTokenPolicies: jest.fn(),
  publishTokenPolicyBytes: jest.fn(),
}));

jest.mock('../events', () => ({
  emitWalletRefresh: jest.fn(),
  emitBilateralCommitted: jest.fn(),
  DSM_WALLET_REFRESH_EVENT: 'dsm-wallet-refresh',
}));

import * as pb from '../../proto/dsm_app_pb';
import {
  createToken,
  listPolicies,
  publishTokenPolicyBytes,
  getTokenPolicyBytes,
  publishTokenPolicy,
} from '../policies';
import {
  routerInvokeBin,
  getTokenPolicyBytes as getTokenPolicyBytesBridge,
  listCachedTokenPolicies,
  publishTokenPolicyBytes as publishTokenPolicyBytesBridge,
} from '../WebViewBridge';
import { encodeBase32Crockford } from '../../utils/textId';

function frameEnvelope(envelope: pb.Envelope): Uint8Array {
  const bytes = envelope.toBinary();
  const framed = new Uint8Array(1 + bytes.length);
  framed[0] = 0x03;
  framed.set(bytes, 1);
  return framed;
}

describe('policies.ts', () => {
  beforeEach(() => jest.clearAllMocks());

  // ── createToken ────────────────────────────────────────────────────

  describe('createToken', () => {
    // Protocol validation lives in Rust. This layer forwards the user's
    // intent and surfaces the state machine's verdict verbatim — it must not
    // re-implement (and therefore be able to disagree with) the rules.
    test('forwards invalid intent to Rust and surfaces its rejection', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'error', value: new pb.ErrorResponse({ message: 'token.create: ticker must be 2-8 chars' }) },
      });
      const framed = new Uint8Array(1 + env.toBinary().length);
      framed[0] = 0x03;
      framed.set(env.toBinary(), 1);
      (routerInvokeBin as jest.Mock).mockResolvedValue(framed);

      const result = await createToken({ ticker: 'X', alias: 'test', decimals: 0, maxSupply: '1000' });
      expect(routerInvokeBin).toHaveBeenCalledWith('token.create', expect.any(Uint8Array));
      expect(result.success).toBe(false);
      expect(result.message).toMatch(/ticker must be 2-8/);
    });

    // The client no longer publishes the policy separately, and no longer
    // supplies an anchor: `token.create` is a single invoke and Rust derives
    // the content-addressed anchor from the policy it packs.
    test('creates in one invoke without a separate publish round-trip', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'tokenCreateResponse',
          value: new pb.TokenCreateResponse({
            success: true,
            tokenId: 'TOKEN123',
            policyAnchor: new Uint8Array(32).fill(0xCC),
          }),
        },
      });
      const framed = new Uint8Array(1 + env.toBinary().length);
      framed[0] = 0x03;
      framed.set(env.toBinary(), 1);
      (routerInvokeBin as jest.Mock).mockResolvedValue(framed);

      const result = await createToken({ ticker: 'TOK', alias: 'test', decimals: 0, maxSupply: '1000' });
      expect(result.success).toBe(true);
      expect(result.tokenId).toBe('TOKEN123');
      expect(publishTokenPolicyBytesBridge).not.toHaveBeenCalled();
      expect(routerInvokeBin).toHaveBeenCalledTimes(1);
    });

    test('handles default kind as FUNGIBLE', async () => {
      const anchor = new Uint8Array(32).fill(0xCC);
      (publishTokenPolicyBytesBridge as jest.Mock).mockResolvedValue(anchor);

      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'tokenCreateResponse',
          value: new pb.TokenCreateResponse({ success: true, tokenId: 'FT', policyAnchor: anchor as any }),
        },
      });
      (routerInvokeBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await createToken({
        ticker: 'FT',
        alias: 'Fungible Token',
        decimals: 2,
        maxSupply: '5000',
      });
      expect(result.success).toBe(true);
    });

    test('emits wallet refresh on successful creation', async () => {
      const { emitWalletRefresh } = jest.requireMock('../events');
      const anchor = new Uint8Array(32).fill(0xDA);
      (publishTokenPolicyBytesBridge as jest.Mock).mockResolvedValue(anchor);

      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'tokenCreateResponse',
          value: new pb.TokenCreateResponse({
            success: true,
            tokenId: 'NEWTOK',
            policyAnchor: anchor as any,
          }),
        },
      });
      (routerInvokeBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      await createToken({
        ticker: 'NEW',
        alias: 'New Token',
        decimals: 6,
        maxSupply: '10000',
      });
      expect(emitWalletRefresh).toHaveBeenCalledTimes(1);
      expect(emitWalletRefresh).toHaveBeenCalledWith(
        expect.objectContaining({
          source: 'token.create',
          tokenId: 'NEWTOK',
        }),
      );
    });

    test('does NOT emit wallet refresh when core returns success=false', async () => {
      const { emitWalletRefresh } = jest.requireMock('../events');
      const anchor = new Uint8Array(32).fill(0xDB);
      (publishTokenPolicyBytesBridge as jest.Mock).mockResolvedValue(anchor);

      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'tokenCreateResponse',
          value: new pb.TokenCreateResponse({
            success: false,
            tokenId: '',
            policyAnchor: anchor as any,
            message: 'rejected',
          }),
        },
      });
      (routerInvokeBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      await createToken({
        ticker: 'BAD',
        alias: 'Bad Token',
        decimals: 0,
        maxSupply: '1',
      });
      expect(emitWalletRefresh).not.toHaveBeenCalled();
    });
  });


  describe('listPolicies', () => {
    test('maps policies from envelope', async () => {
      const commit = new Uint8Array(32).fill(0x01);
      const pBytes = new Uint8Array(16).fill(0x02);
      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'tokenPolicyListResponse',
          value: new pb.TokenPolicyListResponse({
            policies: [
              new pb.TokenPolicyCacheEntry({
                policyCommit: commit as any,
                policyBytes: pBytes as any,
                ticker: 'ERA',
                alias: 'Era Coin',
                decimals: 8,
                maxSupply: '1000000',
              }),
            ],
          }),
        },
      });
      (listCachedTokenPolicies as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await listPolicies();
      expect(result).toHaveLength(1);
      expect(result[0].policy_commit).toEqual(commit);
      expect(result[0].policy_bytes).toEqual(pBytes);
      expect(result[0].metadata).toEqual({
        ticker: 'ERA',
        alias: 'Era Coin',
        decimals: 8,
        maxSupply: '1000000',
      });
    });

    test('returns empty array on error envelope', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'error', value: new pb.Error({ message: 'nope' }) },
      });
      (listCachedTokenPolicies as jest.Mock).mockResolvedValue(frameEnvelope(env));

      expect(await listPolicies()).toEqual([]);
    });

    test('returns empty array on bridge error', async () => {
      (listCachedTokenPolicies as jest.Mock).mockRejectedValue(new Error('fail'));
      expect(await listPolicies()).toEqual([]);
    });

    test('metadata is undefined when no metadata fields are present', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'tokenPolicyListResponse',
          value: new pb.TokenPolicyListResponse({
            policies: [new pb.TokenPolicyCacheEntry({ policyCommit: new Uint8Array(32) as any, policyBytes: new Uint8Array(8) as any })],
          }),
        },
      });
      (listCachedTokenPolicies as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await listPolicies();
      expect(result[0].metadata).toBeUndefined();
    });
  });

  // ── publishTokenPolicyBytes ────────────────────────────────────────

  describe('publishTokenPolicyBytes', () => {
    test('returns anchor bytes and base32 on success', async () => {
      const anchor = new Uint8Array(32).fill(0x11);
      (publishTokenPolicyBytesBridge as jest.Mock).mockResolvedValue(anchor);

      const result = await publishTokenPolicyBytes(new Uint8Array(64));
      expect(result.anchorBytes).toEqual(anchor);
      expect(result.anchorBase32).toBe(encodeBase32Crockford(anchor));
    });

    test('throws on empty policy bytes', async () => {
      await expect(publishTokenPolicyBytes(new Uint8Array(0))).rejects.toThrow(/policyBytes required/);
    });

    test('throws on null policy bytes', async () => {
      await expect(publishTokenPolicyBytes(null as any)).rejects.toThrow(/policyBytes required/);
    });
  });

  // ── getTokenPolicyBytes ────────────────────────────────────────────

  describe('getTokenPolicyBytes', () => {
    test('returns bytes from bridge', async () => {
      const policyBytes = new Uint8Array(64);
      (getTokenPolicyBytesBridge as jest.Mock).mockResolvedValue(policyBytes);

      const result = await getTokenPolicyBytes(new Uint8Array(32));
      expect(result).toEqual(policyBytes);
    });

    test('throws when anchor is not 32 bytes', async () => {
      await expect(getTokenPolicyBytes(new Uint8Array(16))).rejects.toThrow(/anchorBytes must be 32 bytes/);
    });

    test('throws when anchor is null', async () => {
      await expect(getTokenPolicyBytes(null as any)).rejects.toThrow(/anchorBytes must be 32 bytes/);
    });
  });

  // ── publishTokenPolicy ─────────────────────────────────────────────

  describe('publishTokenPolicy', () => {
    test('returns error for empty base32', async () => {
      const result = await publishTokenPolicy({ policyBase32: '' });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/policy bytes required/);
    });

    test('returns error for null input', async () => {
      const result = await publishTokenPolicy(null as any);
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/policy bytes required/);
    });

    test('successful publish returns id', async () => {
      const policyV3 = new pb.TokenPolicyV3({ policyBytes: new Uint8Array(16) as any });
      const policyBin = policyV3.toBinary();
      const { encodeBase32Crockford: enc } = await import('../../utils/textId');
      const b32 = enc(new Uint8Array(policyBin));

      const anchor = new Uint8Array(32).fill(0x22);
      (publishTokenPolicyBytesBridge as jest.Mock).mockResolvedValue(anchor);

      const result = await publishTokenPolicy({ policyBase32: b32 });
      expect(result.success).toBe(true);
      expect(result.id).toBe(encodeBase32Crockford(anchor));
    });

    test('returns error when bridge publish fails', async () => {
      const policyV3 = new pb.TokenPolicyV3({ policyBytes: new Uint8Array(16) as any });
      const policyBin = policyV3.toBinary();
      const { encodeBase32Crockford: enc } = await import('../../utils/textId');
      const b32 = enc(new Uint8Array(policyBin));

      (publishTokenPolicyBytesBridge as jest.Mock).mockRejectedValue(new Error('publish boom'));

      const result = await publishTokenPolicy({ policyBase32: b32 });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/publish boom/);
    });
  });
});
