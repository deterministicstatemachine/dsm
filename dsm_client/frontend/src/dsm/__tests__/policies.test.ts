// SPDX-License-Identifier: MIT OR Apache-2.0

jest.mock('../WebViewBridge', () => ({
  routerInvokeBin: jest.fn(),
  routerQueryBin: jest.fn(),
  addTokenByAnchor: jest.fn(),
  publishTokenPolicyBytes: jest.fn(),
}));

jest.mock('../events', () => ({
  emitWalletRefresh: jest.fn(),
  emitBilateralCommitted: jest.fn(),
  DSM_WALLET_REFRESH_EVENT: 'dsm-wallet-refresh',
}));

import * as pb from '../../proto/dsm_app_pb';
import {
  addTokenByAnchor,
  createToken,
  getTokenCreationFeeEra,
  publishTokenPolicyBytes,
  publishTokenPolicy,
} from '../policies';
import {
  addTokenByAnchor as addTokenByAnchorBridge,
  routerInvokeBin,
  routerQueryBin,
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

      const result = await createToken({ ticker: 'X', alias: 'test', decimals: 0, genesisSupply: '1000', burnEnabled: false, transferable: true, threshold: 1 });
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

      const result = await createToken({ ticker: 'TOK', alias: 'test', decimals: 0, genesisSupply: '1000', burnEnabled: false, transferable: true, threshold: 1 });
      expect(result.success).toBe(true);
      expect(result.tokenId).toBe('TOKEN123');
      expect(publishTokenPolicyBytesBridge).not.toHaveBeenCalled();
      expect(routerInvokeBin).toHaveBeenCalledTimes(1);
    });

    test('creates a fungible token', async () => {
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
        genesisSupply: '5000', burnEnabled: false, transferable: true, threshold: 1,
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
        genesisSupply: '10000', burnEnabled: false, transferable: true, threshold: 1,
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
        genesisSupply: '1', burnEnabled: false, transferable: true, threshold: 1,
      });
      expect(emitWalletRefresh).not.toHaveBeenCalled();
    });
  });


  // ── publishTokenPolicyBytes ────────────────────────────────────────

  describe('addTokenByAnchor', () => {
    // The ticker and anchor are the answer's fields; the ticker used to be
    // scraped from the "Added …" prose, and the anchor looked up elsewhere.
    test('reads the adopted token’s ticker and anchor from the answer’s fields, not its prose', async () => {
      const anchor = new Uint8Array(32).fill(0xab);
      (addTokenByAnchorBridge as jest.Mock).mockResolvedValue(frameEnvelope(new pb.Envelope({
        version: 3,
        payload: {
          case: 'tokenCreateResponse',
          value: new pb.TokenCreateResponse({ success: true, tokenId: 'T1', ticker: 'ABC', policyAnchor: anchor as any, message: 'Added XYZ' }),
        },
      })));

      await expect(addTokenByAnchor('ANCHORB32')).resolves.toEqual({
        success: true, tokenId: 'T1', ticker: 'ABC', anchorBase32: encodeBase32Crockford(anchor),
      });
    });

    test('a success answer without the ticker is refused, never shown as a blank name', async () => {
      (addTokenByAnchorBridge as jest.Mock).mockResolvedValue(frameEnvelope(new pb.Envelope({
        version: 3,
        payload: {
          case: 'tokenCreateResponse',
          value: new pb.TokenCreateResponse({ success: true, tokenId: 'T1', policyAnchor: new Uint8Array(32) as any, message: 'Added XYZ' }),
        },
      })));

      const result = await addTokenByAnchor('ANCHORB32');
      expect(result.success).toBe(false);
      expect((result as { error: string }).error).toContain('STRICT');
    });
  });

  describe('getTokenCreationFeeEra', () => {
    test('answers the fee Rust reports', async () => {
      (routerQueryBin as jest.Mock).mockResolvedValue(frameEnvelope(new pb.Envelope({
        version: 3,
        payload: { case: 'tokenFeeScheduleResponse', value: new pb.TokenFeeScheduleResponse({ tokenCreationEra: 100n }) },
      })));
      await expect(getTokenCreationFeeEra()).resolves.toBe(100n);
    });

    // A failed query used to answer undefined, which the dialog showed as "…" for ever.
    test('a refused fee query is the failure, not an absent fee', async () => {
      (routerQueryBin as jest.Mock).mockResolvedValue(frameEnvelope(new pb.Envelope({
        version: 3,
        payload: { case: 'error', value: new pb.ErrorResponse({ message: 'tokens.getFeeSchedule: no fee schedule' }) },
      })));
      await expect(getTokenCreationFeeEra()).rejects.toThrow('no fee schedule');
    });
  });

  describe('amounts', () => {
    // A blank or non-numeric amount used to be read as 0 and sent.
    test('a blank genesis supply is refused before anything is sent', async () => {
      const res = await createToken({
        ticker: 'TKN', alias: 'Token', decimals: 0, genesisSupply: '  ',
        burnEnabled: false, transferable: true, threshold: 1,
      } as any);
      expect(res).toEqual({ success: false, message: expect.stringContaining('whole number') });
      expect(routerInvokeBin).not.toHaveBeenCalled();
    });

    test('a blank burn amount is refused before anything is sent', async () => {
      const { burnToken } = await import('../policies');
      const res = await burnToken({ tokenId: 'TKN', amount: '' });
      expect(res).toEqual({ success: false, message: expect.stringContaining('whole number') });
      expect(routerInvokeBin).not.toHaveBeenCalled();
    });
  });

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

  // ── publishTokenPolicy ─────────────────────────────────────────────

  describe('publishTokenPolicy', () => {
    test('returns error for empty base32', async () => {
      const result = await publishTokenPolicy({ policyBase32: '' });
      expect(result).toEqual({ success: false, error: expect.stringMatching(/policy bytes required/) });
    });

    test('returns error for null input', async () => {
      const result = await publishTokenPolicy(null as any);
      expect(result).toEqual({ success: false, error: expect.stringMatching(/policy bytes required/) });
    });

    test('successful publish returns id', async () => {
      const policyV3 = new pb.TokenPolicyV3({ policyBytes: new Uint8Array(16) as any });
      const policyBin = policyV3.toBinary();
      const { encodeBase32Crockford: enc } = await import('../../utils/textId');
      const b32 = enc(new Uint8Array(policyBin));

      const anchor = new Uint8Array(32).fill(0x22);
      (publishTokenPolicyBytesBridge as jest.Mock).mockResolvedValue(anchor);

      const result = await publishTokenPolicy({ policyBase32: b32 });
      expect(result).toEqual({ success: true, id: encodeBase32Crockford(anchor) });
    });

    test('publishes the pasted bytes exactly as pasted', async () => {
      // An unknown field before policy_bytes: a decode and re-encode here would
      // move it after the known field — other bytes, another anchor.
      const policyBin = new pb.TokenPolicyV3({ policyBytes: new Uint8Array(16).fill(7) as any }).toBinary();
      const pasted = new Uint8Array([0x78, 0x01, ...policyBin]); // field 15, varint 1
      const { encodeBase32Crockford: enc } = await import('../../utils/textId');
      (publishTokenPolicyBytesBridge as jest.Mock).mockResolvedValue(new Uint8Array(32).fill(0x22));

      const result = await publishTokenPolicy({ policyBase32: enc(pasted) });

      expect(result.success).toBe(true);
      expect(Array.from((publishTokenPolicyBytesBridge as jest.Mock).mock.calls.at(-1)[0] as Uint8Array)).toEqual(
        Array.from(pasted),
      );
    });

    test("bytes that are not a policy are Rust's to refuse, in its words", async () => {
      const { encodeBase32Crockford: enc } = await import('../../utils/textId');
      (publishTokenPolicyBytesBridge as jest.Mock).mockRejectedValue(
        new Error('tokens.publishPolicy: not a token policy: policy proto does not decode'),
      );

      const result = await publishTokenPolicy({ policyBase32: enc(new Uint8Array([0xff, 0xff])) });

      expect(result).toEqual({ success: false, error: expect.stringMatching(/not a token policy/) });
    });

    test('returns error when bridge publish fails', async () => {
      const policyV3 = new pb.TokenPolicyV3({ policyBytes: new Uint8Array(16) as any });
      const policyBin = policyV3.toBinary();
      const { encodeBase32Crockford: enc } = await import('../../utils/textId');
      const b32 = enc(new Uint8Array(policyBin));

      (publishTokenPolicyBytesBridge as jest.Mock).mockRejectedValue(new Error('publish boom'));

      const result = await publishTokenPolicy({ policyBase32: b32 });
      expect(result).toEqual({ success: false, error: expect.stringMatching(/publish boom/) });
    });
  });
});
