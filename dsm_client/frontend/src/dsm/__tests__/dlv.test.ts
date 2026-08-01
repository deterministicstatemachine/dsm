// SPDX-License-Identifier: MIT OR Apache-2.0

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

    test('forwards empty creator_public_key + signature to Rust (Track C.4 accept-or-stamp)', async () => {
      // Frontend does NOT validate empty pk / signature — those ride
      // over the wire and the Rust handler stamps the wallet pk and
      // signs.  This test verifies the bridge call goes through with
      // empty fields rather than rejecting client-side.
      const req = new pb.DlvInstantiateV1({
        spec: new pb.DlvSpecV1({
          policyDigest: new Uint8Array(32).fill(0x02) as any,
          contentDigest: new Uint8Array(32).fill(0x03) as any,
          fulfillmentDigest: new Uint8Array(32).fill(0x04) as any,
        }),
        creatorPublicKey: new Uint8Array() as any,
        signature: new Uint8Array() as any,
      });
      const lockB32 = encodeInstantiateToBase32(req);

      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'appStateResponse',
          value: new pb.AppStateResponse({ value: 'STAMPED_VAULT_ID_B32' }),
        },
      });
      (routerInvokeBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await createCustomDlv({ lock: lockB32 });
      expect(result.success).toBe(true);
      expect(result.id).toBe('STAMPED_VAULT_ID_B32');
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
    // The frontend builder is a PURE proto packer per the
    // "all business logic stays in Rust" rule.  Digests are NOT
    // computed here; callers omit them and the Rust handler derives
    // canonical values from the content + fulfillment bytes on
    // arrival.  These tests exercise the proto-shape contract only.
    const baseInput = {
      policyDigest: new Uint8Array(32).fill(0x02),
      content: new Uint8Array([0xaa, 0xbb]),
      fulfillmentBytes: new Uint8Array([0xcc, 0xdd]),
      creatorPublicKey: new Uint8Array(64).fill(0x11),
      signature: new Uint8Array(64).fill(0x22),
    };

    test('omits content and fulfillment digests by default', () => {
      const bytes = buildDlvInstantiateBytes(baseInput);
      const req = pb.DlvInstantiateV1.fromBinary(bytes);
      expect(req.spec).toBeDefined();
      // Both digest fields ride empty over the wire — Rust computes.
      expect(req.spec!.contentDigest.length).toBe(0);
      expect(req.spec!.fulfillmentDigest.length).toBe(0);
      // No lock supplied → NO funding legs. A content-only vault encumbers
      // nothing, and an empty-token zero-amount leg would ask Rust to fund a
      // vault with an asset that does not exist.
      expect(req.fundingLegs.length).toBe(0);
    });

    test('passes 32-byte caller-supplied digests through verbatim (Rust strict-verifies)', () => {
      const cd = new Uint8Array(32).fill(0x77);
      const fd = new Uint8Array(32).fill(0x88);
      const bytes = buildDlvInstantiateBytes({
        ...baseInput,
        contentDigest: cd,
        fulfillmentDigest: fd,
      });
      const req = pb.DlvInstantiateV1.fromBinary(bytes);
      // The frontend does NOT validate digest correctness — that is
      // Rust's job on the receiving end.  The builder just forwards
      // whatever bytes the caller chose.
      expect(Array.from(req.spec!.contentDigest)).toEqual(Array.from(cd));
      expect(Array.from(req.spec!.fulfillmentDigest)).toEqual(Array.from(fd));
    });

    test('turns a single-asset lock into one funding leg', () => {
      const bytes = buildDlvInstantiateBytes({
        ...baseInput,
        policyCommit: new Uint8Array(32).fill(0x7c),
        lockedAmount: 0x0102_0304_0506_0708n,
      });
      const req = pb.DlvInstantiateV1.fromBinary(bytes);
      expect(req.fundingLegs.length).toBe(1);
      expect(Array.from(req.fundingLegs[0].policyCommit)).toEqual(
        Array.from(new Uint8Array(32).fill(0x7c)),
      );
      // u64 base units, carried as a number the wire understands — not a
      // 16-byte blob every consumer had to re-decode.
      expect(req.fundingLegs[0].amount).toBe(0x0102_0304_0506_0708n);
    });

    test('refuses a leg that names only half of itself', () => {
      expect(() =>
        buildDlvInstantiateBytes({
          ...baseInput,
          policyCommit: new Uint8Array(32).fill(0x7c),
        }),
      ).toThrow(/non-zero amount/);
      expect(() =>
        buildDlvInstantiateBytes({ ...baseInput, lockedAmount: 5n }),
      ).toThrow(/policyCommit/);
    });

    /// A ticker is not an identity, and nothing resolves it to one. A leg that
    /// is not exactly 32 bytes dies here rather than being looked up.
    test('refuses an identity that is not a 32-byte policy commit', () => {
      for (const bad of [
        new TextEncoder().encode('RIGB'),
        new Uint8Array(31),
        new Uint8Array(33),
      ]) {
        expect(() =>
          buildDlvInstantiateBytes({
            ...baseInput,
            policyCommit: bad,
            lockedAmount: 5n,
          }),
        ).toThrow(/32 bytes/);
      }
    });

    /// An amount past u64 is REFUSED, never wrapped: these base units are
    /// debited from real balances, so a silent truncation would lock a
    /// different number than the caller named.
    test('refuses an amount that does not fit u64 base units', () => {
      expect(() =>
        buildDlvInstantiateBytes({
          ...baseInput,
          policyCommit: new Uint8Array(32).fill(0x7c),
          lockedAmount: 0x1_0000_0000_0000_0000n,
        }),
      ).toThrow(/u64/);
      expect(() =>
        buildDlvInstantiateBytes({
          ...baseInput,
          policyCommit: new Uint8Array(32).fill(0x7c),
          lockedAmount: -1n,
        }),
      ).toThrow(/non-negative/);
    });

    test.each([
      ['policyDigest', { policyDigest: new Uint8Array(16) }, /policyDigest must be 32 bytes/],
      [
        'contentDigest length',
        { contentDigest: new Uint8Array(16) },
        /contentDigest must be 0 or 32 bytes/,
      ],
      [
        'fulfillmentDigest length',
        { fulfillmentDigest: new Uint8Array(16) },
        /fulfillmentDigest must be 0 or 32 bytes/,
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
