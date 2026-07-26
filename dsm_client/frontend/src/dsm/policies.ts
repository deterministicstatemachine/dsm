// SPDX-License-Identifier: MIT OR Apache-2.0

/* eslint-disable @typescript-eslint/no-explicit-any */
import * as pb from '../proto/dsm_app_pb';
import {
  routerInvokeBin,
  routerQueryBin,
  getTokenPolicyBytes as getTokenPolicyBytesBridge,
  listCachedTokenPolicies,
  publishTokenPolicyBytes as publishTokenPolicyBytesBridge,
} from './WebViewBridge';
import { encodeBase32Crockford, decodeBase32Crockford } from '../utils/textId';
import { decodeFramedEnvelopeV3 } from './decoding';
import { emitWalletRefresh } from './events';

/**
 * Create a native DSM token.
 *
 * PURE TRANSPORT. Every protocol decision lives in Rust: it packs the
 * canonical v3 policy blob, derives the content-addressed CPTA anchor,
 * publishes it, and creates the token — all in one invoke. This layer must
 * never pack policy bytes, compute an anchor, or validate protocol rules;
 * doing so would put a second (and inevitably divergent) definition of the
 * format outside the state machine.
 *
 * `details` carries the user's intent only.
 */
export async function createToken(details: any): Promise<{ success: boolean; tokenId?: string; anchorBase32?: string; message?: string }> {
  try {
    const u128be = (v: string | number | undefined): Uint8Array => {
      const out = new Uint8Array(16);
      let n = BigInt(String(v ?? '0').trim() || '0');
      if (n < 0n) throw new Error('createToken: amounts must be non-negative');
      for (let i = 15; i >= 0; i--) {
        out[i] = Number(n & 0xffn);
        n >>= 8n;
      }
      if (n !== 0n) throw new Error('createToken: amount exceeds u128');
      return out;
    };

    const allowlist: Uint8Array[] =
      String(details?.allowlistKind || 'NONE') === 'INLINE'
        ? String(details?.allowlistData || '')
            .split(/[\s,]+/)
            .map((s) => s.trim())
            .filter(Boolean)
            .map((s) => new Uint8Array(decodeBase32Crockford(s)))
        : [];

    const req = new pb.TokenCreateRequest({
      ticker: String(details?.ticker || '').trim().toUpperCase(),
      alias: String(details?.alias || '').trim(),
      decimals: Number(details?.decimals ?? 0),
      maxSupplyU128: u128be(details?.maxSupply) as any,
      initialAllocU128: u128be(details?.initialAlloc) as any,
      mintBurnEnabled: Boolean(details?.mintBurnEnabled),
      transferable: Boolean(details?.transferable !== false),
      unlimitedSupply: Boolean(details?.unlimitedSupply),
      mintBurnThreshold: Number(details?.mintBurnThreshold ?? 1),
      description: String(details?.description || '').trim(),
      iconUrl: String(details?.iconUrl || '').trim(),
      allowlistDeviceIds: allowlist as any,
    } as any);

    const argPack = new pb.ArgPack({
      codec: pb.Codec.PROTO as any,
      body: new Uint8Array(req.toBinary()),
    });

    const resBytes = await routerInvokeBin('token.create', new Uint8Array(argPack.toBinary()));
    const env = decodeFramedEnvelopeV3(resBytes);

    if (env.payload.case === 'error') {
      throw new Error(`Token creation failed: ${env.payload.value.message}`);
    }
    if (env.payload.case !== 'tokenCreateResponse') {
      throw new Error(`Expected tokenCreateResponse, got ${env.payload.case}`);
    }

    const resp = env.payload.value;
    const success = Boolean(resp.success);
    const tokenId = resp.tokenId || undefined;
    const anchorBase32 =
      resp.policyAnchor?.length === 32 ? encodeBase32Crockford(resp.policyAnchor) : undefined;

    // Single canonical refresh event so the wallet re-fetches balances and
    // metadata without a manual pull-to-refresh.
    if (success) {
      try {
        emitWalletRefresh({
          source: 'token.create',
          tokenId: tokenId ?? '',
          anchorBase32: anchorBase32 ?? '',
        });
      } catch (e) {
        console.warn('createToken: emitWalletRefresh failed (non-fatal):', e);
      }
    }

    return { success, tokenId, anchorBase32, message: resp.message || undefined };
  } catch (e) {
    console.warn('createToken failed:', e);
    return { success: false, message: e instanceof Error ? e.message : String(e) };
  }
}

export async function importTokenPolicy(args: string | { anchorBase32: string }): Promise<{ success: boolean; error?: string }> {
  try {
    const policyId = typeof args === 'string' ? args : args.anchorBase32;
    const b32 = String(policyId || '').trim();
    if (!b32) throw new Error('importTokenPolicy: anchor required');
    const anchorBytes = new Uint8Array(decodeBase32Crockford(b32));
    if (anchorBytes.length !== 32) throw new Error('importTokenPolicy: anchor must be 32 bytes');

    const policyBytes = await getTokenPolicyBytes(anchorBytes);
    if (!policyBytes || policyBytes.length === 0) {
      throw new Error('importTokenPolicy: empty policy bytes');
    }

    return { success: true };
  } catch (e: any) {
    console.warn('importTokenPolicy failed:', e);
    return { success: false, error: e.message || String(e) };
  }
}

export async function listPolicies(): Promise<Array<{
  policy_commit: Uint8Array;
  policy_bytes: Uint8Array;
  metadata?: { ticker: string; alias: string; decimals: number; maxSupply: string };
}>> {
  try {
    const responseBytes = await listCachedTokenPolicies();
    const env = decodeFramedEnvelopeV3(responseBytes);
    if (env.payload.case === 'error') {
      throw new Error(env.payload.value.message || `Error code ${env.payload.value.code}`);
    }
    if (env.payload.case !== 'tokenPolicyListResponse') {
      throw new Error(`Expected tokenPolicyListResponse, got ${env.payload.case}`);
    }
    return (env.payload.value.policies ?? []).map((entry) => ({
      policy_commit: entry.policyCommit instanceof Uint8Array ? entry.policyCommit : new Uint8Array(),
      policy_bytes: entry.policyBytes instanceof Uint8Array ? entry.policyBytes : new Uint8Array(),
      metadata: entry.ticker || entry.alias || entry.maxSupply || entry.decimals
        ? {
            ticker: entry.ticker || '',
            alias: entry.alias || '',
            decimals: Number(entry.decimals || 0),
            maxSupply: entry.maxSupply || '0',
          }
        : undefined,
    }));
  } catch {
    return [];
  }
}

export async function publishTokenPolicyBytes(policyBytes: Uint8Array): Promise<{ anchorBytes: Uint8Array; anchorBase32: string }> {
  if (!policyBytes || policyBytes.length === 0) throw new Error('publishTokenPolicyBytes: policyBytes required');
  const anchorBytes = await publishTokenPolicyBytesBridge(policyBytes);
  return { anchorBytes, anchorBase32: encodeBase32Crockford(anchorBytes) };
}

export async function getTokenPolicyBytes(anchorBytes: Uint8Array): Promise<Uint8Array> {
  if (!anchorBytes || anchorBytes.length !== 32) throw new Error('getTokenPolicyBytes: anchorBytes must be 32 bytes');
  return getTokenPolicyBytesBridge(anchorBytes);
}

/**
 * Publish a CPTA token policy from a Base32 Crockford-encoded CanonicalPolicy proto.
 * Validates the payload as TokenPolicyV3, publishes to the storage node (or falls back
 * to a local content-addressed anchor), and returns the policy anchor ID.
 *
 * This is the entry point for the DevPolicyScreen "Publish Policy" action.
 */
export async function publishTokenPolicy(input: {
  policyBase32: string;
}): Promise<{ success: boolean; id?: string; error?: string }> {
  try {
    const b32 = typeof input?.policyBase32 === 'string' ? input.policyBase32.trim() : '';
    if (!b32) return { success: false, error: 'policy bytes required (base32)' };

    const bytes = decodeBase32Crockford(b32);
    if (!bytes || bytes.length === 0) return { success: false, error: 'decoded policy bytes empty' };

    // Validate payload is a TokenPolicyV3 proto; re-encode to canonical bytes.
    const policy = pb.TokenPolicyV3.fromBinary(bytes);
    const canonicalBytes = new Uint8Array(policy.toBinary());

    const published = await publishTokenPolicyBytes(canonicalBytes);
    return { success: true, id: published.anchorBase32 };
  } catch (e: any) {
    return { success: false, error: e?.message || 'Policy publish failed' };
  }
}

/**
 * Mint additional supply of an existing token.
 *
 * PURE TRANSPORT. Authority, the k-of-N threshold and the supply cap are
 * enforced by the token's committed policy conditions in Rust; this layer
 * cannot approve or bypass any of them, and must never try to pre-judge them.
 */
export async function mintToken(args: { tokenId: string; amount: string | number; message?: string }): Promise<{ success: boolean; newBalance?: bigint; message?: string }> {
  try {
    const req = new pb.TokenMintRequest({
      tokenId: String(args?.tokenId || '').trim(),
      amount: BigInt(String(args?.amount ?? '0')),
      message: String(args?.message || ''),
    } as any);
    const argPack = new pb.ArgPack({
      codec: pb.Codec.PROTO as any,
      body: new Uint8Array(req.toBinary()),
    });
    const env = decodeFramedEnvelopeV3(
      await routerInvokeBin('token.mint', new Uint8Array(argPack.toBinary())),
    );
    if (env.payload.case === 'error') throw new Error(env.payload.value.message);
    if (env.payload.case !== 'tokenMintResponse') {
      throw new Error(`Expected tokenMintResponse, got ${env.payload.case}`);
    }
    const resp = env.payload.value;
    if (resp.success) {
      try {
        emitWalletRefresh({ source: 'token.mint', tokenId: resp.tokenId, anchorBase32: '' });
      } catch (e) {
        console.warn('mintToken: emitWalletRefresh failed (non-fatal):', e);
      }
    }
    return { success: Boolean(resp.success), newBalance: resp.newBalance, message: resp.message || undefined };
  } catch (e) {
    console.warn('mintToken failed:', e);
    return { success: false, message: e instanceof Error ? e.message : String(e) };
  }
}

/** Burn supply the caller holds. Burn <= balance is enforced by the core conservation guard. */
export async function burnToken(args: { tokenId: string; amount: string | number; message?: string }): Promise<{ success: boolean; newBalance?: bigint; message?: string }> {
  try {
    const req = new pb.TokenBurnRequest({
      tokenId: String(args?.tokenId || '').trim(),
      amount: BigInt(String(args?.amount ?? '0')),
      message: String(args?.message || ''),
    } as any);
    const argPack = new pb.ArgPack({
      codec: pb.Codec.PROTO as any,
      body: new Uint8Array(req.toBinary()),
    });
    const env = decodeFramedEnvelopeV3(
      await routerInvokeBin('token.burn', new Uint8Array(argPack.toBinary())),
    );
    if (env.payload.case === 'error') throw new Error(env.payload.value.message);
    if (env.payload.case !== 'tokenBurnResponse') {
      throw new Error(`Expected tokenBurnResponse, got ${env.payload.case}`);
    }
    const resp = env.payload.value;
    if (resp.success) {
      try {
        emitWalletRefresh({ source: 'token.burn', tokenId: resp.tokenId, anchorBase32: '' });
      } catch (e) {
        console.warn('burnToken: emitWalletRefresh failed (non-fatal):', e);
      }
    }
    return { success: Boolean(resp.success), newBalance: resp.newBalance, message: resp.message || undefined };
  } catch (e) {
    console.warn('burnToken failed:', e);
    return { success: false, message: e instanceof Error ? e.message : String(e) };
  }
}

/**
 * Authoritative token-creation fee, in ERA.
 *
 * DISPLAY ONLY. Rust reads the same core constant the conservation guard
 * validates against, so the number shown can never disagree with the number
 * charged. The UI must never hardcode this.
 */
export async function getTokenCreationFeeEra(): Promise<bigint | undefined> {
  try {
    const env = decodeFramedEnvelopeV3(
      await routerQueryBin('tokens.getFeeSchedule', new Uint8Array()),
    );
    if (env.payload.case !== 'tokenFeeScheduleResponse') return undefined;
    return env.payload.value.tokenCreationEra;
  } catch (e) {
    console.warn('getTokenCreationFeeEra failed:', e);
    return undefined;
  }
}
