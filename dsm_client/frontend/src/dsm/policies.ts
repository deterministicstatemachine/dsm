/* eslint-disable @typescript-eslint/no-explicit-any */
import * as pb from '../proto/dsm_app_pb';
import {
  routerInvokeBin,
  getTokenPolicyBytes as getTokenPolicyBytesBridge,
  listCachedTokenPolicies,
  publishTokenPolicyBytes as publishTokenPolicyBytesBridge,
} from './WebViewBridge';
import { encodeBase32Crockford, decodeBase32Crockford } from '../utils/textId';
import { decodeFramedEnvelopeV3 } from './decoding';
import { emitWalletRefresh } from './events';

export async function createToken(details: any): Promise<{ success: boolean; tokenId?: string; anchorBase32?: string; message?: string }> {
  try {
    const ticker = String(details?.ticker || '').trim().toUpperCase();
    const alias = String(details?.alias || '').trim();
    const decimals = Number(details?.decimals ?? 0);
    const maxSupplyStr = String(details?.maxSupply ?? '').trim();

    if (!ticker || ticker.length < 2 || ticker.length > 8) {
      throw new Error('createToken: ticker must be 2-8 uppercase chars');
    }
    if (!alias) throw new Error('createToken: alias required');
    if (!Number.isInteger(decimals) || decimals < 0 || decimals > 18) {
      throw new Error('createToken: decimals must be 0..18');
    }
    if (!/^[0-9]+$/.test(maxSupplyStr)) {
      throw new Error('createToken: maxSupply must be a positive integer string');
    }

    const enc = new TextEncoder();
    const tickerBytes = enc.encode(ticker);
    const aliasBytes = enc.encode(alias);

    if (tickerBytes.length > 255) throw new Error('createToken: ticker too long');
    if (aliasBytes.length > 65535) throw new Error('createToken: alias too long');

    const maxSupply = BigInt(maxSupplyStr);
    if (maxSupply < 0n) throw new Error('createToken: maxSupply must be >= 0');

    const kindMap: Record<string, number> = { FUNGIBLE: 0, NFT: 1, SBT: 2 };
    const kindByte = kindMap[String(details?.kind || 'FUNGIBLE')] ?? 0;
    const unlimitedSupplyV2 = Boolean(details?.unlimitedSupply);
    const mintBurnEnabled = Boolean(details?.mintBurnEnabled);
    const transferable = Boolean(details?.transferable !== false);
    const allowlistKind = String(details?.allowlistKind || 'NONE') === 'INLINE' ? 'INLINE' : 'NONE';
    const mintBurnThreshold = Math.max(1, Math.min(255, Number(details?.mintBurnThreshold ?? 1)));
    const descBytes   = enc.encode(String(details?.description || '').trim());
    const iconBytes   = enc.encode(String(details?.iconUrl    || '').trim());
    const allocStr    = String(details?.initialAlloc || '0').trim();
    const allocBig    = /^[0-9]+$/.test(allocStr) ? BigInt(allocStr) : 0n;
    const alDataStr   = allowlistKind === 'INLINE' ? String(details?.allowlistData || '').trim() : '';
    const alDataBytes = enc.encode(alDataStr);

    const flags =
      (mintBurnEnabled          ? 0x01 : 0) |
      (transferable             ? 0x02 : 0) |
      (allowlistKind !== 'NONE' ? 0x04 : 0) |
      (unlimitedSupplyV2        ? 0x08 : 0);

    const maxSupplyBytes = new Uint8Array(16);
    {
      let tmp = maxSupply;
      for (let i = 15; i >= 0; i--) {
        maxSupplyBytes[i] = Number(tmp & 0xffn);
        tmp >>= 8n;
      }
    }

    const allocBytes = new Uint8Array(16);
    {
      let tmp2 = allocBig;
      for (let i = 15; i >= 0; i--) {
        allocBytes[i] = Number(tmp2 & 0xffn);
        tmp2 >>= 8n;
      }
    }
    const payloadSize = 1 + 1 + 1 + 1                        // ver + kind + flags + threshold
      + 1 + tickerBytes.length                               // tickerLen + ticker
      + 2 + aliasBytes.length                                // aliasLen(2B) + alias
      + 1 + 16 + 16                                          // decimals + maxSupply + initialAlloc
      + 2 + descBytes.length                                 // descLen(2B) + desc
      + 2 + iconBytes.length                                 // iconLen(2B) + icon
      + 1 + 2 + alDataBytes.length;                          // alKind + alDataLen(2B) + alData
    const policyPayload = new Uint8Array(payloadSize);
    let off = 0;
    policyPayload[off++] = 2;
    policyPayload[off++] = kindByte;
    policyPayload[off++] = flags;
    policyPayload[off++] = mintBurnThreshold;
    policyPayload[off++] = tickerBytes.length & 0xff;
    policyPayload.set(tickerBytes, off); off += tickerBytes.length;
    policyPayload[off++] = (aliasBytes.length >>> 8) & 0xff;
    policyPayload[off++] = aliasBytes.length & 0xff;
    policyPayload.set(aliasBytes, off); off += aliasBytes.length;
    policyPayload[off++] = decimals & 0xff;
    policyPayload.set(maxSupplyBytes, off); off += 16;
    policyPayload.set(allocBytes, off); off += 16;
    policyPayload[off++] = (descBytes.length >>> 8) & 0xff;
    policyPayload[off++] = descBytes.length & 0xff;
    policyPayload.set(descBytes, off); off += descBytes.length;
    policyPayload[off++] = (iconBytes.length >>> 8) & 0xff;
    policyPayload[off++] = iconBytes.length & 0xff;
    policyPayload.set(iconBytes, off); off += iconBytes.length;
    policyPayload[off++] = allowlistKind === 'INLINE' ? 1 : 0;
    policyPayload[off++] = (alDataBytes.length >>> 8) & 0xff;
    policyPayload[off++] = alDataBytes.length & 0xff;
    policyPayload.set(alDataBytes, off);

    const policy = new pb.TokenPolicyV3({ policyBytes: policyPayload as any });
    const canonicalBytes = policy.toBinary();

    const published = await publishTokenPolicyBytes(new Uint8Array(canonicalBytes));
    const anchorBytes = published.anchorBytes;
    if (!anchorBytes || anchorBytes.length !== 32) {
      throw new Error('createToken: policy publish failed');
    }

    const req = new pb.TokenCreateRequest({
      ticker,
      alias,
      decimals,
      maxSupplyU128: maxSupplyBytes as any,
      policyAnchor: anchorBytes as any,
    } as any);

    const argPack = new pb.ArgPack({
      codec: pb.Codec.PROTO as any,
      body: new Uint8Array(req.toBinary()),
    });

    const resBytes = await routerInvokeBin('token.create', new Uint8Array(argPack.toBinary()));

    // Canonical Envelope v3 decode (TokenCreateResponse now in Envelope payload oneof)
    const env = decodeFramedEnvelopeV3(resBytes);
    
    if (env.payload.case === 'error') {
      throw new Error(`Token creation failed: ${env.payload.value.message}`);
    }
    
    if (env.payload.case !== 'tokenCreateResponse') {
      throw new Error(`Expected tokenCreateResponse, got ${env.payload.case}`);
    }
    
    const resp = env.payload.value;
    const anchorB32 = resp.policyAnchor?.length === 32
      ? encodeBase32Crockford(resp.policyAnchor)
      : published.anchorBase32;
    const tokenId = resp.tokenId || undefined;
    const success = Boolean(resp.success);
    // Notify the wallet UI that a new token has been registered so
    // `TokenManagementScreen` (and any other listener) can re-fetch
    // its balances + metadata cache without the user having to pull-
    // to-refresh.  Single canonical refresh event per
    // `events.ts::DSM_WALLET_REFRESH_EVENT`.
    if (success) {
      try {
        emitWalletRefresh({
          source: 'token.create',
          tokenId: tokenId ?? '',
          anchorBase32: anchorB32 ?? '',
        });
      } catch (e) {
        console.warn('createToken: emitWalletRefresh failed (non-fatal):', e);
      }
    }
    return {
      success,
      tokenId,
      anchorBase32: anchorB32,
      message: resp.message || undefined,
    };
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
