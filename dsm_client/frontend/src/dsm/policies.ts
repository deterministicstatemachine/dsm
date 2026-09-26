// SPDX-License-Identifier: MIT OR Apache-2.0

/* eslint-disable @typescript-eslint/no-explicit-any */
import * as pb from '../proto/dsm_app_pb';
import {
  routerInvokeBin,
  routerQueryBin,
  addTokenByAnchor as addTokenByAnchorBridge,
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
/**
 * What a token is created with (SoFi §48–§51). The whole genesis supply is
 * released to the creator at creation; there is no minting afterwards, and no
 * unlimited supply.
 */
export interface TokenCreateDetails {
  ticker: string;
  alias: string;
  decimals: number;
  /** The whole supply, in base units. Fixed at creation. */
  genesisSupply: string;
  /** Whether holders may burn their own units. */
  burnEnabled: boolean;
  transferable: boolean;
  threshold: number;
  description?: string;
  iconUrl?: string;
  allowlistKind?: 'NONE' | 'INLINE';
  allowlistData?: string;
}

export async function createToken(details: TokenCreateDetails): Promise<{ success: boolean; tokenId?: string; anchorBase32?: string; message?: string }> {
  try {
    const u128be = (v: string | number): Uint8Array => {
      const text = String(v).trim();
      if (!/^\d+$/.test(text)) throw new Error('createToken: the genesis supply must be a whole number');
      const out = new Uint8Array(16);
      let n = BigInt(text);
      for (let i = 15; i >= 0; i--) {
        out[i] = Number(n & 0xffn);
        n >>= 8n;
      }
      if (n !== 0n) throw new Error('createToken: amount exceeds u128');
      return out;
    };

    const allowlist: Uint8Array[] =
      details.allowlistKind === 'INLINE'
        ? (details.allowlistData ?? '')
            .split(/[\s,]+/)
            .map((s) => s.trim())
            .filter(Boolean)
            .map((s) => new Uint8Array(decodeBase32Crockford(s)))
        : [];

    // What the user entered, as entered. Rust trims and uppercases the ticker
    // and refuses what its rules refuse; nothing is filled in here for a
    // value the caller did not give.
    const req = new pb.TokenCreateRequest({
      ticker: details.ticker,
      alias: details.alias,
      decimals: details.decimals,
      genesisSupplyU128: u128be(details.genesisSupply) as any,
      burnEnabled: details.burnEnabled,
      transferable: details.transferable,
      threshold: details.threshold,
      description: details.description ?? '',
      iconUrl: details.iconUrl ?? '',
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
    if (!resp.success) {
      return { success: false, message: resp.message };
    }
    // Rust names the token it created; an answer without its id and anchor
    // is refused, never shown as a token with none.
    if (!resp.tokenId || resp.policyAnchor.length !== 32) {
      throw new Error('STRICT: token.create answered success without the token id and its 32-byte anchor');
    }
    const anchorBase32 = encodeBase32Crockford(resp.policyAnchor);

    // The token exists from here. The wallet re-fetches balances and metadata
    // on this event; a listener's failure is logged, not reported as a failed
    // creation.
    try {
      emitWalletRefresh({ source: 'token.create', tokenId: resp.tokenId, anchorBase32 });
    } catch (e) {
      console.warn('createToken: a wallet.refresh listener failed:', e);
    }

    return { success: true, tokenId: resp.tokenId, anchorBase32, message: resp.message };
  } catch (e) {
    console.warn('createToken failed:', e);
    return { success: false, message: e instanceof Error ? e.message : String(e) };
  }
}

/**
 * Add a token created on another device, by its CPTA anchor.
 *
 * PURE TRANSPORT. Rust fetches the published policy, re-derives the anchor
 * from the bytes and requires it to match what was asked for, parses it, and
 * registers the token locally. Nothing here interprets the policy.
 *
 * This is the step between "someone created a token" and "I can receive it":
 * balances are keyed by policy commitment, so a device that has not added the
 * CPTA has nowhere to put the token and no rules to enforce on it.
 */
/// Adopt a token from whatever the user supplied.
///
/// The TEXT is handed to Rust verbatim — a bare Base32 anchor or a
/// `dsm:token/v1:` payload from a scan. Rust decides what a pasted string
/// means, rejects a scanned payload whose ticker disagrees with the policy it
/// fetches, and answers the token it registered: its id, its ticker and the
/// anchor it re-derived from the policy bytes.
export async function addTokenByAnchor(
  args: string | { anchorBase32: string },
): Promise<
  | { success: true; tokenId: string; ticker: string; anchorBase32: string }
  | { success: false; error: string }
> {
  try {
    const text = (typeof args === 'string' ? args : args.anchorBase32).trim();
    if (!text) throw new Error('addTokenByAnchor: anchor required');

    const env = decodeFramedEnvelopeV3(await addTokenByAnchorBridge(new TextEncoder().encode(text)));
    if (env.payload.case === 'error') throw new Error(env.payload.value.message || 'add token failed');
    if (env.payload.case !== 'tokenCreateResponse') {
      throw new Error(`Expected tokenCreateResponse, got ${env.payload.case}`);
    }
    const r = env.payload.value;
    if (!r.success) throw new Error(r.message || 'add token failed');
    if (!r.tokenId || !r.ticker || r.policyAnchor.length !== 32) {
      throw new Error('STRICT: tokens.addByAnchor answered success without the token id, its ticker and its 32-byte anchor');
    }
    const anchorBase32 = encodeBase32Crockford(r.policyAnchor);
    emitWalletRefresh({ source: 'tokens.addByAnchor', tokenId: r.tokenId, anchorBase32 });
    return { success: true, tokenId: r.tokenId, ticker: r.ticker, anchorBase32 };
  } catch (e) {
    return { success: false, error: e instanceof Error ? e.message : String(e) };
  }
}

/// The scannable adoption payload for a token this device holds.
///
/// Rust assembles the complete `dsm:token/v1:` URI so the framing has one
/// implementation; this fetches it and the fields shown beside it.
export async function tokenAdoptionQr(tokenIdOrTicker: string): Promise<{
  uri: string;
  ticker: string;
  tokenId: string;
  policyAnchorB32: string;
  anchorFingerprint: string;
}> {
  const raw = await routerQueryBin(
    'token.adoptionQr',
    new TextEncoder().encode(tokenIdOrTicker.trim()),
  );
  const env = decodeFramedEnvelopeV3(raw);
  if (env.payload.case === 'error') throw new Error(env.payload.value.message);
  if (env.payload.case !== 'tokenAdoptionQrResponse') {
    throw new Error(`Expected tokenAdoptionQrResponse, got ${env.payload.case}`);
  }
  const r = env.payload.value;
  return {
    uri: r.uri,
    ticker: r.ticker,
    tokenId: r.tokenId,
    policyAnchorB32: r.policyAnchorB32,
    anchorFingerprint: r.anchorFingerprint,
  };
}

export async function publishTokenPolicyBytes(policyBytes: Uint8Array): Promise<{ anchorBytes: Uint8Array; anchorBase32: string }> {
  if (!policyBytes || policyBytes.length === 0) throw new Error('publishTokenPolicyBytes: policyBytes required');
  const anchorBytes = await publishTokenPolicyBytesBridge(policyBytes);
  return { anchorBytes, anchorBase32: encodeBase32Crockford(anchorBytes) };
}

/**
 * Publish a token policy: the Base32 Crockford of serialized TokenPolicyV3
 * bytes, sent to Rust exactly as pasted. Rust refuses bytes Core's policy
 * parser does not accept; its anchor is the BLAKE3 content hash of those
 * bytes; it keeps the policy on this device and answers whether the network
 * stored it.
 *
 * This is the entry point for the DevPolicyScreen "Publish Policy" action.
 */
export async function publishTokenPolicy(input: {
  policyBase32: string;
}): Promise<{ success: true; id: string } | { success: false; error: string }> {
  try {
    const b32 = typeof input?.policyBase32 === 'string' ? input.policyBase32.trim() : '';
    if (!b32) return { success: false, error: 'policy bytes required (base32)' };

    const bytes = decodeBase32Crockford(b32);
    if (!bytes || bytes.length === 0) return { success: false, error: 'decoded policy bytes empty' };

    // Exactly the bytes pasted: the anchor is their hash, so a re-encoding here
    // would publish another policy's bytes under another anchor.
    const published = await publishTokenPolicyBytes(new Uint8Array(bytes));
    return { success: true, id: published.anchorBase32 };
  } catch (e: any) {
    return { success: false, error: e?.message || 'Policy publish failed' };
  }
}

/// Drop a token's identity from this device.
///
/// A ticker names one token, so a device that has adopted one cannot adopt a
/// different token with the same ticker. Without this there was no way out of
/// that: a superseded token — one whose creator re-created it, producing a new
/// policy anchor and therefore a new token id — blocked its own ticker
/// forever.
///
/// The backend refuses while a balance is held, and refuses outright for
/// protocol assets. Nothing recoverable is lost: the policy is
/// content-addressed and adoption is online, so it can always be adopted again.
export async function forgetToken(
  tokenId: string,
): Promise<{ success: boolean; message?: string }> {
  const req = new pb.TokenForgetRequest({ tokenId: tokenId.trim() } as any);
  const argPack = new pb.ArgPack({
    codec: pb.Codec.PROTO as any,
    body: new Uint8Array(req.toBinary()),
  });
  const env = decodeFramedEnvelopeV3(
    await routerInvokeBin('token.forget', new Uint8Array(argPack.toBinary())),
  );
  if (env.payload.case === 'error') throw new Error(env.payload.value.message);
  if (env.payload.case !== 'tokenForgetResponse') {
    throw new Error(`Expected tokenForgetResponse, got ${env.payload.case}`);
  }
  const resp = env.payload.value;
  return { success: resp.success, message: resp.message };
}

/** A whole-number amount as typed; a blank or non-numeric one is refused, never read as 0. */
function wholeAmount(action: string, value: string | number): bigint {
  const text = String(value).trim();
  if (!/^\d+$/.test(text)) throw new Error(`${action}: the amount must be a whole number`);
  return BigInt(text);
}

/** Burn supply the caller holds. Burn <= balance is enforced by the core conservation guard. */
export async function burnToken(args: { tokenId: string; amount: string | number; message?: string }): Promise<{ success: boolean; newBalance?: bigint; message?: string }> {
  try {
    const req = new pb.TokenBurnRequest({
      tokenId: args.tokenId.trim(),
      amount: wholeAmount('burnToken', args.amount),
      message: args.message ?? '',
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
 * The token-creation fee, in ERA, as Rust reports it.
 *
 * DISPLAY ONLY. Rust reads the same core constant the conservation guard
 * validates against, so the number shown can never disagree with the number
 * charged. A failed query is the failure, for the screen to show; it is not
 * an absent fee.
 */
export async function getTokenCreationFeeEra(): Promise<bigint> {
  const env = decodeFramedEnvelopeV3(
    await routerQueryBin('tokens.getFeeSchedule', new Uint8Array()),
  );
  if (env.payload.case === 'error') throw new Error(env.payload.value.message);
  if (env.payload.case !== 'tokenFeeScheduleResponse') {
    throw new Error(`Expected tokenFeeScheduleResponse, got ${env.payload.case}`);
  }
  return env.payload.value.tokenCreationEra;
}
