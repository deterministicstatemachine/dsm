/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/dsm/route_commit.ts
// SPDX-License-Identifier: Apache-2.0
//
// SoFi route-commit + atomic-unlock helpers (Track C.2 follow-on
// to chunks #3 / #4 / #5).
//
// Flow:
//   * Trader binds a Path → RouteCommitV1 → signs (signing currently
//     happens Rust-side; this module exposes the post-sign helpers
//     and a TS round-trip for the bytes).
//   * Trader calls `computeExternalCommitment(rcBytes)` — server
//     computes X via the SAME canonicalisation the SDK uses for
//     SPHINCS+ verification.  Trader gets X back as Base32 Crockford.
//   * Trader calls `publishExternalCommitment(rcBytes)` to write the
//     anchor at `defi/extcommit/{X_b32}`.
//   * Vault owners call `isExternalCommitmentVisible(xBytes)` to
//     check the anchor before invoking `unlockVaultRouted`.
//   * Vault owners call `unlockVaultRouted(vaultId, deviceId,
//     rcBytes)` which routes to `dlv.unlockRouted` — the eligibility
//     gate (chunks #4 + #5: SPHINCS+ verify + vault-in-route +
//     anchor-visible) runs server-side.
//
// All four helpers go over the standard ArgPack + Envelope v3 path
// through the JNI bridge.

import * as pb from '../proto/dsm_app_pb';
import { routerInvokeBin, routerQueryBin } from './WebViewBridge';
import { decodeFramedEnvelopeV3 } from './decoding';
import { decodeBase32Crockford, encodeBase32Crockford } from '../utils/textId';

function packBody(body: Uint8Array): Uint8Array {
  const argPack = new pb.ArgPack({
    codec: pb.Codec.PROTO as any,
    body,
  });
  return new Uint8Array(argPack.toBinary());
}

function readAppStateValue(env: pb.Envelope, route: string): string {
  if (env.payload.case === 'error') {
    throw new Error(env.payload.value.message || `${route}: error`);
  }
  if (env.payload.case !== 'appStateResponse') {
    throw new Error(`${route}: unexpected payload ${String(env.payload.case)}`);
  }
  return env.payload.value.value ?? '';
}

/**
 * Sign an unsigned `RouteCommitV1` byte payload with the local
 * wallet's SPHINCS+ key.  Per the "all business logic stays in Rust"
 * rule, all cryptographic operations run server-side: the trader UI
 * hands an unsigned RouteCommit to this helper, the Rust handler
 * stamps the wallet's public key on `initiator_public_key`,
 * canonicalises (zeros the signature field), runs SPHINCS+, and
 * returns the signed bytes ready for `computeExternalCommitment` →
 * `publishExternalCommitment`.
 *
 * Returns the signed RouteCommit as Base32 Crockford so the caller
 * can keep it as a single string token through the rest of the
 * publish flow.  Decode with `decodeBase32Crockford` before
 * forwarding to other helpers.
 */
export async function signRouteCommit(
  unsignedRouteCommitBytes: Uint8Array,
): Promise<{ success: boolean; signedRouteCommitBase32?: string; error?: string }> {
  try {
    if (
      !(unsignedRouteCommitBytes instanceof Uint8Array) ||
      unsignedRouteCommitBytes.length === 0
    ) {
      return { success: false, error: 'unsignedRouteCommitBytes required' };
    }
    const resBytes = await routerInvokeBin(
      'route.signRouteCommit',
      packBody(unsignedRouteCommitBytes),
    );
    const env = decodeFramedEnvelopeV3(resBytes);
    const signedRouteCommitBase32 = readAppStateValue(env, 'route.signRouteCommit');
    return { success: true, signedRouteCommitBase32 };
  } catch (e: any) {
    return { success: false, error: e?.message || 'signRouteCommit failed' };
  }
}

/**
 * Compute the external commitment `X = BLAKE3("DSM/ext\0" ||
 * canonical(RouteCommit{initiator_signature=[]}))` for a given
 * RouteCommitV1 byte payload.  Server-side compute keeps the
 * canonicalisation rule colocated with the SDK's SPHINCS+ verifier
 * — TS callers don't need to re-implement signature-zeroing.
 *
 * Returns X as Base32 Crockford (32 bytes → 52 chars).
 */
export async function computeExternalCommitment(
  routeCommitBytes: Uint8Array,
): Promise<{ success: boolean; xBase32?: string; error?: string }> {
  try {
    if (!(routeCommitBytes instanceof Uint8Array) || routeCommitBytes.length === 0) {
      return { success: false, error: 'routeCommitBytes required' };
    }
    const resBytes = await routerQueryBin(
      'route.computeExternalCommitment',
      packBody(routeCommitBytes),
    );
    const env = decodeFramedEnvelopeV3(resBytes);
    const xBase32 = readAppStateValue(env, 'route.computeExternalCommitment');
    return { success: true, xBase32 };
  } catch (e: any) {
    return { success: false, error: e?.message || 'computeExternalCommitment failed' };
  }
}

/**
 * Publish the external-commitment anchor to storage nodes.  Caller
 * supplies the 32-byte X (typically obtained via
 * `computeExternalCommitment` first) and an optional human-readable
 * label.  `publisherPublicKey` is optional: when omitted the Rust
 * handler stamps the wallet's current SPHINCS+ pk per the
 * "all crypto stays in Rust" rule.
 *
 * Once this resolves successfully every vault on the route may
 * atomically unlock — visibility of X is the trigger.
 */
export async function publishExternalCommitment(input: {
  x: Uint8Array;
  /** Optional — empty / omitted lets Rust stamp the wallet pk. */
  publisherPublicKey?: Uint8Array;
  label?: string;
}): Promise<{ success: boolean; xBase32?: string; error?: string }> {
  try {
    if (!input?.x || input.x.length !== 32) {
      return { success: false, error: 'x must be 32 bytes' };
    }
    const anchor = new pb.ExternalCommitmentV1({
      version: 1,
      x: input.x as any,
      // Empty bytes → Rust accept-or-stamp; the wallet pk is filled in.
      publisherPublicKey: (input.publisherPublicKey ?? new Uint8Array()) as any,
      label: input.label ?? '',
    });
    const resBytes = await routerInvokeBin(
      'route.publishExternalCommitment',
      packBody(new Uint8Array(anchor.toBinary())),
    );
    const env = decodeFramedEnvelopeV3(resBytes);
    const xBase32 = readAppStateValue(env, 'route.publishExternalCommitment');
    return { success: true, xBase32 };
  } catch (e: any) {
    return { success: false, error: e?.message || 'publishExternalCommitment failed' };
  }
}

/**
 * Check whether the anchor for X is currently visible at storage
 * nodes.  Vault-owner devices call this before invoking
 * `unlockVaultRouted` — if the anchor is absent the unlock would
 * be rejected by the SDK gate anyway, but the early check saves a
 * round trip and gives the UI a clean "waiting for trader to
 * publish" state.
 */
export async function isExternalCommitmentVisible(
  x: Uint8Array,
): Promise<{ success: boolean; visible?: boolean; error?: string }> {
  try {
    if (!(x instanceof Uint8Array) || x.length !== 32) {
      return { success: false, error: 'x must be 32 bytes' };
    }
    const resBytes = await routerQueryBin('route.isExternalCommitmentVisible', packBody(x));
    const env = decodeFramedEnvelopeV3(resBytes);
    const value = readAppStateValue(env, 'route.isExternalCommitmentVisible');
    if (value === 'true') return { success: true, visible: true };
    if (value === 'false') return { success: true, visible: false };
    return { success: false, error: `unexpected value: ${value}` };
  } catch (e: any) {
    return {
      success: false,
      error: e?.message || 'isExternalCommitmentVisible failed',
    };
  }
}

/**
 * Invoke the routed-unlock path on the local device.  Handler runs
 * the chunks #4 + #5 eligibility gate (SPHINCS+ verify the
 * RouteCommit, locate this vault's hop, confirm anchor visibility)
 * and only then emits `Operation::DlvUnlock` on the local actor's
 * self-loop.
 *
 * Returns the unlocked vault id as Base32 on success.  On any
 * eligibility failure the SDK error variant is surfaced verbatim
 * (e.g. `InvalidInitiatorSignature`, `VaultNotInRoute`,
 * `ExternalCommitmentNotVisible`) so the UI can render a precise
 * rejection reason.
 */
export async function unlockVaultRouted(input: {
  vaultId: Uint8Array;
  deviceId: Uint8Array;
  routeCommitBytes: Uint8Array;
  unlockerPublicKey?: Uint8Array;
  signature?: Uint8Array;
}): Promise<{ success: boolean; vaultIdBase32?: string; error?: string }> {
  try {
    if (!input?.vaultId || input.vaultId.length !== 32) {
      return { success: false, error: 'vaultId must be 32 bytes' };
    }
    if (!input.deviceId || input.deviceId.length !== 32) {
      return { success: false, error: 'deviceId must be 32 bytes' };
    }
    if (!input.routeCommitBytes || input.routeCommitBytes.length === 0) {
      return { success: false, error: 'routeCommitBytes is required' };
    }
    const req = new pb.DlvUnlockRoutedV1({
      vaultId: input.vaultId as any,
      deviceId: input.deviceId as any,
      routeCommitBytes: input.routeCommitBytes as any,
      unlockerPublicKey: (input.unlockerPublicKey ?? new Uint8Array()) as any,
      signature: (input.signature ?? new Uint8Array()) as any,
    });
    const resBytes = await routerInvokeBin(
      'dlv.unlockRouted',
      packBody(new Uint8Array(req.toBinary())),
    );
    const env = decodeFramedEnvelopeV3(resBytes);
    const vaultIdBase32 = readAppStateValue(env, 'dlv.unlockRouted');
    return { success: true, vaultIdBase32 };
  } catch (e: any) {
    return { success: false, error: e?.message || 'unlockVaultRouted failed' };
  }
}

// ─────────────────────────────────────────────────────────────────────
// Track C.3 — frontend trade-flow helpers
// ─────────────────────────────────────────────────────────────────────

/**
 * Big-endian u128 encoding helper.  Reused for amounts and reserves
 * across the trade-flow protos.  Pure framing — no protocol logic.
 */
function u128BigEndian(n: bigint): Uint8Array {
  if (n < 0n) throw new Error('amount must be non-negative');
  const out = new Uint8Array(16);
  let v = n;
  for (let i = 15; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new Error('amount exceeds u128');
  return out;
}

/**
 * Vault owner: publish a routing-vault advertisement for an AMM vault.
 * The Rust handler computes the BLAKE3 digest from
 * `vaultProtoBytes` per the chunk #1 substrate; frontend only frames
 * typed inputs.
 */
export async function publishRoutingAdvertisement(input: {
  vaultId: Uint8Array;
  tokenA: Uint8Array;
  tokenB: Uint8Array;
  reserveA: bigint;
  reserveB: bigint;
  feeBps: number;
  unlockSpecDigest: Uint8Array;
  unlockSpecKey: string;
  /** Optional — empty / omitted lets Rust stamp the wallet pk. */
  ownerPublicKey?: Uint8Array;
  vaultProtoBytes: Uint8Array;
}): Promise<{ success: boolean; vaultIdBase32?: string; error?: string }> {
  try {
    if (!input?.vaultId || input.vaultId.length !== 32) {
      return { success: false, error: 'vaultId must be 32 bytes' };
    }
    if (!input.unlockSpecDigest || input.unlockSpecDigest.length !== 32) {
      return { success: false, error: 'unlockSpecDigest must be 32 bytes' };
    }
    if (!input.vaultProtoBytes || input.vaultProtoBytes.length === 0) {
      return { success: false, error: 'vaultProtoBytes is required' };
    }
    const req = new pb.PublishRoutingAdvertisementRequest({
      vaultId: input.vaultId as any,
      tokenA: input.tokenA as any,
      tokenB: input.tokenB as any,
      reserveAU128: u128BigEndian(input.reserveA) as any,
      reserveBU128: u128BigEndian(input.reserveB) as any,
      feeBps: input.feeBps,
      unlockSpecDigest: input.unlockSpecDigest as any,
      unlockSpecKey: input.unlockSpecKey,
      // Empty bytes → Rust accept-or-stamp; wallet pk is filled in.
      ownerPublicKey: (input.ownerPublicKey ?? new Uint8Array()) as any,
      vaultProtoBytes: input.vaultProtoBytes as any,
    });
    const resBytes = await routerInvokeBin(
      'route.publishRoutingAdvertisement',
      packBody(new Uint8Array(req.toBinary())),
    );
    const env = decodeFramedEnvelopeV3(resBytes);
    const vaultIdBase32 = readAppStateValue(env, 'route.publishRoutingAdvertisement');
    return { success: true, vaultIdBase32 };
  } catch (e: any) {
    return {
      success: false,
      error: e?.message || 'publishRoutingAdvertisement failed',
    };
  }
}

/**
 * Lightweight summary returned by `listAdvertisementsForPair`.  Carries
 * the fields a trader UI needs to render liquidity without re-fetching.
 */
export interface RoutingAdvertisementSummary {
  vaultIdBase32: string;
  tokenA: Uint8Array;
  tokenB: Uint8Array;
  reserveA: bigint;
  reserveB: bigint;
  feeBps: number;
  stateNumber: bigint;
  ownerPublicKey: Uint8Array;
}

function decodeReserveBigInt(bytes: Uint8Array): bigint {
  let acc = 0n;
  for (const b of bytes) {
    acc = (acc << 8n) | BigInt(b);
  }
  return acc;
}

/**
 * Anyone: list active routing-vault advertisements for a token pair.
 * The handler returns a newline-separated list of Base32-encoded
 * `RoutingVaultAdvertisementV1` protos; this helper decodes each line
 * into a typed summary.
 *
 * Token-pair canonicalisation is the Rust side's responsibility — the
 * caller may pass `(A, B)` or `(B, A)` and get the same result.
 */
export async function listAdvertisementsForPair(input: {
  tokenA: Uint8Array;
  tokenB: Uint8Array;
}): Promise<{
  success: boolean;
  advertisements?: RoutingAdvertisementSummary[];
  error?: string;
}> {
  try {
    const req = new pb.RoutingPairRequest({
      tokenA: input.tokenA as any,
      tokenB: input.tokenB as any,
    });
    const resBytes = await routerQueryBin(
      'route.listAdvertisementsForPair',
      packBody(new Uint8Array(req.toBinary())),
    );
    const env = decodeFramedEnvelopeV3(resBytes);
    const value = readAppStateValue(env, 'route.listAdvertisementsForPair');
    const lines = value ? value.split('\n').filter((l) => l.length > 0) : [];
    const advertisements: RoutingAdvertisementSummary[] = lines.map((line) => {
      const adBytes = decodeBase32Crockford(line);
      const ad = pb.RoutingVaultAdvertisementV1.fromBinary(new Uint8Array(adBytes));
      return {
        vaultIdBase32: encodeBase32Crockford(ad.vaultId),
        tokenA: ad.tokenA,
        tokenB: ad.tokenB,
        reserveA: decodeReserveBigInt(ad.reserveAU128),
        reserveB: decodeReserveBigInt(ad.reserveBU128),
        feeBps: ad.feeBps,
        stateNumber: ad.updatedStateNumber,
        ownerPublicKey: ad.ownerPublicKey,
      };
    });
    return { success: true, advertisements };
  } catch (e: any) {
    return {
      success: false,
      error: e?.message || 'listAdvertisementsForPair failed',
    };
  }
}

/**
 * Trader: fetch + verify + mirror every routing vault for a pair into
 * the local DLVManager so a subsequent `findAndBindBestPath` and
 * `unlockVaultRouted` can re-simulate against the real vault state.
 * Idempotent — already-mirrored vaults are skipped.  Returns the
 * Base32 vault_ids that were freshly inserted in this call.
 */
export async function syncVaultsForPair(input: {
  tokenA: Uint8Array;
  tokenB: Uint8Array;
}): Promise<{
  success: boolean;
  newlyMirroredBase32?: string[];
  error?: string;
}> {
  try {
    const req = new pb.RoutingPairRequest({
      tokenA: input.tokenA as any,
      tokenB: input.tokenB as any,
    });
    const resBytes = await routerInvokeBin(
      'route.syncVaultsForPair',
      packBody(new Uint8Array(req.toBinary())),
    );
    const env = decodeFramedEnvelopeV3(resBytes);
    const value = readAppStateValue(env, 'route.syncVaultsForPair');
    const lines = value ? value.split('\n').filter((l) => l.length > 0) : [];
    return { success: true, newlyMirroredBase32: lines };
  } catch (e: any) {
    return { success: false, error: e?.message || 'syncVaultsForPair failed' };
  }
}

/**
 * Trader: ask Rust to run chunk #2 path search over the locally-known
 * advertisements (caller should `syncVaultsForPair` first) and bind
 * the chosen Path into an UNSIGNED `RouteCommitV1`.  The wallet's pk
 * is stamped during the subsequent `signRouteCommit` call, not here.
 *
 * Returns the unsigned RouteCommit bytes (not Base32) — pass them
 * directly into `signRouteCommit`.
 */
export async function findAndBindBestPath(input: {
  inputToken: Uint8Array;
  outputToken: Uint8Array;
  inputAmount: bigint;
  /** 32-byte random nonce for replay protection.  Caller MUST pick
   *  a fresh value per route. */
  nonce: Uint8Array;
  /** 0 → server default (4). */
  maxHops?: number;
}): Promise<{
  success: boolean;
  unsignedRouteCommitBytes?: Uint8Array;
  error?: string;
}> {
  try {
    if (!input?.nonce || input.nonce.length !== 32) {
      return { success: false, error: 'nonce must be 32 bytes' };
    }
    const req = new pb.FindAndBindRouteRequest({
      inputToken: input.inputToken as any,
      outputToken: input.outputToken as any,
      inputAmountU128: u128BigEndian(input.inputAmount) as any,
      maxHops: input.maxHops ?? 0,
      nonce: input.nonce as any,
    });
    const resBytes = await routerInvokeBin(
      'route.findAndBindBestPath',
      packBody(new Uint8Array(req.toBinary())),
    );
    const env = decodeFramedEnvelopeV3(resBytes);
    const base32 = readAppStateValue(env, 'route.findAndBindBestPath');
    const unsignedRouteCommitBytes = new Uint8Array(decodeBase32Crockford(base32));
    return { success: true, unsignedRouteCommitBytes };
  } catch (e: any) {
    return { success: false, error: e?.message || 'findAndBindBestPath failed' };
  }
}
