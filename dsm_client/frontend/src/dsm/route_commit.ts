/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/dsm/route_commit.ts
// SPDX-License-Identifier: Apache-2.0
//
// DeTFi route-commit + atomic-unlock helpers (Track C.2 follow-on
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
 * `computeExternalCommitment` first), the publisher's SPHINCS+
 * public key, and an optional human-readable label.
 *
 * Once this resolves successfully every vault on the route may
 * atomically unlock — visibility of X is the trigger.
 */
export async function publishExternalCommitment(input: {
  x: Uint8Array;
  publisherPublicKey: Uint8Array;
  label?: string;
}): Promise<{ success: boolean; xBase32?: string; error?: string }> {
  try {
    if (!input?.x || input.x.length !== 32) {
      return { success: false, error: 'x must be 32 bytes' };
    }
    if (!input.publisherPublicKey || input.publisherPublicKey.length === 0) {
      return { success: false, error: 'publisherPublicKey is required' };
    }
    const anchor = new pb.ExternalCommitmentV1({
      version: 1,
      x: input.x as any,
      publisherPublicKey: input.publisherPublicKey as any,
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
