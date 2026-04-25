/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/dsm/posted_dlv.ts
// SPDX-License-Identifier: Apache-2.0
//
// Posted-mode DLV discovery + sync helpers.
//
// Routes (registered on the Rust side in `posted_dlv_routes.rs`):
//   * `posted_dlv.list`  (query)  — list active advertisements
//                                   addressed to the local device's
//                                   Kyber public key.
//   * `posted_dlv.sync`  (invoke) — fetch + verify + mirror every
//                                   active advertisement into the
//                                   local DLVManager so a subsequent
//                                   `dlv.claim` can succeed.
//
// Wire format: both routes return an `AppStateResponse.value` string
// in the v3 envelope; `value` is a newline-separated text list whose
// rows the helpers below parse into typed objects.  When the typed
// frontend wrapper is upgraded to a dedicated proto response, only
// these two parsers need to change.

import * as pb from '../proto/dsm_app_pb';
import { routerInvokeBin, routerQueryBin } from './WebViewBridge';
import { decodeFramedEnvelopeV3 } from './decoding';

/**
 * Lightweight summary row returned by `listPostedDlvs`.  Both fields
 * are Base32-Crockford strings the Rust handler emits directly so
 * paste-into-other-tool flows work without a second encode.
 */
export interface PostedDlvSummary {
  /** Vault id (32 bytes) as Base32 Crockford. */
  dlvIdBase32: string;
  /** Creator's SPHINCS+ public key as Base32 Crockford. */
  creatorPublicKeyBase32: string;
}

function parseAppStateResponse(env: pb.Envelope, route: string): string {
  if (env.payload.case === 'error') {
    throw new Error(env.payload.value.message || `${route}: error`);
  }
  if (env.payload.case !== 'appStateResponse') {
    throw new Error(`${route}: unexpected payload ${String(env.payload.case)}`);
  }
  return env.payload.value.value ?? '';
}

function parseLineList(value: string): string[] {
  if (!value) return [];
  return value
    .split('\n')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/**
 * List active posted-mode DLV advertisements addressed to the local
 * device's Kyber public key.  Read-only — does not mutate the local
 * DLVManager; pair with `syncPostedDlvs()` when the user actually
 * intends to claim.
 */
export async function listPostedDlvs(): Promise<{
  success: boolean;
  vaults?: PostedDlvSummary[];
  error?: string;
}> {
  try {
    const argPack = new pb.ArgPack({
      codec: pb.Codec.PROTO as any,
      body: new Uint8Array(),
    });
    const resBytes = await routerQueryBin(
      'posted_dlv.list',
      new Uint8Array(argPack.toBinary()),
    );
    const env = decodeFramedEnvelopeV3(resBytes);
    const value = parseAppStateResponse(env, 'posted_dlv.list');
    const rows = parseLineList(value);
    const vaults: PostedDlvSummary[] = rows.map((row) => {
      const [dlvIdBase32 = '', creatorPublicKeyBase32 = ''] = row.split(' ');
      return { dlvIdBase32, creatorPublicKeyBase32 };
    });
    return { success: true, vaults };
  } catch (e: any) {
    return { success: false, error: e?.message || 'listPostedDlvs failed' };
  }
}

/**
 * Fetch + verify + mirror every active advertisement into the local
 * DLVManager.  Returns the Base32 vault_ids that were freshly
 * inserted in this call (already-mirrored vaults are silently
 * skipped).  Idempotent — safe to call repeatedly.
 *
 * After this resolves, the corresponding `dlv.claim` calls on the
 * returned vault_ids will succeed against the local cache.
 */
export async function syncPostedDlvs(): Promise<{
  success: boolean;
  newlyMirroredBase32?: string[];
  error?: string;
}> {
  try {
    const argPack = new pb.ArgPack({
      codec: pb.Codec.PROTO as any,
      body: new Uint8Array(),
    });
    const resBytes = await routerInvokeBin(
      'posted_dlv.sync',
      new Uint8Array(argPack.toBinary()),
    );
    const env = decodeFramedEnvelopeV3(resBytes);
    const value = parseAppStateResponse(env, 'posted_dlv.sync');
    return { success: true, newlyMirroredBase32: parseLineList(value) };
  } catch (e: any) {
    return { success: false, error: e?.message || 'syncPostedDlvs failed' };
  }
}
