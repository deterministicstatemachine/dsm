// SPDX-License-Identifier: Apache-2.0

// path: src/dsm/vaultState.ts
//
// Read-side binding for Tier 2 Foundation vault state anchors.
// Pure proto framing — zero crypto on the TS side per the
// "all business logic stays in Rust" architectural rule.
//
// The Rust handler (`dlv.getVaultStateAnchor`) base32-encodes the
// signed `VaultStateAnchorV1` proto bytes into
// `AppStateResponse.value`, or returns an empty value when no
// anchor has been published yet.  This binding decodes that
// shape into a typed result; signature verification stays
// Rust-side at the routed-unlock gate.

/* eslint-disable @typescript-eslint/no-explicit-any */

import * as pb from '../proto/dsm_app_pb';
import { routerQueryBin } from './WebViewBridge';
import { decodeFramedEnvelopeV3 } from './decoding';
import { encodeBase32Crockford, decodeBase32Crockford } from '../utils/textId';

export interface VaultStateAnchor {
  vaultIdBase32: string;
  sequence: bigint;
  reservesDigest: Uint8Array;
  ownerPublicKey: Uint8Array;
  ownerSignature: Uint8Array;
}

/**
 * Fetch the latest published `VaultStateAnchorV1` for a given vault.
 * Returns `anchor: null` when no anchor has been published yet
 * (best-effort publish may have skipped or failed).  Frontend never
 * verifies the signature — that is enforced Rust-side at the
 * routed-unlock gate, which uses vault internal state as the truth
 * source anyway.
 */
export async function getVaultStateAnchor(
  vaultIdBase32: string,
): Promise<{ success: boolean; anchor?: VaultStateAnchor | null; error?: string }> {
  try {
    const argPack = new pb.ArgPack({
      codec: pb.Codec.PROTO as any,
      body: new TextEncoder().encode(vaultIdBase32),
    });
    const resBytes = await routerQueryBin(
      'dlv.getVaultStateAnchor',
      new Uint8Array(argPack.toBinary()),
    );
    const env = decodeFramedEnvelopeV3(resBytes);
    if (env.payload.case === 'error') {
      return {
        success: false,
        error: env.payload.value.message || 'dlv.getVaultStateAnchor failed',
      };
    }
    if (env.payload.case !== 'appStateResponse') {
      return {
        success: false,
        error: `Unexpected response payload: ${String(env.payload.case)}`,
      };
    }
    const value = env.payload.value.value ?? '';
    if (!value) {
      return { success: true, anchor: null };
    }
    const anchorBytes = decodeBase32Crockford(value);
    const proto = pb.VaultStateAnchorV1.fromBinary(new Uint8Array(anchorBytes));
    return {
      success: true,
      anchor: {
        vaultIdBase32: encodeBase32Crockford(proto.vaultId),
        sequence: proto.sequence,
        reservesDigest: proto.reservesDigest,
        ownerPublicKey: proto.ownerPublicKey,
        ownerSignature: proto.ownerSignature,
      },
    };
  } catch (e: any) {
    return { success: false, error: e?.message || 'getVaultStateAnchor failed' };
  }
}
