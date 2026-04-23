/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/dsm/dlv.ts
// SPDX-License-Identifier: Apache-2.0
// DLV (Deterministic Limbo Vault) lifecycle helpers.
// All calls go through the normal AppRouter protobuf envelope path:
//   TypeScript → routerInvokeBin → MessagePort → Kotlin → JNI → Rust

import * as pb from '../proto/dsm_app_pb';
import { routerInvokeBin } from './WebViewBridge';
import { decodeBase32Crockford } from '../utils/textId';
import { decodeFramedEnvelopeV3 } from './decoding';

/**
 * Create a DLV (Deterministic Limbo Vault) from a serialised DlvInstantiateV1 proto.
 *
 * Commit 8 replaces this thin Base32-in/Base32-out wrapper with a typed
 * builder that takes a DlvSpecV1Input object + creatorPublicKey + optional
 * tokenId/lockedAmount + signature.  Commit 1 keeps the shape stable so
 * the frontend compiles against the new proto while handler wiring lands.
 *
 * @param params.lock  Base32 Crockford encoding of the DlvInstantiateV1 proto bytes.
 * @returns { success, id?, error? } — `id` is the vault_id as Base32 Crockford,
 *          produced by Rust from the DlvSpecV1 contents.
 */
export async function createCustomDlv(params: {
  lock: string;
  condition?: string;
}): Promise<{ success: boolean; id?: string; error?: string }> {
  try {
    const lockB32 = typeof params?.lock === 'string' ? params.lock.trim() : '';
    if (!lockB32) return { success: false, error: 'DLV create payload (lock) required' };

    const lockBytes = decodeBase32Crockford(lockB32);
    if (!lockBytes || lockBytes.length === 0) {
      return { success: false, error: 'decoded DlvInstantiateV1 bytes empty' };
    }

    // Validate that the payload decodes as a DlvInstantiateV1 proto.
    const req = pb.DlvInstantiateV1.fromBinary(lockBytes);
    if (!req.spec) {
      return { success: false, error: 'DlvInstantiateV1.spec is required' };
    }
    if (!req.spec.policyDigest || req.spec.policyDigest.length !== 32) {
      return { success: false, error: 'DlvSpecV1.policy_digest must be 32 bytes' };
    }
    if (!req.spec.contentDigest || req.spec.contentDigest.length !== 32) {
      return { success: false, error: 'DlvSpecV1.content_digest must be 32 bytes' };
    }
    if (!req.spec.fulfillmentDigest || req.spec.fulfillmentDigest.length !== 32) {
      return { success: false, error: 'DlvSpecV1.fulfillment_digest must be 32 bytes' };
    }
    if (!req.creatorPublicKey || req.creatorPublicKey.length === 0) {
      return { success: false, error: 'DlvInstantiateV1.creator_public_key is required' };
    }
    if (!req.signature || req.signature.length === 0) {
      return { success: false, error: 'DlvInstantiateV1.signature is required' };
    }

    const argPack = new pb.ArgPack({
      codec: pb.Codec.PROTO as any,
      body: new Uint8Array(lockBytes),
    });

    const resBytes = await routerInvokeBin('dlv.create', new Uint8Array(argPack.toBinary()));
    const env = decodeFramedEnvelopeV3(resBytes);

    if (env.payload.case === 'error') {
      return { success: false, error: env.payload.value.message || 'dlv.create failed' };
    }

    if (env.payload.case === 'appStateResponse') {
      const vaultIdB32 = env.payload.value.value ?? '';
      return { success: true, id: vaultIdB32 };
    }

    return {
      success: false,
      error: `Unexpected response payload: ${env.payload.case}`,
    };
  } catch (e: any) {
    return { success: false, error: e?.message || 'createCustomDlv failed' };
  }
}
