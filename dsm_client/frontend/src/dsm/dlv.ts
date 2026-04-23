/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/dsm/dlv.ts
// SPDX-License-Identifier: Apache-2.0
// DLV (Deterministic Limbo Vault) lifecycle helpers.
// All calls go through the normal AppRouter protobuf envelope path:
//   TypeScript → routerInvokeBin → MessagePort → Kotlin → JNI → Rust

import * as pb from '../proto/dsm_app_pb';
import { routerInvokeBin } from './WebViewBridge';
import { decodeBase32Crockford, encodeBase32Crockford } from '../utils/textId';
import { decodeFramedEnvelopeV3 } from './decoding';

/**
 * Typed input for constructing a `DlvInstantiateV1` proto payload
 * without hand-packing the v2 TLV.
 *
 * BLAKE3 is not yet in the frontend bundle so the caller is expected
 * to supply `contentDigest` and `fulfillmentDigest` pre-computed (via
 * Rust over the bridge, or via an ambient hashing helper wired in a
 * later commit).  The Rust `dlv.create` handler strict-verifies that
 * each digest matches its bytes; a mismatched pair will be rejected
 * at the core boundary before any state transition runs.
 */
export interface BuildDlvInstantiateInput {
  /** 32-byte CPTA anchor bound to the token's policy.  Typically the
   *  Base32-Crockford-decoded response from `tokens.publishPolicy`. */
  policyDigest: Uint8Array;
  /** `blake3("DSM/dlv-content\0" || content)` — 32 bytes. */
  contentDigest: Uint8Array;
  /** `blake3("DSM/dlv-fulfillment\0" || fulfillmentBytes)` — 32 bytes. */
  fulfillmentDigest: Uint8Array;
  /** Plaintext bytes the vault will hold (local mode) or the
   *  sender-encrypted ciphertext (posted mode). */
  content: Uint8Array;
  /** Canonical `FulfillmentMechanism` proto bytes. */
  fulfillmentBytes: Uint8Array;
  /** Optional Kyber pk of the intended recipient.  Empty = self-encrypted. */
  intendedRecipient?: Uint8Array;
  /** SPHINCS+ pk of the creator. */
  creatorPublicKey: Uint8Array;
  /** Optional token_id for a balance-locked vault.  Empty = content-only. */
  tokenId?: string;
  /** Optional locked amount (u128, big-endian).  Pass `0n` / omit for no lock. */
  lockedAmount?: bigint;
  /** SPHINCS+ signature over the canonical `Operation::DlvCreate` bytes. */
  signature: Uint8Array;
}

function lockedAmountU128BigEndian(n: bigint): Uint8Array {
  if (n < 0n) throw new Error('lockedAmount must be non-negative');
  const out = new Uint8Array(16);
  let v = n;
  for (let i = 15; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new Error('lockedAmount exceeds u128');
  return out;
}

/**
 * Build the canonical `DlvInstantiateV1` proto bytes from typed inputs.
 *
 * Digests are not computed here — the caller supplies
 * `contentDigest = H("DSM/dlv-content", content)` and
 * `fulfillmentDigest = H("DSM/dlv-fulfillment", fulfillmentBytes)`
 * matching the Rust handler's strict-verify pair.  A mismatch fails
 * closed at the core boundary before any state advance.
 */
export function buildDlvInstantiateBytes(input: BuildDlvInstantiateInput): Uint8Array {
  if (input.policyDigest.length !== 32) {
    throw new Error('policyDigest must be 32 bytes');
  }
  if (input.contentDigest.length !== 32) {
    throw new Error('contentDigest must be 32 bytes');
  }
  if (input.fulfillmentDigest.length !== 32) {
    throw new Error('fulfillmentDigest must be 32 bytes');
  }
  if (input.creatorPublicKey.length === 0) {
    throw new Error('creatorPublicKey is required');
  }
  if (input.signature.length === 0) {
    throw new Error('signature is required');
  }

  const spec = new pb.DlvSpecV1({
    policyDigest: input.policyDigest as any,
    contentDigest: input.contentDigest as any,
    fulfillmentDigest: input.fulfillmentDigest as any,
    intendedRecipient: (input.intendedRecipient ?? new Uint8Array()) as any,
    fulfillmentBytes: input.fulfillmentBytes as any,
    content: input.content as any,
  });

  const lockedBytes =
    input.lockedAmount !== undefined
      ? lockedAmountU128BigEndian(input.lockedAmount)
      : new Uint8Array(16);

  const req = new pb.DlvInstantiateV1({
    spec,
    creatorPublicKey: input.creatorPublicKey as any,
    tokenId: (input.tokenId
      ? new TextEncoder().encode(input.tokenId)
      : new Uint8Array()) as any,
    lockedAmountU128: lockedBytes as any,
    signature: input.signature as any,
  });

  return new Uint8Array(req.toBinary());
}

/**
 * Typed convenience around `createCustomDlv`: builds the
 * `DlvInstantiateV1` bytes via `buildDlvInstantiateBytes` and then
 * routes them through the standard Base32 + ArgPack wire path.
 *
 * Preferred entry point from UI code; keeps the low-level
 * `createCustomDlv({ lock })` surface for paste-Base32 developer tools.
 */
export async function createDlv(
  input: BuildDlvInstantiateInput,
): Promise<{ success: boolean; id?: string; error?: string }> {
  try {
    const bytes = buildDlvInstantiateBytes(input);
    return await createCustomDlv({ lock: encodeBase32Crockford(bytes) });
  } catch (e: any) {
    return { success: false, error: e?.message || 'createDlv failed' };
  }
}

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
