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
 * Per the "all business logic stays in Rust" rule, this builder is a
 * PURE proto packer — no cryptography, no protocol-defined hashing.
 * `content_digest` and `fulfillment_digest` ride the wire as empty
 * bytes; the Rust `dlv.create` handler computes them from
 * `BLAKE3("DSM/dlv-content\0" || content)` and
 * `BLAKE3("DSM/dlv-fulfillment\0" || fulfillment_bytes)` and uses
 * them as the canonical values.  A future caller that already holds
 * pre-computed digests (e.g. derived off-device for an air-gapped
 * vault) MAY pass them in — the Rust handler strict-verifies any
 * supplied 32-byte digest against the local computation and rejects
 * mismatches.
 */
export interface BuildDlvInstantiateInput {
  /** 32-byte CPTA anchor bound to the token's policy.  Typically the
   *  Base32-Crockford-decoded response from `tokens.publishPolicy`. */
  policyDigest: Uint8Array;
  /** Optional pre-computed digest.  Default = empty (Rust computes). */
  contentDigest?: Uint8Array;
  /** Optional pre-computed digest.  Default = empty (Rust computes). */
  fulfillmentDigest?: Uint8Array;
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
 * Build the canonical `DlvInstantiateV1` proto bytes from typed
 * inputs.  Pure proto packer — no cryptography runs in the frontend.
 *
 * `contentDigest` / `fulfillmentDigest` ride the wire as supplied
 * (default: empty); the Rust `dlv.create` handler computes them
 * from `BLAKE3("DSM/dlv-content\0" || content)` /
 * `BLAKE3("DSM/dlv-fulfillment\0" || fulfillment_bytes)` and uses
 * those as the canonical values.  A caller that DID pre-hash off-
 * device (e.g. air-gapped signing) MAY pass the digests in; the
 * Rust handler strict-verifies any 32-byte digest it receives.
 */
export function buildDlvInstantiateBytes(input: BuildDlvInstantiateInput): Uint8Array {
  if (input.policyDigest.length !== 32) {
    throw new Error('policyDigest must be 32 bytes');
  }
  if (input.creatorPublicKey.length === 0) {
    throw new Error('creatorPublicKey is required');
  }
  if (input.signature.length === 0) {
    throw new Error('signature is required');
  }
  // Length sanity for caller-supplied digests.  The Rust handler
  // accepts 0 OR 32 bytes; anything else is a malformed call.
  if (input.contentDigest !== undefined && input.contentDigest.length !== 0 && input.contentDigest.length !== 32) {
    throw new Error('contentDigest must be 0 or 32 bytes');
  }
  if (
    input.fulfillmentDigest !== undefined &&
    input.fulfillmentDigest.length !== 0 &&
    input.fulfillmentDigest.length !== 32
  ) {
    throw new Error('fulfillmentDigest must be 0 or 32 bytes');
  }

  const spec = new pb.DlvSpecV1({
    policyDigest: input.policyDigest as any,
    contentDigest: (input.contentDigest ?? new Uint8Array()) as any,
    fulfillmentDigest: (input.fulfillmentDigest ?? new Uint8Array()) as any,
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

    // Sanity-decode the payload as a DlvInstantiateV1 proto.  Length
    // checks live here only to fail fast on obviously-malformed
    // inputs; deep validation (digest binding, signature, balance,
    // policy registration) is the Rust handler's authoritative
    // responsibility per the "all business logic stays in Rust" rule.
    const req = pb.DlvInstantiateV1.fromBinary(lockBytes);
    if (!req.spec) {
      return { success: false, error: 'DlvInstantiateV1.spec is required' };
    }
    if (!req.spec.policyDigest || req.spec.policyDigest.length !== 32) {
      return { success: false, error: 'DlvSpecV1.policy_digest must be 32 bytes' };
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
