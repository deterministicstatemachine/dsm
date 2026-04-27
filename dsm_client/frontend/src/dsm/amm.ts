/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/dsm/amm.ts
// SPDX-License-Identifier: Apache-2.0
//
// AMM (constant-product) DLV helpers.  Pure proto framing per the
// "all business logic stays in Rust" rule — no crypto, no validation
// beyond length sanity checks.  The Rust `dlv.create` handler runs
// every protocol-level check (lex-canonical pair, reserve length,
// digest verification) on receipt.

import * as pb from '../proto/dsm_app_pb';
import { routerInvokeBin } from './WebViewBridge';
import { decodeFramedEnvelopeV3 } from './decoding';
import { encodeBase32Crockford } from '../utils/textId';

/**
 * Encode an `AmmConstantProduct` fulfillment mechanism into the
 * canonical proto bytes the `dlv.create` handler expects in
 * `DlvSpecV1.fulfillment_bytes`.
 *
 * Token-pair canonicalisation (lex-lower first) is also enforced
 * here because the proto round-trip would silently swap reserves
 * if the caller passed `(B, A)` with reserves `(reserveA, reserveB)` —
 * Rust would reject the misordered ad anyway, but the frontend
 * should fail fast with a clear error.
 */
export function encodeAmmConstantProductFulfillment(input: {
  tokenA: Uint8Array;
  tokenB: Uint8Array;
  reserveA: bigint;
  reserveB: bigint;
  feeBps: number;
}): Uint8Array {
  if (!input.tokenA || input.tokenA.length === 0) {
    throw new Error('tokenA is required');
  }
  if (!input.tokenB || input.tokenB.length === 0) {
    throw new Error('tokenB is required');
  }
  if (compareBytes(input.tokenA, input.tokenB) >= 0) {
    throw new Error(
      'tokenA must be lex-lower than tokenB (canonical-pair invariant)',
    );
  }
  if (input.reserveA < 0n || input.reserveB < 0n) {
    throw new Error('reserves must be non-negative');
  }
  if (!Number.isInteger(input.feeBps) || input.feeBps < 0 || input.feeBps >= 10_000) {
    throw new Error('feeBps must be 0..9999 (basis points; 10000 = 100%)');
  }

  const amm = new pb.AmmConstantProduct({
    tokenA: input.tokenA as any,
    tokenB: input.tokenB as any,
    reserveAU128: u128BigEndian(input.reserveA) as any,
    reserveBU128: u128BigEndian(input.reserveB) as any,
    feeBps: input.feeBps,
  });
  const fm = new pb.FulfillmentMechanism({
    kind: { case: 'ammConstantProduct', value: amm },
  });
  return new Uint8Array(fm.toBinary());
}

function u128BigEndian(n: bigint): Uint8Array {
  const out = new Uint8Array(16);
  let v = n;
  for (let i = 15; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new Error('amount exceeds u128');
  return out;
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

/**
 * Create an AMM constant-product vault.  Pure proto framing — the
 * wallet's SPHINCS+ pk + signature are stamped by the Rust
 * `dlv.create` handler when the corresponding fields ride empty
 * over the wire (Track C.4 accept-or-stamp path; mirrors chunk #6's
 * `route.signRouteCommit`).
 *
 * `policyDigest` MUST be the 32-byte CPTA anchor of the token
 * governing this vault.  `content` is a small placeholder (AMM
 * vaults don't carry encrypted content the way posted-mode DLVs do).
 *
 * Returns the vault_id Base32 on success.
 */
export async function createAmmVault(input: {
  /** Lex-lower token id (must be < tokenB by byte order). */
  tokenA: Uint8Array;
  /** Lex-higher token id. */
  tokenB: Uint8Array;
  reserveA: bigint;
  reserveB: bigint;
  feeBps: number;
  /** 32-byte CPTA anchor of the policy governing this vault. */
  policyDigest: Uint8Array;
  /** Optional informational content (default = "AMM vault"). */
  content?: Uint8Array;
}): Promise<{ success: boolean; vaultIdBase32?: string; error?: string }> {
  try {
    if (!input?.policyDigest || input.policyDigest.length !== 32) {
      return { success: false, error: 'policyDigest must be 32 bytes' };
    }
    const fulfillmentBytes = encodeAmmConstantProductFulfillment({
      tokenA: input.tokenA,
      tokenB: input.tokenB,
      reserveA: input.reserveA,
      reserveB: input.reserveB,
      feeBps: input.feeBps,
    });
    const content = input.content ?? new TextEncoder().encode('AMM vault');

    const spec = new pb.DlvSpecV1({
      policyDigest: input.policyDigest as any,
      // Empty digests → Rust accept-or-compute (chunk #6).
      contentDigest: new Uint8Array() as any,
      fulfillmentDigest: new Uint8Array() as any,
      intendedRecipient: new Uint8Array() as any,
      fulfillmentBytes: fulfillmentBytes as any,
      content: content as any,
      // Tier 2 Foundation: new wallet-created vaults default to
      // REQUIRED so the anchor gate enforces vault state anchors.
      anchorEnforcement: pb.AnchorEnforcement.REQUIRED,
    });
    const req = new pb.DlvInstantiateV1({
      spec,
      // Empty pk + signature → Rust stamps wallet pk + signs (Track
      // C.4 accept-or-stamp).  No crypto in TS.
      creatorPublicKey: new Uint8Array() as any,
      tokenId: new Uint8Array() as any,
      lockedAmountU128: new Uint8Array(16) as any,
      signature: new Uint8Array() as any,
    });
    const argPack = new pb.ArgPack({
      codec: pb.Codec.PROTO as any,
      body: new Uint8Array(req.toBinary()),
    });

    const resBytes = await routerInvokeBin(
      'dlv.create',
      new Uint8Array(argPack.toBinary()),
    );
    const env = decodeFramedEnvelopeV3(resBytes);
    if (env.payload.case === 'error') {
      return { success: false, error: env.payload.value.message || 'dlv.create failed' };
    }
    if (env.payload.case === 'appStateResponse') {
      return { success: true, vaultIdBase32: env.payload.value.value ?? '' };
    }
    return {
      success: false,
      error: `Unexpected response payload: ${env.payload.case}`,
    };
  } catch (e: any) {
    return { success: false, error: e?.message || 'createAmmVault failed' };
  }
}

// Re-export for screens that prefer importing both AMM helpers from one place.
export { encodeBase32Crockford } from '../utils/textId';

import { decodeBase32Crockford, encodeBase32Crockford } from '../utils/textId';
import { decodeFramedEnvelopeV3 } from './decoding';
import { routerQueryBin } from './WebViewBridge';

/**
 * Lightweight summary returned by `listOwnedAmmVaults`.  Bigint
 * reserves keep the full u128 range without rounding.
 */
export interface AmmVaultSummary {
  vaultIdBase32: string;
  tokenA: Uint8Array;
  tokenB: Uint8Array;
  reserveA: bigint;
  reserveB: bigint;
  feeBps: number;
  advertisedStateNumber: bigint;
  routingAdvertised: boolean;
}

function decodeReserveBigInt(bytes: Uint8Array): bigint {
  let acc = 0n;
  for (const b of bytes) {
    acc = (acc << 8n) | BigInt(b);
  }
  return acc;
}

/**
 * Owner: enumerate the local DLVManager's AMM vaults (filtered to
 * those whose creator pk matches the wallet's signing pk).  Each
 * entry carries the live reserves + fee + advertised state_number
 * from storage.  Powers the `DevAmmMonitorScreen`.
 *
 * Returns a typed `AmmVaultSummary[]`.  Rust-side filtering is the
 * authority — TS just decodes the wire shape (newline-separated
 * Base32 of `AmmVaultSummaryV1` protos).
 */
export async function listOwnedAmmVaults(): Promise<{
  success: boolean;
  vaults?: AmmVaultSummary[];
  error?: string;
}> {
  try {
    const argPack = new pb.ArgPack({
      codec: pb.Codec.PROTO as any,
      body: new Uint8Array(),
    });
    const resBytes = await routerQueryBin(
      'dlv.listOwnedAmmVaults',
      new Uint8Array(argPack.toBinary()),
    );
    const env = decodeFramedEnvelopeV3(resBytes);
    if (env.payload.case === 'error') {
      return {
        success: false,
        error: env.payload.value.message || 'dlv.listOwnedAmmVaults failed',
      };
    }
    if (env.payload.case !== 'appStateResponse') {
      return {
        success: false,
        error: `Unexpected response payload: ${String(env.payload.case)}`,
      };
    }
    const value = env.payload.value.value ?? '';
    const lines = value ? value.split('\n').filter((l) => l.length > 0) : [];
    const vaults: AmmVaultSummary[] = lines.map((line) => {
      const summaryBytes = decodeBase32Crockford(line);
      const summary = pb.AmmVaultSummaryV1.fromBinary(new Uint8Array(summaryBytes));
      return {
        vaultIdBase32: encodeBase32Crockford(summary.vaultId),
        tokenA: summary.tokenA,
        tokenB: summary.tokenB,
        reserveA: decodeReserveBigInt(summary.reserveAU128),
        reserveB: decodeReserveBigInt(summary.reserveBU128),
        feeBps: summary.feeBps,
        advertisedStateNumber: summary.advertisedStateNumber,
        routingAdvertised: summary.routingAdvertised,
      };
    });
    return { success: true, vaults };
  } catch (e: any) {
    return { success: false, error: e?.message || 'listOwnedAmmVaults failed' };
  }
}
