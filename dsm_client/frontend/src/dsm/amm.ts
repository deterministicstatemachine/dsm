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
