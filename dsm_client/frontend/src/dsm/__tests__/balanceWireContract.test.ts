// SPDX-License-Identifier: Apache-2.0
//! The bytes Rust actually sends must decode, in TypeScript, with every field.
//!
//! The bridge narrowed BalanceGetResponse into a two-field surrogate and the
//! JNI layer re-inflated it with defaults, so `symbol`, `decimals`, `locked`
//! and `token_name` arrived blank. token_id and available survived — the two
//! fields the surrogate carried — which made it look convincingly like proto
//! field-number skew. It was not: both sides declare tags 1-6 identically.
//!
//! A hand-written object could never have caught that, because the loss
//! happened in transport, not in either schema. So this decodes REAL bytes
//! produced by the Rust encoder (dsm_sdk/tests/balance_wire_fixture.rs) using
//! the REAL generated decoder.

import { readFileSync } from 'fs';
import { join } from 'path';
import { decodeFramedEnvelopeV3 } from '../decoding';

describe('balance wire contract (Rust -> TypeScript)', () => {
  it('decodes every field the Rust encoder wrote', () => {
    const bytes = new Uint8Array(
      readFileSync(join(__dirname, 'fixtures/balances_list_rigb.bin')),
    );

    const env = decodeFramedEnvelopeV3(bytes);
    expect(env.payload.case).toBe('balancesListResponse');

    const row: any = (env.payload.value as any).balances[0];

    expect(row.tokenId).toBe('RIGB');
    expect(row.available).toBe(100000n);
    expect(row.locked).toBe(0n);
    // The four that were silently dropped in transport:
    expect(row.symbol).toBe('RIGB');
    expect(row.decimals).toBe(2);
    expect(row.tokenName).toBe('RigBravo');
    // The rendered amount, produced by Rust from the SAME base units in the
    // same message. This is what the wallet prints; nothing downstream
    // recomputes it, so if these two ever disagree it is one bug in one place.
    expect(row.displayAmount).toBe('1000.00');
  });

  /// decimals must arrive as a real number, since the mapper's guard is
  /// `typeof b.decimals === 'number'` — a string or bigint would silently
  /// become 0 and reproduce the display bug by another route.
  it('delivers decimals as a JavaScript number', () => {
    const bytes = new Uint8Array(
      readFileSync(join(__dirname, 'fixtures/balances_list_rigb.bin')),
    );
    const env = decodeFramedEnvelopeV3(bytes);
    const row: any = (env.payload.value as any).balances[0];
    expect(typeof row.decimals).toBe('number');
  });
});
