// SPDX-License-Identifier: MIT OR Apache-2.0

import * as pb from '../../proto/dsm_app_pb';
import { encodeAmmConstantProductFulfillment } from '../amm';

describe('amm.ts', () => {
  const tokenA = new TextEncoder().encode('AAA');
  const tokenB = new TextEncoder().encode('BBB');

  // The predicate carries a RULE, never a balance. Reserves used to live
  // inside this message, which is what made a vault's advertised liquidity
  // a number the owner asserted about itself: nothing held it, and a settled
  // swap moved no value. They are funding legs now, debited from canonical
  // balances by `dlv.create`.

  test('carries the pair and the fee, and nothing that could state liquidity', () => {
    const bytes = encodeAmmConstantProductFulfillment({
      tokenA,
      tokenB,
      feeBps: 30,
    });
    const fm = pb.FulfillmentMechanism.fromBinary(bytes);
    expect(fm.kind.case).toBe('ammConstantProduct');
    if (fm.kind.case !== 'ammConstantProduct') return;
    const amm = fm.kind.value;
    expect(Array.from(amm.tokenA)).toEqual(Array.from(tokenA));
    expect(Array.from(amm.tokenB)).toEqual(Array.from(tokenB));
    expect(amm.feeBps).toBe(30);

    // No reserve field survives, under any spelling. A field that came back
    // would be a place for a self-declared quantity to hide.
    const asRecord = amm as unknown as Record<string, unknown>;
    for (const key of Object.keys(asRecord)) {
      expect(key.toLowerCase()).not.toContain('reserve');
    }
  });

  test('rejects non-canonical pair (tokenA >= tokenB)', () => {
    expect(() =>
      encodeAmmConstantProductFulfillment({
        tokenA: tokenB, // swapped
        tokenB: tokenA,
        feeBps: 30,
      }),
    ).toThrow(/lex-lower/);
  });

  test('rejects equal tokens', () => {
    expect(() =>
      encodeAmmConstantProductFulfillment({
        tokenA,
        tokenB: tokenA,
        feeBps: 30,
      }),
    ).toThrow(/lex-lower/);
  });

  test('rejects empty token bytes', () => {
    expect(() =>
      encodeAmmConstantProductFulfillment({
        tokenA: new Uint8Array(0),
        tokenB,
        feeBps: 30,
      }),
    ).toThrow(/tokenA is required/);
  });

  test('rejects an out-of-range fee', () => {
    for (const feeBps of [-1, 10_000, 1.5]) {
      expect(() =>
        encodeAmmConstantProductFulfillment({ tokenA, tokenB, feeBps }),
      ).toThrow(/feeBps/);
    }
  });
});
