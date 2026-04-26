import * as pb from '../../proto/dsm_app_pb';
import { encodeAmmConstantProductFulfillment } from '../amm';

describe('amm.ts', () => {
  const tokenA = new TextEncoder().encode('AAA');
  const tokenB = new TextEncoder().encode('BBB');

  test('produces a FulfillmentMechanism that round-trips through the proto', () => {
    const bytes = encodeAmmConstantProductFulfillment({
      tokenA,
      tokenB,
      reserveA: 1_000_000n,
      reserveB: 2_000_000n,
      feeBps: 30,
    });
    const fm = pb.FulfillmentMechanism.fromBinary(bytes);
    expect(fm.kind.case).toBe('ammConstantProduct');
    if (fm.kind.case !== 'ammConstantProduct') return;
    const amm = fm.kind.value;
    expect(Array.from(amm.tokenA)).toEqual(Array.from(tokenA));
    expect(Array.from(amm.tokenB)).toEqual(Array.from(tokenB));
    expect(amm.feeBps).toBe(30);
    // Big-endian u128 round-trip on reserves.
    expect(amm.reserveAU128.length).toBe(16);
    expect(amm.reserveBU128.length).toBe(16);
    // Last 4 bytes of reserveA = 1_000_000.
    expect(amm.reserveAU128[15]).toBe(0x40);
    expect(amm.reserveAU128[14]).toBe(0x42);
    expect(amm.reserveAU128[13]).toBe(0x0F);
    expect(amm.reserveAU128[12]).toBe(0x00);
  });

  test('rejects non-canonical pair (tokenA >= tokenB)', () => {
    expect(() =>
      encodeAmmConstantProductFulfillment({
        tokenA: tokenB, // swapped
        tokenB: tokenA,
        reserveA: 1n,
        reserveB: 1n,
        feeBps: 30,
      }),
    ).toThrow(/lex-lower/);
  });

  test('rejects equal tokens', () => {
    expect(() =>
      encodeAmmConstantProductFulfillment({
        tokenA,
        tokenB: tokenA,
        reserveA: 1n,
        reserveB: 1n,
        feeBps: 30,
      }),
    ).toThrow(/lex-lower/);
  });

  test('rejects empty token bytes', () => {
    expect(() =>
      encodeAmmConstantProductFulfillment({
        tokenA: new Uint8Array(0),
        tokenB,
        reserveA: 1n,
        reserveB: 1n,
        feeBps: 30,
      }),
    ).toThrow(/tokenA is required/);
  });

  test('rejects negative reserves', () => {
    expect(() =>
      encodeAmmConstantProductFulfillment({
        tokenA,
        tokenB,
        reserveA: -1n,
        reserveB: 1n,
        feeBps: 30,
      }),
    ).toThrow(/non-negative/);
  });

  test('rejects feeBps out of basis-point range', () => {
    expect(() =>
      encodeAmmConstantProductFulfillment({
        tokenA,
        tokenB,
        reserveA: 1n,
        reserveB: 1n,
        feeBps: 10_000, // 100% — degenerate
      }),
    ).toThrow(/feeBps/);
  });

  test('rejects reserves exceeding u128', () => {
    const overflow = (1n << 128n) + 1n;
    expect(() =>
      encodeAmmConstantProductFulfillment({
        tokenA,
        tokenB,
        reserveA: overflow,
        reserveB: 1n,
        feeBps: 30,
      }),
    ).toThrow(/u128/);
  });
});
