/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// eslint-env jest
declare const describe: any;
declare const test: any;
declare const expect: any;
declare const it: any;

import { getTokenDecimals, formatTokenAmount, formatSignedTokenAmount } from '../tokenMeta';

describe('getTokenDecimals', () => {
  test('returns 8 for dBTC (case-insensitive)', () => {
    expect(getTokenDecimals('DBTC')).toBe(8);
    expect(getTokenDecimals('dbtc')).toBe(8);
    expect(getTokenDecimals('Dbtc')).toBe(8);
  });

  test('returns 8 for BTC', () => {
    expect(getTokenDecimals('BTC')).toBe(8);
    expect(getTokenDecimals('btc')).toBe(8);
  });

  test('returns 0 for unknown tokens', () => {
    expect(getTokenDecimals('ERA')).toBe(0);
    expect(getTokenDecimals('UNKNOWN')).toBe(0);
    expect(getTokenDecimals('foo')).toBe(0);
  });

  test('returns 0 for undefined/empty input', () => {
    expect(getTokenDecimals(undefined)).toBe(0);
    expect(getTokenDecimals('')).toBe(0);
  });

  test('trims whitespace from token id', () => {
    expect(getTokenDecimals('  DBTC  ')).toBe(8);
    expect(getTokenDecimals(' btc ')).toBe(8);
  });
});

describe('formatTokenAmount', () => {
  test('formats whole-unit tokens (0 decimals)', () => {
    expect(formatTokenAmount(0n, 'ERA')).toBe('0');
    expect(formatTokenAmount(1n, 'ERA')).toBe('1');
    expect(formatTokenAmount(123456n, 'ERA')).toBe('123456');
  });

  test('formats dBTC with 8 decimals', () => {
    expect(formatTokenAmount(100000000n, 'DBTC')).toBe('1.0');
    expect(formatTokenAmount(0n, 'DBTC')).toBe('0.0');
    expect(formatTokenAmount(1n, 'DBTC')).toBe('0.00000001');
    expect(formatTokenAmount(50000000n, 'DBTC')).toBe('0.5');
    expect(formatTokenAmount(123456789n, 'DBTC')).toBe('1.23456789');
  });

  test('strips trailing zeros but keeps at least one decimal digit', () => {
    expect(formatTokenAmount(100000000n, 'BTC')).toBe('1.0');
    expect(formatTokenAmount(110000000n, 'BTC')).toBe('1.1');
    expect(formatTokenAmount(100100000n, 'BTC')).toBe('1.001');
  });

  test('handles large values without precision loss', () => {
    const tenBtc = 1000000000n;
    expect(formatTokenAmount(tenBtc, 'BTC')).toBe('10.0');

    const huge = 2100000000000000n;
    expect(formatTokenAmount(huge, 'BTC')).toBe('21000000.0');
  });
});

describe('formatSignedTokenAmount', () => {
  test('positive amounts have no prefix', () => {
    expect(formatSignedTokenAmount(100000000n, 'DBTC')).toBe('1.0');
    expect(formatSignedTokenAmount(1n, 'ERA')).toBe('1');
  });

  test('negative amounts have minus prefix', () => {
    expect(formatSignedTokenAmount(-100000000n, 'DBTC')).toBe('-1.0');
    expect(formatSignedTokenAmount(-1n, 'ERA')).toBe('-1');
    expect(formatSignedTokenAmount(-50000000n, 'BTC')).toBe('-0.5');
  });

  test('zero has no prefix', () => {
    expect(formatSignedTokenAmount(0n, 'DBTC')).toBe('0.0');
    expect(formatSignedTokenAmount(0n, 'ERA')).toBe('0');
  });
});
