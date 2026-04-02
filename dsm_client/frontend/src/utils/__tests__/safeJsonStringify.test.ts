// SPDX-License-Identifier: Apache-2.0
import { safeJsonStringify } from '../safeJsonStringify';

describe('safeJsonStringify', () => {
  it('matches JSON.stringify for plain objects', () => {
    expect(safeJsonStringify({ a: 1, b: 'x' })).toBe(JSON.stringify({ a: 1, b: 'x' }));
  });

  it('serializes bigint as decimal string', () => {
    expect(safeJsonStringify({ n: 42n })).toBe('{"n":"42"}');
  });

  it('handles nested bigint', () => {
    expect(safeJsonStringify({ inner: { v: 9007199254740993n } })).toBe(
      '{"inner":{"v":"9007199254740993"}}',
    );
  });

  it('handles bigint in arrays', () => {
    expect(safeJsonStringify([1n, 2n])).toBe('["1","2"]');
  });

  it('preserves null and undefined omission behavior of JSON.stringify', () => {
    expect(safeJsonStringify({ x: null })).toBe('{"x":null}');
  });
});
