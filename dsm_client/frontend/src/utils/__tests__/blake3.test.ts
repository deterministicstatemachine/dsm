import { domainHash, dlvContentDigest, dlvFulfillmentDigest } from '../blake3';
import { blake3 } from '@noble/hashes/blake3';

describe('domainHash', () => {
  test('matches BLAKE3(tag || \\0 || data) byte-for-byte', () => {
    const tag = 'DSM/test-domain';
    const data = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const tagBytes = new TextEncoder().encode(tag);
    const expected = blake3(
      Uint8Array.from([...tagBytes, 0, ...data]),
    );
    expect(Array.from(domainHash(tag, data))).toEqual(Array.from(expected));
  });

  test('returns a 32-byte digest', () => {
    expect(domainHash('DSM/test', new Uint8Array(0)).length).toBe(32);
    expect(domainHash('DSM/test', new Uint8Array([1, 2, 3])).length).toBe(32);
  });

  test('different domain tags yield different digests for the same data', () => {
    const data = new Uint8Array([0xaa, 0xbb]);
    const a = domainHash('DSM/domain-a', data);
    const b = domainHash('DSM/domain-b', data);
    expect(Array.from(a)).not.toEqual(Array.from(b));
  });

  test('rejects empty tag (would let domains collide)', () => {
    expect(() => domainHash('', new Uint8Array(0))).toThrow(/non-empty/);
  });

  test('handles empty data without throwing', () => {
    const out = domainHash('DSM/test', new Uint8Array(0));
    expect(out.length).toBe(32);
  });
});

describe('dlvContentDigest / dlvFulfillmentDigest', () => {
  test('content digest uses the DSM/dlv-content tag', () => {
    const content = new Uint8Array([1, 2, 3, 4]);
    expect(Array.from(dlvContentDigest(content))).toEqual(
      Array.from(domainHash('DSM/dlv-content', content)),
    );
  });

  test('fulfillment digest uses the DSM/dlv-fulfillment tag', () => {
    const fm = new Uint8Array([0x10, 0x20, 0x30]);
    expect(Array.from(dlvFulfillmentDigest(fm))).toEqual(
      Array.from(domainHash('DSM/dlv-fulfillment', fm)),
    );
  });

  test('content and fulfillment digests over the same bytes differ', () => {
    const same = new Uint8Array([0xaa, 0xbb, 0xcc]);
    expect(Array.from(dlvContentDigest(same))).not.toEqual(
      Array.from(dlvFulfillmentDigest(same)),
    );
  });
});
