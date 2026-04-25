// path: src/utils/blake3.ts
// SPDX-License-Identifier: Apache-2.0
//
// Domain-separated BLAKE3 helpers for the frontend.
//
// The Rust core uses `dsm::crypto::blake3::domain_hash(tag, data) =
// blake3(tag || \0 || data)`.  Every TypeScript caller that needs to
// produce a digest the Rust handler can verify MUST go through
// `domainHash` here — concatenating the tag in any other order, or
// using a different separator, breaks the cross-layer contract.
//
// We intentionally hide the raw `blake3` import behind a single
// `domainHash` entry point so a future audit can grep for every
// frontend BLAKE3 user from one place.

import { blake3 } from '@noble/hashes/blake3';

/**
 * Compute BLAKE3(`tag` || `\0` || `data`) and return the 32-byte digest.
 *
 * Mirrors `dsm::crypto::blake3::domain_hash_bytes` byte-for-byte.  The
 * null separator is REQUIRED — the Rust verifier will reject any digest
 * computed without it.
 *
 * @param tag  Domain tag string (e.g. "DSM/dlv-content"). MUST NOT be
 *             empty; an empty tag would let two different domains
 *             collide on the same data.
 * @param data Arbitrary input bytes to hash inside the domain.
 */
export function domainHash(tag: string, data: Uint8Array): Uint8Array {
  if (typeof tag !== 'string' || tag.length === 0) {
    throw new Error('domainHash: tag must be a non-empty string');
  }
  const tagBytes = new TextEncoder().encode(tag);
  const buf = new Uint8Array(tagBytes.length + 1 + data.length);
  buf.set(tagBytes, 0);
  buf[tagBytes.length] = 0; // null separator
  buf.set(data, tagBytes.length + 1);
  // @noble/hashes always returns Uint8Array(32) for blake3 with no
  // explicit output length — exactly what the Rust core expects.
  return blake3(buf);
}

/**
 * Convenience: compute the DLV content digest used by `dlv.create`.
 * The Rust handler strict-verifies this against
 * `BLAKE3("DSM/dlv-content\0" || content)`.
 */
export function dlvContentDigest(content: Uint8Array): Uint8Array {
  return domainHash('DSM/dlv-content', content);
}

/**
 * Convenience: compute the DLV fulfillment digest used by `dlv.create`.
 * The Rust handler strict-verifies this against
 * `BLAKE3("DSM/dlv-fulfillment\0" || fulfillmentBytes)`.
 */
export function dlvFulfillmentDigest(fulfillmentBytes: Uint8Array): Uint8Array {
  return domainHash('DSM/dlv-fulfillment', fulfillmentBytes);
}
