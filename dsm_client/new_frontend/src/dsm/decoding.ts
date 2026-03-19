import * as pb from '../proto/dsm_app_pb';
import { bytesToBase32CrockfordPrefix, encodeBase32Crockford, decodeBase32Crockford } from '../utils/textId';


/**
 * CANONICAL DECODER: All transport ingress/egress paths MUST use this.
 * 
 * FramedEnvelopeV3 = [1 byte framing] || Envelope(version=3, ...)
 * 
 * This is the single gate into DSM protocol layer:
 * - QR scanner: scan text → base32 decode → decodeFramedEnvelopeV3 → route
 * - BLE: reassemble chunks → decodeFramedEnvelopeV3 → route
 * - WebView bridge: bytes → decodeFramedEnvelopeV3 → route
 * - Storage sync: bytes → decodeFramedEnvelopeV3 → route
 * - Faucet: bytes → decodeFramedEnvelopeV3 → route
 * 
 * NO exceptions. NO direct protobuf decoding. NO ad-hoc parsers.
 * One door into the castle.
 */
export function decodeFramedEnvelopeV3(bytes: Uint8Array): pb.Envelope {
  if (!bytes || bytes.length < 2) {
    throw new Error(`FramedEnvelopeV3 requires at least 2 bytes, got ${bytes?.length ?? 0}`);
  }

  const framingByte = bytes[0];

  // Standard framed format: 0x03 framing byte followed by raw Envelope protobuf.
  // This is the canonical path — all well-formed native responses use this.
  if (framingByte === 0x03) {
    const envBytes = bytes.slice(1);

    let env: pb.Envelope;
    try {
      env = pb.Envelope.fromBinary(envBytes);
    } catch (e) {
      throw new Error(`Failed to decode Envelope from framed bytes: ${e instanceof Error ? e.message : String(e)}`);
    }

    if (env.version !== 3) {
      throw new Error(`Expected Envelope v3, got v${env.version}`);
    }

    return env;
  }

  // Hard invariant: all transport envelopes MUST have 0x03 framing byte.
  // No fallback, no dual-format acceptance.
  throw new Error(
    `FramedEnvelopeV3: invalid framing byte 0x${framingByte.toString(16).padStart(2, '0')} (expected 0x03). First 4 bytes: ${Array.from(bytes.slice(0, Math.min(4, bytes.length))).map((b) => `0x${b.toString(16).padStart(2, '0')}`).join(' ')}`
  );


}

// Strict decode only: decodeFramedEnvelopeV3 is the canonical transport entrypoint.

/** Canonical base32 Crockford encoding for 32-byte identifiers. */
export function toBase32Crockford(bytes: Uint8Array): string {
  return encodeBase32Crockford(bytes);
}

/** Canonical base32 Crockford decoder. */
export function fromBase32Crockford(value: string): Uint8Array {
  return decodeBase32Crockford(value);
}

/** Encode a canonical Envelope into deterministic bytes. */
export function encodeEnvelope(env: pb.Envelope): Uint8Array {
  return env.toBinary();
}

// decodeEnvelope deleted: all transport ingress MUST go through decodeFramedEnvelopeV3.
// Direct pb.Envelope.fromBinary is not allowed outside the canonical decoder.

// ---------------- Balances decoding (consolidated) ----------------

export type DecodeBalancesOpts = {
  /** Label used in error messages/logs for easier tracing. */
  label?: string;
};

export type DecodeBalancesResult = {
  response: pb.BalancesListResponse;
  headB32: string;
  /** Where we found the response bytes. Useful for debugging bridge mismatches. */
  decodedVia: 'direct' | 'result-pack' | 'arg-pack' | 'arg-pack-result-pack' | 'envelope' | 'unwrapped';
};



/**
 * Strictly decode a BalancesListResponse from arbitrary bridge bytes.
 *
 * Rules:
 * - Skip 1-byte framing prefix (0x03 transport marker)
 * - Decode as Envelope
 * - If error payload, throw
 * - Extract balancesListResponse from envelope payload
 */
export function decodeBalancesListResponseStrict(bytes: Uint8Array, opts?: DecodeBalancesOpts): DecodeBalancesResult {
  const label = opts?.label ?? 'balances';
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
    throw new Error(`DSM:${label}: empty response bytes`);
  }

  const headB32 = bytesToBase32CrockfordPrefix(bytes, 24);
  // ALL bridge responses go through the single canonical decoder — no manual byte slicing.
  const env = decodeFramedEnvelopeV3(bytes);

  // Check for error response first
  if (env.payload.case === 'error') {
    const err = env.payload.value;
    throw new Error(`Native error: ${err.message || 'Unknown error'} (code ${err.code || 0})`);
  }

  // Extract balances from envelope
  if (env.payload.case !== 'balancesListResponse') {
    throw new Error(`Unexpected payload case for balances: ${env.payload.case}`);
  }

  const balancesResponse = env.payload.value;
  if (!balancesResponse) {
    throw new Error('balancesListResponse payload is null');
  }

  return { response: balancesResponse, headB32, decodedVia: 'envelope' };
}

// Helper removed: bytesEqual was unused
