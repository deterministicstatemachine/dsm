// SPDX-License-Identifier: MIT OR Apache-2.0

// Base32 Crockford, as DSM writes every identifier for people to read
// (`dsm::utils::text_id`): 0-9 and A-Z without I, L, O and U, no padding.

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export function encodeB32(bytes: Uint8Array): string {
  let out = "";
  let buffer = 0;
  let bits = 0;
  for (const b of bytes) {
    buffer = ((buffer << 8) | b) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(buffer >> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += ALPHABET[(buffer << (5 - bits)) & 31];
  }
  return out;
}

function valueOf(ch: string): number {
  const c = ch.toUpperCase();
  if (c === "O") return 0;
  if (c === "I" || c === "L") return 1;
  const v = ALPHABET.indexOf(c);
  if (v < 0) {
    throw new Error(`"${ch}" is not a Base32 Crockford character`);
  }
  return v;
}

export function decodeB32(text: string): Uint8Array {
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of text) {
    if (ch === "-" || ch === " ") continue;
    buffer = ((buffer << 5) | valueOf(ch)) & 0xffff;
    bits += 5;
    while (bits >= 8) {
      out.push((buffer >> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}

/** A 32-byte identifier from its Base32 Crockford text; refuses any other length. */
export function decodeId(text: string, what: string): Uint8Array {
  const bytes = decodeB32(text);
  if (bytes.length !== 32) {
    throw new Error(`${what} is ${bytes.length} bytes, not 32: ${text}`);
  }
  return bytes;
}
