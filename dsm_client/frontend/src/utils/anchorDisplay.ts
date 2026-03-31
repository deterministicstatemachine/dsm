/* eslint-disable security/detect-object-injection */
// Internal anchor display helpers for debugging policy/token anchors
// STRICT: These functions are for DISPLAY ONLY of internal cryptographic anchors.
// DO NOT use for user identity (genesis_hash, device_id) or user input parsing.
// User-facing identities must be shown via ALIAS ONLY.

const CROCKFORD_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const _CHAR_TO_VAL: Record<string, number> = (() => {
  const m: Record<string, number> = {};
  for (let i = 0; i < CROCKFORD_ALPHABET.length; i++) {
    m[CROCKFORD_ALPHABET[i]] = i;
  }
  // Tolerant mappings: i,l -> 1 ; o -> 0 ; u -> v (per common Crockford practice)
  m['I'] = m['1'] = 1;
  m['L'] = 1;
  m['O'] = m['0'] = 0;
  // Treat U as V for legibility; not normative, UI-only.
  m['U'] = m['V'];
  return m;
})();

// --- INTERNAL HELPERS (not exported for user input) ---

function toBase32Crockford(bytes: Uint8Array): string {
  if (!bytes || bytes.length === 0) return '';
  let bits = 0;
  let value = 0;
  let output = '';
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      const idx = (value >>> (bits - 5)) & 0x1f;
      output += CROCKFORD_ALPHABET[idx];
      bits -= 5;
    }
  }
  if (bits > 0) {
    const idx = (value << (5 - bits)) & 0x1f;
    output += CROCKFORD_ALPHABET[idx];
  }
  return output;
}

function groupBlocks(s: string, n = 8): string {
  const parts: string[] = [];
  for (let i = 0; i < s.length; i += n) parts.push(s.slice(i, i + n));
  return parts.join(' ');
}

function fnv1a32(data: Uint8Array): number {
  let hash = 0x811c9dc5;
  for (let i = 0; i < data.length; i++) {
    hash ^= data[i];
    // 32-bit FNV prime
    hash = (hash + ((hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24))) >>> 0;
  }
  return hash >>> 0;
}

function uiChecksum2(bytes: Uint8Array): string {
  const tag = new TextEncoder().encode('DSM/anchor-check\0');
  const merged = new Uint8Array(tag.length + bytes.length);
  merged.set(tag, 0);
  merged.set(bytes, tag.length);
  const h = fnv1a32(merged);
  // Map top 10 bits → 2 Crockford chars (5 bits each)
  const a = (h >>> 27) & 0x1f;
  const b = (h >>> 22) & 0x1f;
  return CROCKFORD_ALPHABET[a] + CROCKFORD_ALPHABET[b];
}

// --- PUBLIC EXPORTS (for internal anchor display only, NOT user identity) ---

/**
 * Render a short, human-friendly ID for internal anchors (policies, tokens).
 * STRICT: DO NOT use for user identity (genesis_hash, device_id). Use aliases only.
 */
export function shortId(bytes: Uint8Array, bodyLen = 10): string {
  const b32 = toBase32Crockford(bytes);
  const body = b32.slice(0, bodyLen);
  const sum = uiChecksum2(bytes);
  return `${body}-${sum}`;
}

/**
 * Pretty-print an internal anchor (bytes) for debugging.
 * STRICT: DO NOT use for user identity. Use aliases only.
 */
export function prettyAnchor(bytes: Uint8Array): string {
  return groupBlocks(toBase32Crockford(bytes), 8);
}


// UI-only clipboard copy helper (best-effort)
export async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator?.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {}
  try {
    const el = document.createElement('textarea');
    el.value = text;
    el.style.position = 'fixed';
    el.style.opacity = '0';
    document.body.appendChild(el);
    el.focus();
    el.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(el);
    return ok;
  } catch {
    return false;
  }
}

