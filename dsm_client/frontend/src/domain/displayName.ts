// SPDX-License-Identifier: Apache-2.0
// The names people choose for themselves, as this wallet shows them (audit
// 2026-10-15, item 5; 2026-10-18, SA-159). A contact card's alias is its
// owner's own words, and a card can say anything: whatever renders as nothing
// is taken out, so one name cannot render as another (a right-to-left
// override, U+202E, renders the text after it reversed; a Hangul filler,
// U+3164, draws as blank space). Two names are the same name when they read
// the same, letter shapes included: a Cyrillic a (U+0430) is read as the Latin
// a it looks like. Where money moves, a name stands beside the fingerprint of
// the device it pays, and a name two contacts share is said to be shared.

import { encodeBase32Crockford } from '../utils/textId';
import { CONFUSABLES } from './confusables';
import type { DomainContact } from './types';

/**
 * What renders as nothing: control and format characters (bidi embeddings,
 * overrides, isolates and marks, zero-width characters, the BOM); every
 * default-ignorable code point, among them the Hangul fillers U+115F, U+1160,
 * U+3164 and U+FFA0 (letters that draw as blank space), the combining grapheme
 * joiner, variation selectors and tags; and the blank symbols outside both,
 * U+2800 BRAILLE PATTERN BLANK and U+1D159 MUSICAL SYMBOL NULL NOTEHEAD.
 */
const INVISIBLE = /[\p{Cc}\p{Cf}\p{Default_Ignorable_Code_Point}\u2800\u{1D159}]/gu;

/** Each character Unicode lists as confusable (UTS #39), and the prototype it is read as. */
const PROTOTYPE: ReadonlyMap<string, string> = new Map(
  CONFUSABLES.map(([source, ...prototype]) => [String.fromCodePoint(source), String.fromCodePoint(...prototype)]),
);

/** `text` without its invisible characters, each run of whitespace one space, trimmed. */
export function visibleText(text: string): string {
  return text.replace(INVISIBLE, '').replace(/\s+/gu, ' ').trim();
}

/** The fingerprint of a device id: the first twelve characters of its Base32 Crockford, in groups of four. */
export function deviceFingerprint(deviceId: string | Uint8Array): string {
  const b32 = typeof deviceId === 'string' ? deviceId : encodeBase32Crockford(deviceId);
  if (b32.length < 12) throw new Error(`a device id of ${b32.length} Base32 characters has no fingerprint`);
  return `${b32.slice(0, 4)}-${b32.slice(4, 8)}-${b32.slice(8, 12)}`;
}

/** The UTS #39 skeleton of `text`: decomposed, each character replaced by its prototype, decomposed again. */
function skeleton(text: string): string {
  let read = '';
  for (const ch of text.normalize('NFD')) {
    const prototype = PROTOTYPE.get(ch);
    read += prototype === undefined ? ch : prototype;
  }
  return read.normalize('NFD');
}

/**
 * How a name is compared, two ways: without regard to case (folded, then read
 * by skeleton), and by shape (read by skeleton with case kept, as an upper-case
 * I reads as an l, then folded and read again). Both start from the name's
 * visible text with compatibility forms folded (NFKC).
 */
function nameKeys(name: string): { anyCase: string; shape: string } {
  const visible = visibleText(name.normalize('NFKC'));
  return {
    anyCase: skeleton(visible.toLowerCase()),
    shape: skeleton(skeleton(visible).toLowerCase()),
  };
}

/**
 * Two names are the same name when they read the same: invisible characters
 * out, compatibility forms folded, and either case folded or letter shapes
 * read alike (Unicode's confusables).
 */
export function sameName(a: string, b: string): boolean {
  const ka = nameKeys(a);
  const kb = nameKeys(b);
  return ka.anyCase.length > 0 && (ka.anyCase === kb.anyCase || ka.shape === kb.shape);
}

/**
 * The contacts, other than the device `except`, that go by `name`: by the alias
 * they were added under or by the name in their details.
 */
export function contactsNamed<C extends Pick<DomainContact, 'alias' | 'deviceId' | 'profile'>>(
  contacts: C[],
  name: string,
  except: string,
): C[] {
  return contacts.filter(
    (c) => c.deviceId !== except && (sameName(c.alias, name) || (c.profile !== undefined && sameName(c.profile.name, name))),
  );
}
