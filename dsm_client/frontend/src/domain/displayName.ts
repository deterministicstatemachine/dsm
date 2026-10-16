// SPDX-License-Identifier: Apache-2.0
// The names people choose for themselves, as this wallet shows them (audit
// 2026-10-15, item 5). A contact card's alias is its owner's own words, and a
// card can say anything: bidirectional controls, zero-width and other
// invisible characters are taken out, so one name cannot render as another
// (a right-to-left override, U+202E, renders the text after it reversed). Where
// money moves, a name stands beside the fingerprint of the device it pays, and
// a name two contacts share is said to be shared.

import { encodeBase32Crockford } from '../utils/textId';
import type { DomainContact } from './types';

/** Control and format characters: bidi embeddings, overrides, isolates and marks, zero-width characters, the BOM. */
const INVISIBLE = /[\p{Cc}\p{Cf}]/gu;

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

function nameKey(name: string): string {
  return visibleText(name).normalize('NFKC').toLocaleLowerCase();
}

/** Two names are the same name when they read the same: invisible characters out, compatibility forms folded, case folded. */
export function sameName(a: string, b: string): boolean {
  const key = nameKey(a);
  return key.length > 0 && key === nameKey(b);
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
