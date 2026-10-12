// SPDX-License-Identifier: Apache-2.0
// Where Bluetooth pairing with contacts stands, as Rust states it on each
// contact. When pairing runs is Rust's (the app in the foreground with
// Bluetooth on and permitted, until no contact is left unpaired); these only
// name where it has got, for both skins' contact lists.

import type { DomainContact } from './types';

/** One contact's pairing, in a few words; `null` while it has not started. */
export function pairingLineFor(c: DomainContact): string | null {
  switch (c.pairing) {
    case 'paired': return 'Paired over Bluetooth';
    case 'connected': return 'Connecting…';
    case 'searching':
    case 'retrying': return 'Pairing…';
    default: return null;
  }
}

/** The same in a word, for a row with little room beside a button. */
export function pairingWordFor(c: DomainContact): string | null {
  switch (c.pairing) {
    case 'paired': return 'Paired';
    case 'connected': return 'Connecting…';
    case 'searching':
    case 'retrying': return 'Pairing…';
    default: return null;
  }
}

/** The furthest any pairing has got across the list; `null` when none is under way. */
export function pairingStage(contacts: DomainContact[]): 'connected' | 'searching' | null {
  if (contacts.some((c) => c.pairing === 'connected')) return 'connected';
  if (contacts.some((c) => c.pairing === 'searching' || c.pairing === 'retrying')) return 'searching';
  return null;
}
