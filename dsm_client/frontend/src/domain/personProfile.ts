// SPDX-License-Identifier: Apache-2.0
// A person's details when they are added as a contact (DSM Amendment A17):
// what their contact card shared, and what a phone contact picked for them
// adds. Both skins' add-contact screens use these.

import type { ContactCard } from '../dsm/types';
import type { PersonProfile } from './types';

/** What the card itself says about its owner. */
export function profileFromCard(card: ContactCard): PersonProfile {
  return {
    name: card.preferredAlias !== undefined ? card.preferredAlias : '',
    email: card.email !== undefined ? card.email : '',
    phone: card.phone !== undefined ? card.phone : '',
    phoneLookupKey: '',
  };
}

/** The phone contact's details first; what the card shared fills what the phone lacks. */
export function withPhoneContact(current: PersonProfile, picked: PersonProfile): PersonProfile {
  return {
    name: picked.name.length > 0 ? picked.name : current.name,
    email: picked.email.length > 0 ? picked.email : current.email,
    phone: picked.phone.length > 0 ? picked.phone : current.phone,
    phoneLookupKey: picked.phoneLookupKey,
  };
}
