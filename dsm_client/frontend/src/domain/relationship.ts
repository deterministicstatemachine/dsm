// SPDX-License-Identifier: Apache-2.0
// Where a relationship stands, in a few words (DSM Amendment A33). Rust
// decides the state; these lines only say it.

import type { DomainContact } from './types';

/** The line a contact's page shows for its relationship. */
export function relationshipLineFor(c: DomainContact): string {
  switch (c.relationship) {
    case 'established': return 'You can send each other money.';
    case 'opened':
    case 'proposed': return 'Waiting for them to add you. Share your code with them.';
    case 'ending': return 'You ended this relationship. Waiting for their acknowledgement.';
    case 'ended': return 'This relationship has ended.';
  }
}

/** The same in a word or two, for a list row. */
export function relationshipWordFor(c: DomainContact): string | null {
  switch (c.relationship) {
    case 'established': return null;
    case 'opened':
    case 'proposed': return 'Waiting for them';
    case 'ending': return 'Ending';
    case 'ended': return 'Ended';
  }
}

/** Whether the wallet offers to send to the contact: only on an established relationship. */
export function canSendTo(c: DomainContact): boolean {
  return c.relationship === 'established';
}

/** Whether the wallet offers to end the relationship: not once it is over. */
export function canEnd(c: DomainContact): boolean {
  return c.relationship !== 'ending' && c.relationship !== 'ended';
}
