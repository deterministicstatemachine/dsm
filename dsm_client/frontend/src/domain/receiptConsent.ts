// SPDX-License-Identifier: Apache-2.0
// What the owner agrees to when email receipts go on: exactly what the DSM
// receipt service is given for each receipt (DSM Amendment A17). Both skins'
// permission screens read it from here, so they can never say different things.

export const RECEIPT_CONSENT = {
  lead: 'When you pay someone whose email you have, DSM can email them a receipt.',
  given: 'To send it, the DSM receipt service is given, for that payment only:',
  items: [
    'their email address',
    'your name, from your contact card',
    'the amount, the currency and your note',
    "the payment's reference, and your phone's date and time",
  ],
  after: 'Nothing else is sent, and the service keeps no copy. Payments work the same with receipts off.',
} as const;
