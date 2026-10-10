// SPDX-License-Identifier: Apache-2.0
// The receipt after a send (DSM Amendment A17), as both skins' send screens
// ask for it: emailed only when the owner has receipts on, the person paid has
// an email, and Rust named the transfer. The send never waits on it.

import { emailReceipt } from '../dsm/receipts';
import type { Switch } from '../runtime/appRuntimeStore';
import type { DomainContact } from './types';

export type SentPayment = {
  receiptsEmail: Switch;
  contact: DomainContact;
  /** The token's symbol, as the person reads it. */
  token: string;
  amount: string;
  note: string;
  /** The transfer's hash, Base32, when Rust named one. */
  reference: string | null;
  sentAtLocal: string;
};

/** Emails the receipt when one is due: answers where it went (masked), or `null` when none is due. */
export function emailReceiptIfDue(sent: SentPayment): Promise<string> | null {
  const email = sent.contact.profile?.email;
  if (sent.receiptsEmail !== 'on' || email === undefined || email.length === 0 || sent.reference === null) return null;
  return emailReceipt({
    recipientDeviceId: sent.contact.deviceId,
    token: sent.token,
    amount: sent.amount.trim(),
    memo: sent.note,
    reference: sent.reference,
    sentAtLocal: sent.sentAtLocal,
  });
}
