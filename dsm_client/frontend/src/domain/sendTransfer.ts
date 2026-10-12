// SPDX-License-Identifier: Apache-2.0
// One send, online or offline, as both skins' send screens make it. The answer
// is what Rust answered: sent, an offline step still open on both appliances,
// or refused with Rust's reason. Nothing is decided here.

import { dsmClient } from '../services/dsmClient';
import { failureReasonMessage } from './bilateral';
import { encodeBase32Crockford } from '../utils/textId';

export type SendMode = 'online' | 'offline';

export type SendRequest = {
  mode: SendMode;
  /** The recipient contact's device id, Base32: never an alias. */
  to: string;
  tokenId: string;
  amount: string;
  note: string;
};

export type SendOutcome =
  /** Rust accepted it. `reference` is the transfer's hash, Base32, when Rust named one. */
  | { kind: 'sent'; reference: string | null }
  /** Offline only: not finished and not failed; it completes when the appliances meet again. */
  | { kind: 'open'; message: string }
  | { kind: 'refused'; message: string };

export async function sendTransfer(request: SendRequest): Promise<SendOutcome> {
  const amount = request.amount.trim();
  const memo = request.note.length > 0 ? request.note : undefined;
  if (request.mode === 'offline') {
    const res = await dsmClient.sendOfflineTransfer({ tokenId: request.tokenId, to: request.to, amount, memo });
    if (res.open) return { kind: 'open', message: res.result ?? 'It completes when the two appliances are together again.' };
    if (!res.accepted) {
      return { kind: 'refused', message: failureReasonMessage(res.failureReason) ?? res.result ?? 'Offline transfer failed' };
    }
    return { kind: 'sent', reference: null };
  }
  const res = await dsmClient.sendOnlineTransferSmart(request.to, amount, memo, request.tokenId);
  if (!res.success) return { kind: 'refused', message: res.message ?? 'Online transfer failed' };
  const hash = res.transactionHash;
  return { kind: 'sent', reference: hash !== undefined && hash.length > 0 ? encodeBase32Crockford(hash) : null };
}
