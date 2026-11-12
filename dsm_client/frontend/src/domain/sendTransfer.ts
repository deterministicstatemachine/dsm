// SPDX-License-Identifier: Apache-2.0
// One send, online or offline, as both skins' send screens make it. The answer
// is what Rust answered: sent, an offline step still open on both appliances,
// or refused with Rust's reason. Nothing is decided here.

import { dsmClient } from '../services/dsmClient';
import { failureReasonMessage, type PendingBilateralPhase } from './bilateral';
import type { SendWatch } from '../dsm/transactions';
import { encodeBase32Crockford } from '../utils/textId';
import { Unanswered } from '../dsm/NativeBoundaryBridge';

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
  | { kind: 'refused'; message: string }
  /**
   * The request reached Rust and no answer came back that can be read. The send may have been
   * made: the screen says so, and never that it was not.
   */
  | { kind: 'unknown'; message: string };

/** What a send screen says of a send whose outcome is not known. */
export const UNKNOWN_OUTCOME = 'The wallet did not answer, so this may or may not have been sent. Check Activity before sending it again.';

export type { SendWatch };

/**
 * What the send screen says while an offline step is in flight, from the step's phase as Rust
 * lists it and the name of the person paid. A phase Rust has not reached yet reads as sending.
 */
export function sendingWords(phase: PendingBilateralPhase | null, name: string): string {
  switch (phase) {
    case 'pending_user_action':
      return `Waiting for ${name} to accept`;
    case 'accepted':
      return `${name} accepted — finishing`;
    case 'confirm_pending':
      return 'Finishing…';
    case 'committed':
      return 'Sent';
    case 'rejected':
      return `${name} declined`;
    case 'failed':
      return 'Not sent';
    case 'preparing':
    case 'prepared':
    case null:
      return `Sending to ${name}…`;
  }
}

export async function sendTransfer(request: SendRequest, watch: SendWatch = {}): Promise<SendOutcome> {
  try {
    return await answeredSend(request, watch);
  } catch (e) {
    if (e instanceof Unanswered) return { kind: 'unknown', message: e.message };
    throw e;
  }
}

/** The send as Rust answered it; throws `Unanswered` when Rust was asked and no answer came back. */
async function answeredSend(request: SendRequest, watch: SendWatch): Promise<SendOutcome> {
  const amount = request.amount.trim();
  const memo = request.note.length > 0 ? request.note : undefined;
  if (request.mode === 'offline') {
    const res = await dsmClient.sendOfflineTransfer({ tokenId: request.tokenId, to: request.to, amount, memo }, watch);
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
