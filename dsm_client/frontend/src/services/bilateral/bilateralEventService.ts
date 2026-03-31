/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/services/bilateral/bilateralEventService.ts
// SPDX-License-Identifier: Apache-2.0
// Transport-layer bilateral event decoding and actions.

import * as pb from '../../proto/dsm_app_pb';
import { encodeBase32Crockford, decodeBase32Crockford } from '../../utils/textId';
import { acceptOfflineTransfer, rejectOfflineTransfer } from '../../dsm/index';

export const BilateralEventType = {
  PREPARE_RECEIVED: pb.BilateralEventType.BILATERAL_EVENT_PREPARE_RECEIVED,
  ACCEPT_SENT: pb.BilateralEventType.BILATERAL_EVENT_ACCEPT_SENT,
  COMMIT_RECEIVED: pb.BilateralEventType.BILATERAL_EVENT_COMMIT_RECEIVED,
  TRANSFER_COMPLETE: pb.BilateralEventType.BILATERAL_EVENT_TRANSFER_COMPLETE,
  REJECTED: pb.BilateralEventType.BILATERAL_EVENT_REJECTED,
  FAILED: pb.BilateralEventType.BILATERAL_EVENT_FAILED,
} as const;

export type BilateralEventTypeValue = typeof BilateralEventType[keyof typeof BilateralEventType];

export interface BilateralTransferEvent {
  eventType: BilateralEventTypeValue;
  counterpartyDeviceId: string; // base32
  commitmentHash: string; // base32
  transactionHash?: string; // base32
  amount?: bigint;
  tokenId?: string;
  status: string;
  message: string;
  senderBleAddress?: string;
}

function toB32(bytes?: Uint8Array | null): string {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return '';
  return encodeBase32Crockford(bytes);
}

export function decodeBilateralEvent(payload: Uint8Array): BilateralTransferEvent | null {
  try {
    const notification = pb.BilateralEventNotification.fromBinary(payload);
    return {
      eventType: notification.eventType as BilateralEventTypeValue,
      counterpartyDeviceId: toB32(notification.counterpartyDeviceId),
      commitmentHash: toB32(notification.commitmentHash),
      transactionHash: toB32(notification.transactionHash),
      amount: notification.amount,
      tokenId: notification.tokenId,
      status: notification.status,
      message: notification.message,
      senderBleAddress: notification.senderBleAddress,
    };
  } catch {
    return null;
  }
}

export function encodeBilateralEventNotification(input: {
  eventType: BilateralEventTypeValue;
  status?: string;
  message?: string;
  amount?: bigint;
  tokenId?: string;
  counterpartyDeviceId?: Uint8Array;
  commitmentHash?: Uint8Array;
  transactionHash?: Uint8Array;
  senderBleAddress?: string;
}): Uint8Array {
  const note = new pb.BilateralEventNotification({
    eventType: input.eventType as any,
    status: input.status || '',
    message: input.message || '',
    amount: input.amount,
    tokenId: input.tokenId,
    counterpartyDeviceId: input.counterpartyDeviceId as any,
    commitmentHash: input.commitmentHash as any,
    transactionHash: input.transactionHash as any,
    senderBleAddress: input.senderBleAddress,
  } as any);
  return note.toBinary();
}

function decodeB32To32Bytes(value: string, label: string): Uint8Array {
  const bytes = decodeBase32Crockford(value);
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    throw new Error(`${label} must decode to 32 bytes`);
  }
  return bytes;
}

export async function acceptIncomingTransfer(event: BilateralTransferEvent): Promise<{ success: boolean }> {
  const commitmentHash = decodeB32To32Bytes(event.commitmentHash, 'commitmentHash');
  const counterpartyDeviceId = decodeB32To32Bytes(event.counterpartyDeviceId, 'counterpartyDeviceId');
  return acceptOfflineTransfer({ commitmentHash, counterpartyDeviceId });
}

export async function rejectIncomingTransfer(event: BilateralTransferEvent, reason?: string): Promise<{ success: boolean }> {
  const commitmentHash = decodeB32To32Bytes(event.commitmentHash, 'commitmentHash');
  const counterpartyDeviceId = decodeB32To32Bytes(event.counterpartyDeviceId, 'counterpartyDeviceId');
  return rejectOfflineTransfer({ commitmentHash, counterpartyDeviceId, reason });
}
