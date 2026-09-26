// SPDX-License-Identifier: MIT OR Apache-2.0
// A `BilateralEventNotification` as Rust would post it, for tests that drive
// the event bridge. Production only decodes these (bilateralEventService), so
// the encoder lives with the tests that need it, not in the app.

import * as pb from '../../proto/dsm_app_pb';
import type { BilateralEventTypeValue } from '../../services/bilateral/bilateralEventService';

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
    eventType: input.eventType as pb.BilateralEventType,
    status: input.status || '',
    message: input.message || '',
    amount: input.amount,
    tokenId: input.tokenId,
    counterpartyDeviceId: input.counterpartyDeviceId && new Uint8Array(input.counterpartyDeviceId),
    commitmentHash: input.commitmentHash && new Uint8Array(input.commitmentHash),
    transactionHash: input.transactionHash && new Uint8Array(input.transactionHash),
    senderBleAddress: input.senderBleAddress,
  });
  return note.toBinary();
}
