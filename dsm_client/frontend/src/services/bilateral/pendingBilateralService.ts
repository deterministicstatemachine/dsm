/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/services/bilateral/pendingBilateralService.ts
// SPDX-License-Identifier: Apache-2.0
// Transport helpers for pending bilateral accept/reject flows.

import { decodeBase32Crockford } from '../../utils/textId';
import { acceptOfflineTransfer, rejectOfflineTransfer } from '../../dsm/index';

function decodeB32To32Bytes(value: string, label: string): Uint8Array {
  const trimmed = String(value || '').trim();
  const bytes = decodeBase32Crockford(trimmed);
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    throw new Error(`${label} must decode to 32 bytes`);
  }
  return bytes;
}

export async function acceptPendingTransfer(params: {
  commitmentHashB32: string;
  counterpartyDeviceIdB32: string;
}): Promise<{ success: boolean; error?: string }> {
  const commitmentHash = decodeB32To32Bytes(params.commitmentHashB32, 'commitmentHash');
  const counterpartyDeviceId = decodeB32To32Bytes(params.counterpartyDeviceIdB32, 'counterpartyDeviceId');
  return acceptOfflineTransfer({ commitmentHash, counterpartyDeviceId });
}

export async function rejectPendingTransfer(params: {
  commitmentHashB32: string;
  counterpartyDeviceIdB32: string;
  reason?: string;
}): Promise<{ success: boolean; error?: string }> {
  const commitmentHash = decodeB32To32Bytes(params.commitmentHashB32, 'commitmentHash');
  const counterpartyDeviceId = decodeB32To32Bytes(params.counterpartyDeviceIdB32, 'counterpartyDeviceId');
  return rejectOfflineTransfer({ commitmentHash, counterpartyDeviceId, reason: params.reason });
}
