/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

// Domain-only helpers for bilateral flows. UI must not import protobuf types.

// Map numeric failure codes (from protobuf enum) to user-friendly messages.
export function failureReasonMessage(code: number | undefined | null): string | undefined {
  switch (code) {
    case 4: // FAILURE_REASON_REJECTED_BY_PEER
      return 'Transfer was rejected by the recipient.';
    case 2: // FAILURE_REASON_CRYPTO_INVALID
      return 'Security verification failed. Please re-pair devices.';
    case 1: // FAILURE_REASON_BLE_GATT_ERROR
      return 'Bluetooth connection unstable. Move closer and try again.';
    case 3: // FAILURE_REASON_SECURITY_LOCKOUT
      return 'Hardware security lockout. Restart the app.';
    case 6: // FAILURE_REASON_TIMEOUT
      return 'Transaction timed out.';
    case 5: // FAILURE_REASON_PROTOCOL_VIOLATION / VERSION MISMATCH
      return 'Incompatible or invalid protocol version. Please update.';
    case 0: // unspecified
    default:
      return undefined;
  }
}

// DTO for pending bilateral transactions (UI-safe)
export interface PendingBilateralDto {
  id: string;
  type: 'incoming' | 'outgoing';
  counterpartyAlias: string;
  counterpartyDeviceId: string;
  amount: string;
  tokenId: string;
  commitmentHash: string;
  status: 'pending' | 'verified' | 'hash_mismatch' | 'accepted' | 'committed' | 'failed' | 'rejected';
  tick: number;
  bleAddress?: string;
  verificationStatus?: 'verified' | 'failed' | 'pending';
}

// Decode protobuf OfflineBilateralPendingListResponse bytes into DTOs.
// This keeps protobuf parsing out of React components.
export async function decodeOfflinePendingList(bytes: Uint8Array): Promise<PendingBilateralDto[]> {
  const pb = await import('../proto/dsm_app_pb');
  const { encodeBase32Crockford } = await import('../utils/textId');
  const { decodeFramedEnvelopeV3 } = await import('../dsm/decoding');

  let items: Array<InstanceType<typeof pb.OfflineBilateralTransaction>> = [] as any;
  try {
    const env = decodeFramedEnvelopeV3(bytes);
    if (env.payload.case === 'offlineBilateralPendingListResponse') {
      const resp = env.payload.value;
      items = resp.transactions;
    }
  } catch {
    items = [] as any;
  }

  return items.map((it: any, idx: number) => {
    let statusStr: PendingBilateralDto['status'] = 'pending';
    switch (it.status) {
      case pb.OfflineBilateralTransactionStatus.OFFLINE_TX_CONFIRMED:
        statusStr = 'verified';
        break;
      case pb.OfflineBilateralTransactionStatus.OFFLINE_TX_FAILED:
        statusStr = 'failed';
        break;
      case pb.OfflineBilateralTransactionStatus.OFFLINE_TX_REJECTED:
        statusStr = 'rejected';
        break;
      case pb.OfflineBilateralTransactionStatus.OFFLINE_TX_IN_PROGRESS:
        statusStr = 'committed';
        break;
      case pb.OfflineBilateralTransactionStatus.OFFLINE_TX_PENDING:
      default:
        statusStr = 'pending';
        break;
    }

    const dir = it.metadata?.['direction'] || 'incoming';
    const amount = it.metadata?.['amount'] || '0';
    const tokenId = it.metadata?.['token_id'] || 'ERA';
    const alias = it.metadata?.['counterparty_alias'] || 'peer';
    const bleAddr = it.metadata?.['ble_address'];

    return {
      id: encodeBase32Crockford(it.commitmentHash),
      type: dir === 'outgoing' ? 'outgoing' : 'incoming',
      counterpartyAlias: alias,
      counterpartyDeviceId: encodeBase32Crockford(it.senderId),
      amount,
      tokenId,
      commitmentHash: encodeBase32Crockford(it.commitmentHash),
      status: statusStr,
      tick: idx + 1,
      bleAddress: bleAddr,
      verificationStatus: 'pending',
    };
  });
}
