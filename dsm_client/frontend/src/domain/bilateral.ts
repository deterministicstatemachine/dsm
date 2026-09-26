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

/** A bilateral step's phase, as this device's session store holds it. */
export type PendingBilateralPhase =
  | 'preparing'
  | 'prepared'
  | 'pending_user_action'
  | 'accepted'
  | 'rejected'
  | 'confirm_pending'
  | 'committed'
  | 'failed';

/** A bilateral step this device holds a session for, each field as the SDK stated it. */
export interface PendingBilateralDto {
  id: string;
  direction: 'incoming' | 'outgoing';
  phase: PendingBilateralPhase;
  /** The counterparty's contact alias, when the contact has one. */
  counterpartyAlias?: string;
  counterpartyDeviceId: string;
  /** Base units, as the transfer's operation states them. */
  amount: bigint;
  /** Rendered by the SDK; absent when this device does not know the token's decimals. */
  displayAmount?: string;
  tokenId: string;
  commitmentHash: string;
  bleAddress?: string;
  /** Whether this device may cancel the step now, as the SDK decides it. */
  cancellable: boolean;
}

// Decode the SDK's framed answer to `bilateral.pending_list` into DTOs.
// This keeps protobuf parsing out of React components. Any other answer is an
// error for the caller to show, and a row the SDK did not fully state is refused.
export async function decodeOfflinePendingList(bytes: Uint8Array): Promise<PendingBilateralDto[]> {
  const pb = await import('../proto/dsm_app_pb');
  const { encodeBase32Crockford } = await import('../utils/textId');
  const { decodeFramedEnvelopeV3 } = await import('../dsm/decoding');

  const env = decodeFramedEnvelopeV3(bytes);
  if (env.payload.case === 'error') {
    throw new Error(`bilateral.pending_list: ${env.payload.value.message}`);
  }
  if (env.payload.case !== 'offlineBilateralPendingListResponse') {
    throw new Error(`bilateral.pending_list answered ${String(env.payload.case)}, not the list`);
  }

  return env.payload.value.transactions.map((it) => {
    let phase: PendingBilateralPhase;
    switch (it.phase) {
      case pb.OfflineBilateralPhase.OFFLINE_PHASE_PREPARING: phase = 'preparing'; break;
      case pb.OfflineBilateralPhase.OFFLINE_PHASE_PREPARED: phase = 'prepared'; break;
      case pb.OfflineBilateralPhase.OFFLINE_PHASE_PENDING_USER_ACTION: phase = 'pending_user_action'; break;
      case pb.OfflineBilateralPhase.OFFLINE_PHASE_ACCEPTED: phase = 'accepted'; break;
      case pb.OfflineBilateralPhase.OFFLINE_PHASE_REJECTED: phase = 'rejected'; break;
      case pb.OfflineBilateralPhase.OFFLINE_PHASE_CONFIRM_PENDING: phase = 'confirm_pending'; break;
      case pb.OfflineBilateralPhase.OFFLINE_PHASE_COMMITTED: phase = 'committed'; break;
      case pb.OfflineBilateralPhase.OFFLINE_PHASE_FAILED: phase = 'failed'; break;
      default:
        throw new Error(`bilateral.pending_list: step ${it.id} has phase ${it.phase}, which the wire does not name`);
    }
    let direction: PendingBilateralDto['direction'];
    switch (it.direction) {
      case pb.OfflineBilateralDirection.OFFLINE_DIRECTION_INCOMING: direction = 'incoming'; break;
      case pb.OfflineBilateralDirection.OFFLINE_DIRECTION_OUTGOING: direction = 'outgoing'; break;
      default:
        throw new Error(`bilateral.pending_list: step ${it.id} has direction ${it.direction}, which the wire does not name`);
    }
    const counterpartyId = direction === 'outgoing' ? it.recipientId : it.senderId;
    if (it.commitmentHash.length !== 32 || counterpartyId.length !== 32) {
      throw new Error(
        `bilateral.pending_list: step ${it.id} has a ${it.commitmentHash.length}-byte commitment ` +
          `and a ${counterpartyId.length}-byte counterparty, not 32 and 32`,
      );
    }
    if (!it.tokenId) {
      throw new Error(`bilateral.pending_list: step ${it.id} names no token`);
    }
    const commitmentHash = encodeBase32Crockford(it.commitmentHash);
    return {
      id: commitmentHash,
      direction,
      phase,
      counterpartyAlias: it.counterpartyAlias,
      counterpartyDeviceId: encodeBase32Crockford(counterpartyId),
      amount: it.amount,
      displayAmount: it.displayAmount,
      tokenId: it.tokenId,
      commitmentHash,
      bleAddress: it.senderBleAddress,
      cancellable: it.cancellable,
    };
  });
}
