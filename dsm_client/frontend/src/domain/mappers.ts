/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/domain/mappers.ts
// SPDX-License-Identifier: Apache-2.0

import { toBase32Crockford } from '../dsm/decoding';
import {
  RelationshipSendBlockReason,
  RelationshipSendCheckState,
  TransactionType,
  type TransactionInfo,
} from '../proto/dsm_app_pb';
import type { BilateralRelationshipDTO } from '../dsm/types';
import type {
  DomainContact,
  DomainRelationshipSendBlockReason,
  DomainRelationshipSendCheckState,
  DomainRelationshipSendStatus,
  DomainTransaction,
  DomainTxType,
} from './types';

function mapSendCheckState(value: unknown): DomainRelationshipSendCheckState | undefined {
  switch (value) {
    case RelationshipSendCheckState.CHECKING:
      return 'checking';
    case RelationshipSendCheckState.READY:
      return 'ready';
    case RelationshipSendCheckState.BLOCKED:
      return 'blocked';
    default:
      return undefined;
  }
}

function mapSendBlockReason(value: unknown): DomainRelationshipSendBlockReason | undefined {
  switch (value) {
    case RelationshipSendBlockReason.PENDING_CATCHUP:
      return 'pending_catchup';
    case RelationshipSendBlockReason.STATE_DIVERGENCE:
      return 'state_divergence';
    case RelationshipSendBlockReason.INTERNAL_ERROR:
      return 'internal_error';
    default:
      return undefined;
  }
}

export function mapRelationshipSendStatus(status: any): DomainRelationshipSendStatus | undefined {
  if (!status || typeof status !== 'object') return undefined;
  const sendReady = Boolean(status.sendReady);
  const sendCheckState = mapSendCheckState(status.sendCheckState);
  const sendBlockReason = mapSendBlockReason(status.sendBlockReason);
  const sendBlockMessage = typeof status.sendBlockMessage === 'string' && status.sendBlockMessage.trim().length > 0
    ? status.sendBlockMessage
    : undefined;
  if (!sendReady && !sendCheckState && !sendBlockReason && !sendBlockMessage) {
    return undefined;
  }
  return {
    sendReady,
    sendCheckState,
    sendBlockReason,
    sendBlockMessage,
  };
}

export function mapContactList(list: BilateralRelationshipDTO[]): DomainContact[] {
  return list.map((c) => {
    const sendStatus = mapRelationshipSendStatus(c.sendStatus);
    return {
      alias: c.alias,
      deviceId: toBase32Crockford(c.deviceId),
      genesisHash: toBase32Crockford(c.genesisHash),
      chainTip: c.chainTip ? toBase32Crockford(c.chainTip) : undefined,
      // The address Rust holds for the contact: pairing confirmed it.
      bleAddress: c.bleAddress,
      pairing: c.pairing,
      genesisVerifiedOnline: c.genesisVerifiedOnline,
      signingPublicKey: toBase32Crockford(c.publicKey),
      sendReady: sendStatus?.sendReady,
      sendCheckState: sendStatus?.sendCheckState,
      sendBlockReason: sendStatus?.sendBlockReason,
      sendBlockMessage: sendStatus?.sendBlockMessage,
    };
  });
}

const TX_TYPES: Record<number, DomainTxType> = {
  [TransactionType.TX_TYPE_FAUCET]: 'faucet',
  [TransactionType.TX_TYPE_BILATERAL_OFFLINE]: 'bilateral_offline',
  [TransactionType.TX_TYPE_ONLINE]: 'online',
  [TransactionType.TX_TYPE_DBTC_MINT]: 'dbtc_mint',
  [TransactionType.TX_TYPE_DBTC_BURN]: 'dbtc_burn',
};

function txBytes32(t: TransactionInfo, field: string, bytes: Uint8Array): string {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    throw new Error(`STRICT: transaction ${t.id} carries a ${field} that is not 32 bytes`);
  }
  return toBase32Crockford(bytes);
}

function noSender(t: TransactionInfo): undefined {
  if (t.fromDeviceId.length !== 0) {
    throw new Error(`STRICT: faucet claim ${t.id} names a sender device`);
  }
  return undefined;
}

function txText(t: TransactionInfo, field: string, value: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`STRICT: transaction ${t.id || '(no id)'} carries no ${field}`);
  }
  return value;
}

/**
 * `wallet.history` rows as Rust reports them. A row missing a field Rust
 * always writes, or of a type the wire does not name, is refused: nothing is
 * filled in or guessed.
 */
export function mapTransactions(list: TransactionInfo[]): DomainTransaction[] {
  return list.map((t) => {
    const txType = TX_TYPES[t.txType];
    if (!txType) {
      throw new Error(`STRICT: transaction ${t.id || '(no id)'} has type ${t.txType}, which the wire does not name`);
    }
    return {
      txId: txText(t, 'id', t.id),
      txHash: txBytes32(t, 'tx hash', t.txHash),
      txType,
      type: txType === 'bilateral_offline' ? 'offline' : txType === 'online' ? 'online' : undefined,
      amount: t.amountSigned,
      displayAmount: txText(t, 'display amount', t.displayAmount),
      tokenId: txText(t, 'token id', t.tokenId),
      recipient: txText(t, 'counterparty label', t.recipient),
      status: txText(t, 'status', t.status),
      // A faucet row's source is the ERA reserve: Rust names no sender device,
      // and a faucet row that names one is refused as corrupt.
      fromDeviceId: txType === 'faucet' ? noSender(t) : txBytes32(t, 'sender device id', t.fromDeviceId),
      toDeviceId: txBytes32(t, 'recipient device id', t.toDeviceId),
      memo: t.memo.length > 0 ? t.memo : undefined,
      stitchedReceipt: t.stitchedReceipt.length > 0 ? t.stitchedReceipt : undefined,
      receiptVerified: t.receiptVerified,
    };
  });
}
