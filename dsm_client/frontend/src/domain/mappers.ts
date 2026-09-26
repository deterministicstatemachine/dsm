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
import type {
  DomainContact,
  DomainRelationshipSendBlockReason,
  DomainRelationshipSendCheckState,
  DomainRelationshipSendStatus,
  DomainTransaction,
  DomainTxType,
} from './types';

function toBase32(bytes?: Uint8Array | null): string {
  if (!(bytes instanceof Uint8Array)) return '';
  if (bytes.length === 0) return '';
  return toBase32Crockford(bytes);
}

function parseByteListString(input: string): Uint8Array | null {
  const s = String(input || '').trim();
  if (!s.includes(',')) return null;
  const parts = s.split(',').map(p => p.trim()).filter(Boolean);
  if (parts.length !== 32) return null;
  const out = new Uint8Array(32);
  for (let i = 0; i < parts.length; i += 1) {
    const n = Number(parts[i]);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    out[i] = n;
  }
  return out;
}

function normalizeIdField(value: any): string {
  if (value instanceof Uint8Array) return toBase32(value);
  if (typeof value === 'string') {
    const parsed = parseByteListString(value);
    if (parsed) return toBase32(parsed);
    return value;
  }
  return String(value ?? '');
}

export function normalizeBleAddress(input?: string): string | undefined {
  if (typeof input !== 'string') return undefined;
  const s = input.trim();
  if (!s) return undefined;
  // eslint-disable-next-line security/detect-unsafe-regex
  if (/^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/.test(s)) return s.toUpperCase();
  // eslint-disable-next-line security/detect-unsafe-regex
  if (/^[0-9a-fA-F]{12}$/.test(s)) {
    const parts: string[] = [];
    for (let i = 0; i < 12; i += 2) parts.push(s.slice(i, i + 2));
    return parts.join(':').toUpperCase();
  }
  return undefined;
}

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

export function mapContactList(list: any[], bleSnapshot?: { deviceIds: Record<string, string>; genesis: Record<string, string> }): DomainContact[] {
  const snapshot = bleSnapshot || { deviceIds: {}, genesis: {} };
  return list.map((c: any) => {
    // Strict proto field names — camelCase from @bufbuild/protobuf codegen.
    if ('genesis_hash' in c || 'device_id' in c || 'ble_address' in c) {
      console.error('[mappers] snake_case fields in contact — bridge returned raw data instead of protobuf');
    }

    const alias = c.alias instanceof Uint8Array ? toBase32(c.alias) : String(c.alias ?? 'Unknown');
    const deviceId = normalizeIdField(c.deviceId);
    const genesisHash = normalizeIdField(c.genesisHash);
    let chainTip = '';
    if (c.chainTip instanceof Uint8Array) {
      chainTip = toBase32(c.chainTip);
    } else if (c.chainTip?.tipHash instanceof Uint8Array) {
      chainTip = toBase32(c.chainTip.tipHash);
    } else if (c.chainTip?.v instanceof Uint8Array) {
      chainTip = toBase32(c.chainTip.v);
    } else if (typeof c.chainTip === 'string') {
      chainTip = c.chainTip;
    }
    const sendStatus = mapRelationshipSendStatus(c.sendStatus);

    const directBle = normalizeBleAddress(String(c.bleAddress || ''));
    const mappedBle = directBle || snapshot.deviceIds[deviceId] || snapshot.genesis[genesisHash] || undefined;
    return {
      alias,
      deviceId,
      genesisHash,
      chainTip: chainTip || undefined,
      bleAddress: mappedBle,
      status: c.status,
      genesisVerifiedOnline: c.genesisVerifiedOnline,
      verifyingStorageNodes: c.verifyingStorageNodes,
      signingPublicKey: c.publicKey instanceof Uint8Array && c.publicKey.length > 0
        ? toBase32(c.publicKey) : undefined,
      sendReady: sendStatus?.sendReady,
      sendCheckState: sendStatus?.sendCheckState,
      sendBlockReason: sendStatus?.sendBlockReason,
      sendBlockMessage: sendStatus?.sendBlockMessage,
    };
  });
}

const TX_TYPES: Record<number, DomainTxType> = {
  [TransactionType.TX_TYPE_BILATERAL_OFFLINE]: 'bilateral_offline',
  [TransactionType.TX_TYPE_ONLINE]: 'online',
  [TransactionType.TX_TYPE_DBTC_MINT]: 'dbtc_mint',
  [TransactionType.TX_TYPE_DBTC_BURN]: 'dbtc_burn',
};

function txBytes32(t: TransactionInfo, field: string, bytes: Uint8Array): string {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    throw new Error(`STRICT: transaction ${t.id} carries a ${field} that is not 32 bytes`);
  }
  return toBase32(bytes);
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
      fromDeviceId: txBytes32(t, 'sender device id', t.fromDeviceId),
      toDeviceId: txBytes32(t, 'recipient device id', t.toDeviceId),
      memo: t.memo.length > 0 ? t.memo : undefined,
      stitchedReceipt: t.stitchedReceipt.length > 0 ? t.stitchedReceipt : undefined,
      receiptVerified: t.receiptVerified,
    };
  });
}
