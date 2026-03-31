/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/domain/mappers.ts
// SPDX-License-Identifier: Apache-2.0

import { toBase32Crockford } from '../dsm/decoding';
import type { DomainBalance, DomainContact, DomainIdentity, DomainTransaction } from './types';

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

export function toBigint(x: unknown): bigint {
  if (typeof x === 'bigint') return x;
  if (typeof x === 'number') return BigInt(Math.trunc(x));
  if (typeof x === 'string' && x.trim().length > 0) return BigInt(x);
  return 0n;
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

export function mapIdentity(id: any): DomainIdentity | null {
  // Strict proto field names — camelCase from @bufbuild/protobuf codegen.
  if (id && ('genesis_hash' in id || 'device_id' in id)) {
    console.error('[mappers] snake_case fields in identity — bridge returned raw data instead of protobuf');
  }
  const genesisHash = id?.genesisHash instanceof Uint8Array ? toBase32(id.genesisHash) : String(id?.genesisHash ?? '');
  const deviceId = id?.deviceId instanceof Uint8Array ? toBase32(id.deviceId) : String(id?.deviceId ?? '');
  if (!genesisHash || !deviceId) return null;
  return { genesisHash, deviceId };
}

export function mapBalanceList(list: any[]): DomainBalance[] {
  return list.map((b: any) => {
    // Strict proto field names — camelCase only. snake_case = raw data bug.
    if ('token_id' in b) {
      console.error('[mappers] snake_case fields in balance — bridge returned raw data instead of protobuf');
    }
    let tokenId = String(b.tokenId ?? '');
    const symbol = String(b.symbol ?? '');
    if (tokenId.includes(' ') || tokenId.includes('-')) tokenId = 'ERA';
    const tokenName = String(b.tokenName ?? symbol ?? tokenId ?? 'UNKNOWN');
    const balance = toBigint(b.balance);
    const decimals = typeof b.decimals === 'number' ? b.decimals : 0;
    return { tokenId, tokenName, balance, decimals, symbol };
  });
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
    const chainTip = c.chainTip instanceof Uint8Array ? toBase32(c.chainTip) : String(c.chainTip ?? '');
    const chainTipSmtProof = c.chainTipSmtProof;

    const directBle = normalizeBleAddress(String(c.bleAddress || ''));
    const mappedBle = directBle || snapshot.deviceIds[deviceId] || snapshot.genesis[genesisHash] || undefined;

    return {
      alias,
      deviceId,
      genesisHash,
      chainTip: chainTip || undefined,
      chainTipSmtProof: chainTipSmtProof || undefined,
      bleAddress: mappedBle,
      status: c.status,
      needsOnlineReconcile: c.needsOnlineReconcile,
      genesisVerifiedOnline: c.genesisVerifiedOnline,
      verifyCounter: typeof c.lastSeenTick === 'bigint' ? Number(c.lastSeenTick) : c.verifyCounter,
      addedCounter: typeof c.addedCounter === 'bigint' ? Number(c.addedCounter) : c.addedCounter,
      verifyingStorageNodes: c.verifyingStorageNodes,
      signingPublicKey: c.publicKey instanceof Uint8Array && c.publicKey.length > 0
        ? toBase32(c.publicKey) : undefined,
    };
  });
}

export function mapTransactions(list: any[]): DomainTransaction[] {
  const txTypeToString = (raw: unknown): string => {
    if (typeof raw === 'string' && raw.length > 0) return raw;
    if (typeof raw === 'number') {
      switch (raw) {
        case 1:
          return 'faucet';
        case 2:
          return 'bilateral_offline';
        case 3:
          return 'bilateral_offline_recovered';
        case 4:
          return 'online';
        case 5:
          return 'dbtc_mint';
        case 6:
          return 'dbtc_burn';
        default:
          return '';
      }
    }
    return '';
  };

  return list.map((t: any) => {
    // Strict proto field names — camelCase from @bufbuild/protobuf codegen.
    if ('tx_id' in t || 'from_device_id' in t || 'to_device_id' in t) {
      console.error('[mappers] snake_case fields in transaction — bridge returned raw data instead of protobuf');
    }
    const txId = t.txHash instanceof Uint8Array ? toBase32(t.txHash) : String(t.txId ?? t.id ?? '');
    const recipient = t.toDeviceId instanceof Uint8Array ? toBase32(t.toDeviceId) : String(t.recipient ?? '');
    const amountSignedRaw = t.amountSigned ?? t.amount ?? 0;
    const amount = toBigint(amountSignedRaw);
    const txType = txTypeToString(t.txType);
    const status = (typeof t.status === 'string' && t.status.length > 0) ? t.status : 'confirmed';
    const fromDevice = t.fromDeviceId instanceof Uint8Array
      ? toBase32(t.fromDeviceId)
      : typeof t.fromDeviceId === 'string'
        ? t.fromDeviceId
        : undefined;
    const toDevice = t.toDeviceId instanceof Uint8Array
      ? toBase32(t.toDeviceId)
      : typeof t.toDeviceId === 'string'
        ? t.toDeviceId
        : undefined;
    const txHash = t.txHash instanceof Uint8Array
      ? toBase32(t.txHash)
      : typeof t.txHash === 'string'
        ? t.txHash
        : undefined;
    const stitchedReceipt = t.stitchedReceipt instanceof Uint8Array
      ? t.stitchedReceipt
      : undefined;
    // Resolve tokenId: use explicit field first, then infer from txType for dBTC ops.
    const rawTokenId = typeof t.tokenId === 'string' && t.tokenId.length > 0
      ? t.tokenId
      : undefined;
    const tokenId = rawTokenId
      || (txType === 'dbtc_mint' || txType === 'dbtc_burn' ? 'dBTC' : undefined);
    const createdAtRaw = t.createdAt;
    const createdAt = typeof createdAtRaw === 'bigint'
      ? Number(createdAtRaw)
      : typeof createdAtRaw === 'number'
        ? createdAtRaw
        : typeof createdAtRaw === 'string'
          ? Number.parseInt(createdAtRaw, 10)
          : undefined;
    const memo = typeof t.memo === 'string' && t.memo.length > 0 ? t.memo : undefined;
    const type: 'online' | 'offline' = (txType === 'bilateral_offline' || txType === 'bilateral_offline_recovered')
      ? 'offline'
      : (txType === 'faucet' || txType === 'online')
        ? 'online'
        : (t.type === 'offline' || t.type === 'online')
          ? t.type
          : 'online';
    return {
      txId,
      type,
      amount,
      recipient,
      status: status as any,
      syncStatus: t.syncStatus,
      txType: txType || undefined,
      txHash,
      fromDeviceId: fromDevice,
      toDeviceId: toDevice,
      amountSigned: amount,
      stitchedReceipt,
      receiptVerified: !!t.receiptVerified,
      tokenId,
      createdAt: (typeof createdAt === 'number' && Number.isFinite(createdAt) && createdAt > 0) ? createdAt : undefined,
      memo,
    };
  });
}
