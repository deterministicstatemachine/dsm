/* eslint-disable @typescript-eslint/no-explicit-any */
// path: dsm_client/new_frontend/src/hooks/useTransactions.ts
/* SPDX-License-Identifier: Apache-2.0 */
/* eslint-disable @typescript-eslint/no-unsafe-function-type */

// useTransactions.ts — STRICT, protobuf-only boundary, no window.DSM.
// All native interaction must flow through dsmClient.

import { useCallback, useEffect, useState } from 'react';
import { dsmClient } from '@/services/dsmClient';
import { toBase32Crockford } from '../dsm/decoding';
import { emitWalletRefresh } from '@/dsm/events';
import { bridgeEvents } from '@/bridge/bridgeEvents';
import { headerService } from '@/services/headerService';
import logger from '@/utils/logger';

export type TransactionType = 'online' | 'offline';
export type TransactionStatus = 'pending' | 'confirmed' | 'failed';
export type SyncStatus = 'synced' | 'syncing' | 'unsynced' | undefined;

export interface Transaction {
  txId: string;
  type: TransactionType;
  amount: bigint;          // base units (integer)
  recipient: string;       // hex or human-readable id
  txHash?: string;         // hex string of transaction hash (optional)
  status: TransactionStatus;
  syncStatus?: SyncStatus;
  txType?: string;         // raw txType from backend: "faucet", "bilateral_offline", "bilateral_offline_recovered"
  fromDeviceId?: string;
  toDeviceId?: string;
  counterpartyDeviceId?: string;
  stitchedReceipt?: Uint8Array;
  receiptVerified?: boolean;
  localReceivedAt?: number; // Deterministic local counter when first observed
  createdAt?: number;      // unix timestamp (seconds) from backend
  memo?: string;           // optional memo/note
  tokenId?: string;        // token identifier from backend (e.g. "ERA", "dBTC")
}

let localReceivedCounter = 0;
function nextLocalReceivedCounter(): number {
  localReceivedCounter = (localReceivedCounter + 1) >>> 0;
  return localReceivedCounter;
}

export interface TransferInput {
  recipientAlias: string;       // Contact alias (not genesis hash)
  amount: string;               // decimal string (e.g., "12.34")
  offline?: boolean;            // default online
  memo?: string;
  decimals?: number;            // token decimals (default 0)
  tokenId?: string;             // token identifier (e.g. "ERA", "dBTC")
}

/* --------- Required client API (all calls go through dsmClient) ---------- */
type GetTxHistory = () => Promise<{
  transactions: Array<{
    txId: string;
    type: TransactionType;
    amount: string | number | bigint;
    recipient: string;
    createdAt?: number;
    memo?: string;
    status: TransactionStatus;
    syncStatus?: SyncStatus;
    stitchedReceipt?: Uint8Array;
  }>;
}>;

// eslint-disable-next-line @typescript-eslint/no-unused-vars
type PrepareOffline = (recipientGenesis: Uint8Array, amount: bigint) => Promise<{
  tokenId: Uint8Array;
  nonce: Uint8Array;
  signature: Uint8Array;
  chainTip: bigint;
}>;

// eslint-disable-next-line @typescript-eslint/no-unused-vars
type StartOfflineSession = () => Promise<Uint8Array>; // wraps native/Bluetooth; NO window.DSM

// eslint-disable-next-line @typescript-eslint/no-unused-vars
type SendOffline = (
  tokenId: Uint8Array,
  recipientGenesis: Uint8Array,
  amount: bigint,
  nonce: Uint8Array,
  signature: Uint8Array,
  chainTip: bigint,
  sessionId: Uint8Array,
  requiresAcceptance: boolean,
  memo?: string
) => Promise<{ success: boolean; error?: { message?: string } }>;

type SendOnlineSmart = (
  recipientAlias: string,
  scaledAmountStr: string,
  memo?: string
) => Promise<{ success: boolean; error?: { message?: string }; newBalance?: number }>;

/* -------------------------- Strict helpers ------------------------------- */
function requireFn<T extends Function>(obj: any, name: string): T {
  const fn = obj?.[name];
  if (typeof fn !== 'function') {
    throw new Error(`STRICT: dsmClient.${name} is required but not implemented`);
  }
  return fn as unknown as T;
}

function toBaseUnits(amountStr: string, decimals: number): bigint {
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 36) {
    throw new Error('STRICT: decimals must be an integer 0..36');
  }
  const s = amountStr.trim();
  // eslint-disable-next-line security/detect-unsafe-regex
  if (!/^\d+(\.\d+)?$/.test(s)) throw new Error('STRICT: amount must be a positive decimal string');
  const [rawInts, fracs = ''] = s.split('.');
  const ints = rawInts.replace(/^0+(?=\d)/, '') || '0';
  if (fracs.length > decimals) {
    throw new Error(`STRICT: amount has more than ${decimals} fractional digits`);
  }
  const fracPadded = fracs.padEnd(decimals, '0');
  const joined = decimals > 0 ? `${ints}${fracPadded}` : ints;
  const normalized = joined.replace(/^0+(?=\d)/, '') || '0';
  return BigInt(normalized);
}

function toBigIntSignedStrict(v: string | number | bigint, field = 'amount'): bigint {
  if (typeof v === 'bigint') return v;
  if (typeof v === 'string') {
    if (!/^-?\d+$/.test(v)) throw new Error(`STRICT: ${field} must be a signed integer string in base units`);
    return BigInt(v);
  }
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v)) {
      throw new Error(`STRICT: ${field} must be a safe integer`);
    }
    return BigInt(Math.trunc(v));
  }
  throw new Error(`STRICT: ${field} has invalid type`);
}

export type TxFormatter = (v: unknown) => string;

/* -------------------------------- Hook ----------------------------------- */
export function useTransactions() {
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [isProcessing, setIsProcessing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Cache alias lookups for transaction rendering. Contacts are fetched once per refresh.
  const buildAliasLookup = (contacts: Array<{ alias?: unknown; deviceId?: unknown }>): Map<string, string> => {
    const m = new Map<string, string>();
    for (const c of contacts) {
      const alias = String((c as any)?.alias ?? '').trim();
      const deviceId = String((c as any)?.deviceId ?? '').trim();
      if (!alias || !deviceId) continue;
      // Contacts store deviceId as Base32 Crockford string.
      m.set(deviceId, alias);
    }
    return m;
  };

  const resolveCounterpartyLabel = (
    deviceIdBytes: unknown,
    aliasByDeviceId: Map<string, string>
  ): string | null => {
    if (typeof deviceIdBytes === 'string' && deviceIdBytes.trim().length > 0) {
      const alias = aliasByDeviceId.get(deviceIdBytes);
      return alias || (deviceIdBytes.length > 16 ? `${deviceIdBytes.substring(0, 16)  }...` : deviceIdBytes);
    }
    if (!(deviceIdBytes instanceof Uint8Array) || deviceIdBytes.length === 0) return null;
    const base32 = toBase32Crockford(deviceIdBytes);
    const alias = aliasByDeviceId.get(base32);
    if (alias) return alias;
    return base32.length > 16 ? `${base32.substring(0, 16)  }...` : base32;
  };

  const refresh = useCallback(async () => {
    setError(null);

    // Fetch contacts (best-effort) to render aliases for counterparties.
    let aliasByDeviceId: Map<string, string> = new Map();
    try {
      const contactsRes = await dsmClient.getContacts();
      const contacts = Array.isArray((contactsRes as any)?.contacts) ? (contactsRes as any).contacts : [];
      aliasByDeviceId = buildAliasLookup(contacts);
    } catch {
      // ignore; use truncated IDs
    }

    // Use canonical wallet history API
    const getWalletHistory = requireFn<GetTxHistory>(dsmClient as any, 'getWalletHistory');
    const data = await getWalletHistory();
    if (!data || !Array.isArray(data.transactions)) {
      throw new Error('STRICT: backend did not return { transactions: [...] }');
    }

    const mapped: Transaction[] = data.transactions.map((t, idx) => {
      // Strict but robust mapping: derive safe defaults for faucet/system entries.
      const anyT: any = t as any;

      // tx_id derivation: id, logical_index or idx-based (proto uses 'id' not 'tx_id')
      const txId: string = (anyT.id || t.txId)
        ? String(anyT.id || t.txId)
        : (anyT.logicalIndex !== undefined || anyT.logical_index !== undefined
            ? `tx:${String(anyT.logicalIndex ?? anyT.logical_index)}`
            : `tx:${idx}`);

      // type: ALWAYS infer from tx_type first (more reliable), then fall back to explicit type field
      // Proto uses camelCase 'txType', but backend may send snake_case 'tx_type'
      // tx_type values: enum (0=unspecified, 1=faucet, 2=bilateral_offline, 3=bilateral_offline_recovered, 4=online)
      // string values: "bilateral_offline", "bilateral_offline_recovered", "faucet", "online"
      let type: TransactionType;
      const txTypeRaw = anyT.txType ?? anyT.tx_type;
      let txTypeStr: string;
      
      if (typeof txTypeRaw === 'number') {
        // New enum format
        switch (txTypeRaw) {
          case 1: txTypeStr = 'faucet'; break;
          case 2: txTypeStr = 'bilateral_offline'; break;
          case 3: txTypeStr = 'bilateral_offline_recovered'; break;
          case 4: txTypeStr = 'online'; break;
          default: txTypeStr = 'online'; break; // unspecified defaults to online
        }
      } else if (typeof txTypeRaw === 'string') {
        txTypeStr = txTypeRaw;
      } else {
        txTypeStr = '';
      }
      
      if (txTypeStr === 'bilateral_offline' || txTypeStr === 'bilateral_offline_recovered') {
        type = 'offline';
      } else if (txTypeStr === 'faucet' || txTypeStr === 'online') {
        type = 'online';
      } else if (t.type === 'offline' || t.type === 'online') {
        type = t.type as TransactionType;
      } else {
        type = 'online'; // default mapping
      }

      // status default: 'confirmed'
      const status: TransactionStatus = (anyT.status as TransactionStatus) ?? 'confirmed';

      // Parse created_at timestamp (proto camelCase)
      let createdAtNum: number | undefined;
      const createdAtRaw = anyT.createdAt ?? anyT.created_at;
      if (createdAtRaw !== undefined && createdAtRaw !== null) {
        if (typeof createdAtRaw === 'bigint') createdAtNum = Number(createdAtRaw);
        else if (typeof createdAtRaw === 'number') createdAtNum = createdAtRaw;
        else if (typeof createdAtRaw === 'string') createdAtNum = parseInt(createdAtRaw, 10) || undefined;
      }

      // Parse memo
      const memoRaw = anyT.memo;
      const memo = (typeof memoRaw === 'string' && memoRaw.length > 0) ? memoRaw : undefined;

      // Extract tx_hash: may be string (post-mapTransactions) or Uint8Array (raw proto)
      let txHashStr: string | undefined;
      try {
        const rawHash: any = anyT.txHash ?? anyT.tx_hash;
        if (typeof rawHash === 'string' && rawHash.length > 0) {
          txHashStr = rawHash;
        } else if (rawHash instanceof Uint8Array && rawHash.length > 0) {
          txHashStr = toBase32Crockford(rawHash);
        }
      } catch {}

      const normalizeDeviceId = (value: unknown): string | undefined => {
        if (typeof value === 'string' && value.trim().length > 0) return value;
        if (value instanceof Uint8Array && value.length > 0) return toBase32Crockford(value);
        return undefined;
      };

      const fromDeviceId = normalizeDeviceId(anyT.fromDeviceId ?? anyT.from_device_id);
      const toDeviceId = normalizeDeviceId(anyT.toDeviceId ?? anyT.to_device_id);

      // Use signed amount (amountSigned) - standardized camelCase
      let amountBI = 0n;
      const signedVal = anyT.amountSigned;
      
      if (signedVal !== undefined && signedVal !== null) {
        amountBI = toBigIntSignedStrict(signedVal, 'transaction.amountSigned');
      } else if (anyT.amount !== undefined && anyT.amount !== null) {
        // If signed amount is missing but we have an unsigned magnitude, infer direction
        const mag = toBigIntSignedStrict(anyT.amount, 'transaction.amount');
        if (mag > 0n) {
          // Infer direction from device IDs if possible
          // We need local device ID to know if we are sender
          try {
            // dsmClient.getLocalDeviceId() is synchronous and cached
            const localDevId = (dsmClient as any).getLocalDeviceId?.(); 
            const fromDevId = anyT.fromDeviceId ?? anyT.from_device_id;
            
            if (localDevId && fromDevId && 
                localDevId instanceof Uint8Array && fromDevId instanceof Uint8Array &&
                localDevId.length === 32 && fromDevId.length === 32) {
              
              // Compare bytes
              let isFromMe = true;
              for(let i=0; i<32; i++) {
                if (localDevId[i] !== fromDevId[i]) { isFromMe = false; break; }
              }
              
              if (isFromMe) {
                amountBI = -mag; // Outgoing
              } else {
                amountBI = mag; // Incoming
              }
            } else {
              // Conservative default: assume incoming if we can't prove otherwise
              amountBI = mag;
            }
          } catch {
            amountBI = mag;
          }
        } else {
          amountBI = 0n;
        }
      } else {
        throw new Error('STRICT: transaction.amount has invalid type');
      }

      // Determine counterparty (displayed as 'recipient' in the struct)
      // We want to show the OTHER party.
      // If Incoming (amount > 0): Show Sender (from_device_id)
      // If Outgoing (amount < 0): Show Recipient (recipient alias OR to_device_id)
      
      let recipient = 'Unknown';
      const isIncoming = amountBI > 0n;
      
      if (txTypeStr === 'faucet') {
        recipient = 'FAUCET';
      } else if (isIncoming) {
        // INCOMING: We want the SENDER
        const fromDev = anyT.fromDeviceId ?? anyT.from_device_id;

        const label = resolveCounterpartyLabel(fromDev, aliasByDeviceId);
        if (label) {
         recipient = label;
        } else if (anyT.recipient && anyT.recipient !== 'Me') {
           // Use recipient field if it might be the sender (ambiguous backend)
           let r = String(anyT.recipient);
           // Defensive check for binary content in string field
           // eslint-disable-next-line no-control-regex
           if (/[\x00-\x1F]/.test(r)) {
             logger.warn('[useTransactions] Detected binary in recipient string; using Unknown');
             r = 'Unknown';
           }
           recipient = r;
        }
      } else {
        // OUTGOING: We want the RECIPIENT
        if (typeof anyT.recipient === 'string' && anyT.recipient.length > 0) {
           let r = String(anyT.recipient);
           // Defensive check for binary content
           // eslint-disable-next-line no-control-regex
           if (/[\x00-\x1F]/.test(r)) {
              logger.warn('[useTransactions] Detected binary in recipient string; ignoring');
              r = ''; 
           }
           if (r) recipient = r;
           else {
             const toDev = anyT.toDeviceId ?? anyT.to_device_id;
             const label = resolveCounterpartyLabel(toDev, aliasByDeviceId);
             if (label) recipient = label;
           }
        } else {
           const toDev = anyT.toDeviceId ?? anyT.to_device_id;
          const label = resolveCounterpartyLabel(toDev, aliasByDeviceId);
          if (label) recipient = label;
        }
      }

      const counterpartyDeviceId = isIncoming ? fromDeviceId : toDeviceId;

      const stitchedReceipt = (anyT.stitchedReceipt instanceof Uint8Array && anyT.stitchedReceipt.length > 0)
        ? anyT.stitchedReceipt
        : (anyT.stitched_receipt instanceof Uint8Array && anyT.stitched_receipt.length > 0)
          ? anyT.stitched_receipt
          : undefined;

      const tokenId: string | undefined = (() => {
        const raw = anyT.tokenId;
        if (typeof raw === 'string' && raw.length > 0) return raw;
        return undefined;
      })();

      return {
        txId,
        type,
        amount: amountBI,
        recipient,
        txHash: txHashStr,
        status,
        syncStatus: anyT.syncStatus ?? anyT.sync_status,
        txType: txTypeStr || undefined,
        fromDeviceId,
        toDeviceId,
        counterpartyDeviceId,
        stitchedReceipt,
        receiptVerified: !!anyT.receiptVerified,
        localReceivedAt: nextLocalReceivedCounter(),
        createdAt: createdAtNum,
        memo,
        tokenId,
      };
    });

    setTransactions(mapped);
  }, []);

  const sendTransfer = useCallback(async (input: TransferInput): Promise<boolean> => {
    setIsProcessing(true);
    setError(null);
    try {
      // Validate inputs early
      const decimals = Number.isFinite(input.decimals ?? NaN) ? Number(input.decimals) : 0;
      const amountBU = toBaseUnits(input.amount, decimals);

      // Note: recipientAlias is passed to backend; backend must resolve to device_id
      let ok = false;

      if (input.offline) {
        // Offline: we must resolve alias -> device_id locally (no network), then call bilateral prepare.
        const contactsRes = await dsmClient.getContacts();
        const contacts = Array.isArray(contactsRes?.contacts) ? contactsRes.contacts : [];

        const needle = String(input.recipientAlias ?? '').trim().toLowerCase();
        if (!needle) throw new Error('Recipient alias is required');

        const match = contacts.find(c => String(c?.alias ?? '').trim().toLowerCase() === needle);
        if (!match?.deviceId) {
          throw new Error(`Unknown alias for offline transfer: ${input.recipientAlias}`);
        }

        const toDeviceIdB32 = match.deviceId;
        const bleAddress = await dsmClient.resolveBleAddressForContact(match as any);
        if (!bleAddress || typeof bleAddress !== 'string' || bleAddress.length === 0) {
          throw new Error('Offline transfer requires a BLE address for the recipient');
        }

        // Use the selected token
        const tokenId = input.tokenId || 'ERA';

        // Token selection uses input.tokenId
        const res = await dsmClient.sendOfflineTransfer({
          tokenId,
          to: toDeviceIdB32,
          amount: amountBU.toString(10),
          memo: input.memo,
          bleAddress,
        });
        ok = Boolean((res as any)?.success ?? (res as any)?.accepted);
        if (!ok) throw new Error(String((res as any)?.result || (res as any)?.message || 'Offline transfer failed'));
      } else {
        // Online: pass alias and scaled amount; backend resolves contact
        const sendOnlineTransferSmart = requireFn<SendOnlineSmart>(dsmClient, 'sendOnlineTransferSmart');
        const scaledAmountStr = amountBU.toString(10);
        const res = await sendOnlineTransferSmart(input.recipientAlias, scaledAmountStr, input.memo);
        ok = !!res?.success;
        if (!ok) throw new Error(res?.error?.message || 'Online transfer failed');
        // Immediate sender balance reflect: fire wallet.sendCommitted so WalletContext
        // dispatches IMMEDIATE_BALANCE_SET without waiting for the async SQLite refresh.
        if (ok && res?.newBalance !== undefined && res.newBalance !== null) {
          try {
            bridgeEvents.emit('wallet.sendCommitted', {
              success: true,
              tokenId: input.tokenId ?? 'ERA',
              newBalance: res.newBalance,
            } as any);
          } catch {}
        }
      }

      if (ok) {
        headerService.invalidateCache();
        // Canonical wallet refresh: single deterministic pathway.
        try { emitWalletRefresh({ source: 'wallet.send' }); } catch {}
      }

      // Best-effort refresh; don't fail a successful transfer if history isn't wired in tests/env
      try {
        await refresh();
      } catch {
        // ignore
      }
      return true;
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return false;
    } finally {
      setIsProcessing(false);
    }
  }, [refresh]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        // Only refresh if we have an identity
        const hasIdentity = await dsmClient.isReady();
        if (!hasIdentity) {
          logger.debug('[useTransactions] Skipping refresh: no identity yet');
          return;
        }
        await refresh();
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => { cancelled = true; };
  }, [refresh]);

  const formatAmount: (v: unknown) => string = (v) => String(v ?? '');

  return {
    formatAmount,
    transactions,
    isProcessing,
    error,
    refresh,
    sendTransfer,
  };
}
