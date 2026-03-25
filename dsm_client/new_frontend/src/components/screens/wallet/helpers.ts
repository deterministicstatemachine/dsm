// SPDX-License-Identifier: Apache-2.0
// Shared helpers and types for the wallet screen components.
import { encodeBase32Crockford } from '../../../utils/textId';
import { formatTokenAmount } from '../../../utils/tokenMeta';
import type { DomainContact, DomainTransaction } from '../../../domain/types';

// Local UI types
export type Balance = {
  tokenId: string;
  symbol: string;
  balance: string | number;
  decimals?: number;
  usdValue?: string;
};

// Transaction type enum helpers (matches proto TransactionType)
export function txTypeLabel(v: number): string {
  switch (v) {
    case 1: return 'FAUCET';
    case 2: case 3: return 'OFFLINE';
    case 4: return 'ONLINE';
    case 5: return 'dBTC MINT';
    case 6: return 'dBTC BURN';
    default: return 'UNKNOWN';
  }
}

export function txTypeDetail(v: number): string {
  switch (v) {
    case 1: return 'Faucet Claim';
    case 2: return 'Bilateral Offline (BLE)';
    case 3: return 'Bilateral Offline (Recovered)';
    case 4: return 'Online';
    case 5: return 'BTC \u2192 dBTC Deposit';
    case 6: return 'dBTC \u2192 BTC Withdrawal';
    default: return 'Unknown';
  }
}

export function b32(bytes: unknown): string {
  if (typeof bytes === 'string' && bytes.length > 0) return bytes;
  if (bytes instanceof Uint8Array && bytes.length > 0) return encodeBase32Crockford(bytes);
  return '';
}

export function txTypeNumber(tx: DomainTransaction): number {
  switch (tx.txType) {
    case 'faucet': return 1;
    case 'bilateral_offline': return 2;
    case 'bilateral_offline_recovered': return 3;
    case 'online': return 4;
    case 'dbtc_mint': return 5;
    case 'dbtc_burn': return 6;
    default: return tx.type === 'offline' ? 2 : tx.type === 'online' ? 4 : 0;
  }
}

export function formatTxAmount(abs: bigint, tokenId: string): string {
  return formatTokenAmount(abs, tokenId);
}

export function shortStr(s: string, head = 8, tail = 8): string {
  return s.length <= head + tail + 3 ? s : `${s.slice(0, head)}...${s.slice(-tail)}`;
}

export function resolveAlias(deviceIdB32: string, aliasMap: Map<string, string>): string {
  if (!deviceIdB32) return '';
  return aliasMap.get(deviceIdB32) || shortStr(deviceIdB32, 8, 6);
}

export function buildAliasLookup(contacts: DomainContact[]): Map<string, string> {
  const map = new Map<string, string>();
  for (const c of contacts) {
    if (c.deviceId && c.alias) map.set(c.deviceId, c.alias);
  }
  return map;
}
