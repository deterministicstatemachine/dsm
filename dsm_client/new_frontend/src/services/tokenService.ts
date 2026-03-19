/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/services/tokenService.ts
// SPDX-License-Identifier: Apache-2.0
// Token Service — Protobuf-only (strict, v3 envelope path via dsmClient)

export interface TokenBalance {
  tokenId: string;
  balance: number;
  symbol: string;
  decimals: number;
}
export interface TokenMetadata {
  tokenId: string;
  name: string;
  symbol: string;
  decimals: number;
  totalSupply?: number;
  circulatingSupply?: number;
}

import { dsmClient } from '../dsm/index';
import { getTokenDecimals } from '../utils/tokenMeta';

function normalizeToSdkTokenId(id: string): string {
  if (!id) return id;
  const u = id.trim().toUpperCase();
  return u === 'ERA' ? 'ERA' : id;
}
function presentSymbolFor(tokenId: string): string { return tokenId.toUpperCase() === 'ERA' ? 'ERA' : tokenId; }
function presentNameFor(tokenId: string): string { return tokenId.toUpperCase() === 'ERA' ? 'ERA Token' : tokenId; }
// Single source of truth — imported from tokenMeta.
const decimalsFor = getTokenDecimals;

function toNumberClamped(intString: string): number {
  const bn = BigInt(String(intString ?? '0'));
  const max = BigInt(Number.MAX_SAFE_INTEGER);
  if (bn > max) return Number(max);
  if (bn < -max) return -Number(max);
  return Number(bn);
}

export async function getTokenBalance(tokenId: string): Promise<TokenBalance> {
  const sdkId = normalizeToSdkTokenId(tokenId);
  const balances = await dsmClient.getAllBalances();
  const found = balances.find(b => String(b.tokenId).toUpperCase() === sdkId.toUpperCase());
  if (!found) {
    return { tokenId, balance: 0, symbol: presentSymbolFor(tokenId), decimals: decimalsFor(sdkId) };
  }
  return {
    tokenId,
    balance: toNumberClamped(String(found.balance)),
    symbol: presentSymbolFor(String(found.tokenId)),
    decimals: decimalsFor(String(found.tokenId)),
  };
}

export async function getTokenMetadata(tokenId: string): Promise<TokenMetadata> {
  const sdkId = normalizeToSdkTokenId(tokenId);
  const balances = await dsmClient.getAllBalances();
  const _onLedger = balances.find(b => String(b.tokenId).toUpperCase() === sdkId.toUpperCase());
  return {
    tokenId,
    name: presentNameFor(sdkId),
    symbol: presentSymbolFor(sdkId),
    decimals: decimalsFor(sdkId),
  };
}

export async function listTokens(): Promise<TokenMetadata[]> {
  const balances = await dsmClient.getAllBalances();
  const byId = new Map<string, { tokenId: string; symbol: string }>();
  for (const b of balances) {
    const id = String(b.tokenId);
    if (!byId.has(id)) byId.set(id, { tokenId: id, symbol: String(b.symbol ?? presentSymbolFor(id)) });
  }
  return Array.from(byId.values()).map(({ tokenId }) => ({
    tokenId: tokenId === 'ERA' ? 'ERA' : tokenId,
    name: presentNameFor(tokenId),
    symbol: presentSymbolFor(tokenId),
    decimals: decimalsFor(tokenId),
  }));
}

export async function createToken(): Promise<never> {
  throw new Error('STRICT: use dsmClient.createToken from UI; tokenService is read-only');
}
export async function transferToken(): Promise<never> {
  throw new Error('STRICT: use dsmClient.sendOnlineTransfer or sendOfflineTransfer');
}

export default { getTokenBalance, getTokenMetadata, listTokens, createToken, transferToken };