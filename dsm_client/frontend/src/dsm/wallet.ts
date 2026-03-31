/* eslint-disable @typescript-eslint/no-explicit-any */
import * as pb from '../proto/dsm_app_pb';
import {
    getAllBalancesStrictBridge,
    getWalletHistoryStrictBridge,
    getInboxStrictBridge,
} from './WebViewBridge';
import { TokenBalanceView, WalletHistory } from './types';
import { decodeFramedEnvelopeV3 } from './decoding';
import { mapTransactions } from '../domain/mappers';
import logger from '../utils/logger';

export async function getAllBalances(): Promise<TokenBalanceView[]> {
  try {
    const responseBytes = await getAllBalancesStrictBridge();
    const env = decodeFramedEnvelopeV3(responseBytes);
    if (env.payload.case === 'error') {
      const err = env.payload.value;
      throw new Error(`DSM native error: code=${err.code} msg=${err.message}`);
    }
    if (env.payload.case !== 'balancesListResponse') {
      throw new Error(`Unexpected payload case for balances: ${env.payload.case}`);
    }
    const balancesResponse = env.payload.value;

    const out = (balancesResponse.balances ?? []).map((b: any) => ({
      tokenId: b.tokenId || 'ERA',
      ticker: b.symbol || b.tokenId || 'ERA',
      balance: (b.available ?? 0).toString(),
      baseUnits: typeof b.available === 'bigint' ? b.available : BigInt(b.available || 0),
      decimals: typeof b.decimals === 'number' ? b.decimals : 0,
      symbol: b.symbol || b.tokenId || 'ERA',
      tokenName: b.tokenName || b.symbol || b.tokenId || 'ERA',
    }));
    return out;
  } catch (e) {
    logger.warn('[DSM] getAllBalances failed:', e);
    throw e;
  }
}

export async function getWalletBalance(): Promise<string> {
  try {
    const balances = await getAllBalances();
    if (balances.length > 0) {
      return balances[0].balance;
    }
    return "0";
  } catch (e) {
    logger.warn('getWalletBalance failed:', e);
    throw e;
  }
}

export async function getWalletHistory(): Promise<WalletHistory> {
  try {
    const responseBytes = await getWalletHistoryStrictBridge();

    // ALL bridge responses go through the single canonical decoder — no manual byte slicing.
    const env = decodeFramedEnvelopeV3(responseBytes);
    logger.debug('[DSM:getWalletHistory] Envelope v3 decoded, payload.case=', env.payload.case);

    // Check for top-level error
    if (env.payload.case === 'error') {
      const err = env.payload.value;
      throw new Error(`DSM native error (wallet-history): code=${err.code} msg=${err.message}`);
    }

    // Extract wallet history from envelope
    if (env.payload.case !== 'walletHistoryResponse') {
      logger.error('[DSM:getWalletHistory] Unexpected payload.case:', env.payload.case);
      throw new Error(`Unexpected payload case for wallet history: ${env.payload.case}`);
    }

    const historyResponse = env.payload.value;
    if (!historyResponse) {
      throw new Error('walletHistoryResponse payload is null');
    }

    const rawTxList = historyResponse.transactions ?? [];
    if (rawTxList.length > 0) {
      const first = rawTxList[0];
      logger.debug('[DSM:getWalletHistory] First tx', {
        amount: first.amount,
        amountSigned: first.amountSigned,
      });
    }
    // Map proto TransactionInfo → DomainTransaction at the envelope boundary.
    // No raw proto types may leak past this point.
    return { transactions: mapTransactions(rawTxList) };
  } catch (e) {
    logger.warn('[DSM] getWalletHistory failed:', e);
    throw e;
  }
}

export async function getTransactions(): Promise<any[]> {
  const history = await getWalletHistory();
  return history.transactions;
}

export async function getInbox(limit = 50): Promise<{ items: Array<{ id: string; preview: string; sender_id?: string; tick?: bigint; payload?: Uint8Array; isStaleRoute: boolean }> }> {
  try {
    const responseBytes = await getInboxStrictBridge({ limit });
    
    // CANONICAL PATH: All bridge responses are FramedEnvelopeV3
    const env = decodeFramedEnvelopeV3(responseBytes);
    logger.debug('[DSM:getInbox] Successfully decoded Envelope! payload.case=', env.payload.case);

    // Check for error response
    if (env.payload.case === 'error') {
      const err = env.payload.value;
      throw new Error(`Native error: ${err.message || 'Unknown'} (code ${err.code || 0})`);
    }

    // Extract inbox from envelope
    if (env.payload.case !== 'inboxResponse') {
      logger.error('[DSM:getInbox] Unexpected payload.case:', env.payload.case);
      throw new Error(`Unexpected payload case for inbox: ${env.payload.case}`);
    }

    const inboxResponse = env.payload.value;
    if (!inboxResponse) {
      throw new Error('inboxResponse payload is null');
    }

    const items = inboxResponse.items.map((item: pb.InboxItem) => ({
      id: item.id || '',
      preview: item.preview || '',
      sender_id: item.senderId,
      tick: item.tick,
      payload: item.payload,
      isStaleRoute: item.isStaleRoute,
    }));

    return { items };
  } catch (e) {
    logger.warn('[DSM:getInbox] Bridge call failed:', e);
    throw e;
  }
}

export async function listB0xMessages(): Promise<any[]> {
  const inbox = await getInbox();
  return inbox.items.map(item => ({
    id: item.id,
    preview: item.preview,
    tick: item.tick,
    senderId: item.sender_id,
    payload: item.payload,
    isStaleRoute: item.isStaleRoute ?? false,
  }));
}

export async function getTokens(): Promise<any[]> {
  const balances = await getAllBalances();
  return balances.map(balance => ({
    tokenId: balance.tokenId,
    balance: balance.balance,
    decimals: balance.decimals,
    symbol: balance.symbol || balance.tokenId || 'ERA',
  }));
}

export async function getToken(tokenId: string): Promise<any> {
  const balances = await getAllBalances();
  const balance = balances.find(b => b.tokenId === tokenId);
  if (!balance) return null;
  return {
    tokenId: balance.tokenId,
    balance: balance.balance,
    decimals: balance.decimals,
    symbol: balance.symbol || balance.tokenId || 'ERA',
  };
}
