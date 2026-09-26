// SPDX-License-Identifier: MIT OR Apache-2.0

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

/** A string field Rust leaves empty when it names nothing, carried as absent. */
function named(value: string): string | undefined {
  return value.length > 0 ? value : undefined;
}

export async function getAllBalances(): Promise<TokenBalanceView[]> {
  const responseBytes = await getAllBalancesStrictBridge();
  const env = decodeFramedEnvelopeV3(responseBytes);
  if (env.payload.case === 'error') {
    const err = env.payload.value;
    throw new Error(`DSM native error: code=${err.code} msg=${err.message}`);
  }
  if (env.payload.case !== 'balancesListResponse') {
    throw new Error(`Unexpected payload case for balances: ${env.payload.case}`);
  }
  return env.payload.value.balances.map((b: pb.BalanceGetResponse) => {
    for (const [field, value] of [
      ['token_id', b.tokenId],
      ['symbol', b.symbol],
      ['token_name', b.tokenName],
      ['display_amount', b.displayAmount],
    ] as const) {
      if (value.length === 0) {
        throw new Error(`STRICT: balance.list answered a row for ${b.tokenId || 'no token'} without its ${field}`);
      }
    }
    return {
      tokenId: b.tokenId,
      symbol: b.symbol,
      tokenName: b.tokenName,
      baseUnits: b.available,
      decimals: b.decimals,
      // Rust's rendered display form. This layer never computes it.
      displayAmount: b.displayAmount,
      canonicalTokenId: named(b.canonicalTokenId),
      // The token's CPTA anchor, rendered by Rust. Carried, never derived: a
      // second Base32 encoder pads the wrong group and yields an anchor that
      // resolves to nothing.
      policyAnchorB32: named(b.policyAnchorB32),
      anchorFingerprint: named(b.anchorFingerprint),
      // The token policy's icon field, carried from Rust. The wallet draws the coin from it.
      iconUrl: named(b.iconUrl),
    };
  });
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

export async function getInbox(limit = 50): Promise<{ items: Array<{ id: string; preview: string; sender_id?: string; payload?: Uint8Array; isStaleRoute: boolean }> }> {
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
    senderId: item.sender_id,
    isStaleRoute: item.isStaleRoute ?? false,
  }));
}

