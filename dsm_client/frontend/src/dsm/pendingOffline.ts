// SPDX-License-Identifier: Apache-2.0
// The payments this device received offline, waiting for their unload (owner
// ruling, 2026-10-28: shown "separately from spendable balance, including
// asset, amount and pending-settlement status"). Each was committed by this
// device's own board and is held in its offline balance, apart from the
// allocation it pays from (owner, 2026-11-07). Rust keeps them, names the payer
// and renders each amount; this only reads them. They are in no online balance
// until the user unloads them (`unloadReceived`), and each moves only once its
// payer's return online has exposed its signed spend chain.

import * as pb from '../proto/dsm_app_pb';
import { routerQueryBin } from './WebViewBridge';
import { decodeFramedEnvelopeV3 } from './decoding';

export type PendingOfflineReceipt = {
  ticker: string;
  /** The amount as Rust rendered it, with the token's decimals. */
  displayAmount: string;
  /** The paying contact's alias, or its device id when it has none. */
  payer: string;
};

/** The receipts of a `wallet.pendingOffline` answer, oldest first. */
export function pendingOfflineView(response: pb.PendingOfflineValueResponse): PendingOfflineReceipt[] {
  return response.receipts.map((r) => ({
    ticker: r.ticker,
    displayAmount: r.displayAmount,
    payer: r.payer,
  }));
}

/** What this device holds pending now. */
export async function getPendingOffline(): Promise<PendingOfflineReceipt[]> {
  const route = 'wallet.pendingOffline';
  const pack = new pb.ArgPack({ codec: pb.Codec.PROTO, body: new Uint8Array(0) });
  const env = decodeFramedEnvelopeV3(await routerQueryBin(route, pack.toBinary()));
  if (env.payload.case === 'error') {
    throw new Error(env.payload.value.message || `${route} failed with code ${env.payload.value.code}`);
  }
  if (env.payload.case !== 'pendingOfflineValueResponse') {
    throw new Error(`STRICT: ${route} answered ${env.payload.case}`);
  }
  return pendingOfflineView(env.payload.value);
}
