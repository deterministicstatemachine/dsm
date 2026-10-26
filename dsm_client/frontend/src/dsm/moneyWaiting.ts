// SPDX-License-Identifier: Apache-2.0
// The transfers this device received and verified that the user has not
// opened the b0x inbox on yet (owner, 2026-10-23). Rust keeps the list and its
// count — the same count it hands the app icon; this only reads it and reports
// what the user was shown.

import * as pb from '../proto/dsm_app_pb';
import { routerInvokeBin, routerQueryBin } from './WebViewBridge';
import { decodeFramedEnvelopeV3 } from './decoding';
import { mapTransactions } from '../domain/mappers';
import type { DomainTransaction } from '../domain/types';

export type MoneyWaiting = {
  /** Newest first, each as the history shows it. */
  received: DomainTransaction[];
  /** Handed back to `markMoneySeen` once the user was shown `received`. */
  through: bigint;
};

function moneyWaitingFrom(route: string, bytes: Uint8Array): MoneyWaiting {
  const env = decodeFramedEnvelopeV3(bytes);
  if (env.payload.case === 'error') {
    throw new Error(env.payload.value.message || `${route} failed with code ${env.payload.value.code}`);
  }
  if (env.payload.case !== 'moneyWaitingResponse') {
    throw new Error(`STRICT: ${route} answered ${env.payload.case}`);
  }
  return {
    received: mapTransactions(env.payload.value.received),
    through: env.payload.value.through,
  };
}

/** What is waiting now. */
export async function getMoneyWaiting(): Promise<MoneyWaiting> {
  const pack = new pb.ArgPack({ codec: pb.Codec.PROTO, body: new Uint8Array(0) });
  return moneyWaitingFrom('inbox.moneyWaiting', await routerQueryBin('inbox.moneyWaiting', pack.toBinary()));
}

/** The user was shown every received transfer up to `through`; answers what is still waiting. */
export async function markMoneySeen(through: bigint): Promise<MoneyWaiting> {
  const req = new pb.MoneySeenRequest({ through });
  const pack = new pb.ArgPack({ codec: pb.Codec.PROTO, body: new Uint8Array(req.toBinary()) });
  return moneyWaitingFrom('inbox.moneySeen', await routerInvokeBin('inbox.moneySeen', pack.toBinary()));
}
