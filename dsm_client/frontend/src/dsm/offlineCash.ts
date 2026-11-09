// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Moving a token between this device's balances: the online account, spent
// through the storage nodes; the offline allocation the anchor appliance spends
// over Bluetooth; and what the device received offline, which its board
// committed and which moves online by its unload. Rust makes the move and
// scales the amount; this layer carries the user's text in and Rust's rendered
// figures out.

import * as pb from '../proto/dsm_app_pb';
import { routerInvokeBin } from './WebViewBridge';
import { decodeFramedEnvelopeV3 } from './decoding';

/** What Rust answered a load or unload: both balances after the move, rendered by Rust. */
export interface OfflineCashMove {
  onlineDisplay: string;
  allocationDisplay: string;
  /** Rust's own sentence about the move. */
  message: string;
}

async function moveOfflineCash(
  method: 'wallet.loadOffline' | 'wallet.unloadOffline',
  tokenId: string,
  amount: string,
): Promise<OfflineCashMove> {
  const body = new Uint8Array(new pb.OfflineCashRequest({ tokenId, amount: amount.trim() }).toBinary());
  const arg = new pb.ArgPack({ codec: pb.Codec.PROTO, body });
  const env = decodeFramedEnvelopeV3(await routerInvokeBin(method, new Uint8Array(arg.toBinary())));
  if (env.payload.case === 'error') {
    throw new Error(env.payload.value.message || `${method}: error code ${env.payload.value.code}`);
  }
  if (env.payload.case !== 'offlineCashResponse') {
    throw new Error(`${method}: the SDK answered ${String(env.payload.case)}, not offlineCashResponse`);
  }
  const res = env.payload.value;
  if (!res.success) {
    throw new Error(res.message || `${method}: the SDK refused the move`);
  }
  if (res.onlineDisplay.length === 0 || res.allocationDisplay.length === 0) {
    throw new Error(`STRICT: ${method} answered without its rendered balances`);
  }
  return { onlineDisplay: res.onlineDisplay, allocationDisplay: res.allocationDisplay, message: res.message };
}

/** Load `amount` (decimal text, as typed) of `tokenId` from the online account into the offline allocation. */
export function loadOfflineCash(tokenId: string, amount: string): Promise<OfflineCashMove> {
  return moveOfflineCash('wallet.loadOffline', tokenId, amount);
}

/** Unload `amount` (decimal text, as typed) of `tokenId` from the offline allocation back to the online account. */
export function unloadOfflineCash(tokenId: string, amount: string): Promise<OfflineCashMove> {
  return moveOfflineCash('wallet.unloadOffline', tokenId, amount);
}

/** What Rust answered an unload of the money received offline. */
export interface ReceivedUnload {
  /** The payments that moved into the online balance. */
  moved: number;
  /** The payments still waiting for their payers to be back online. */
  waiting: number;
  /** Rust's own sentence about the move. */
  message: string;
}

/**
 * Move every payment received offline that is ready into the online balance (owner, 2026-11-07:
 * "One tap, all ready"). A payment is ready once its payer has been back online; the rest stay in
 * the offline balance, waiting. Nothing moves until this is asked for.
 */
export async function unloadReceived(): Promise<ReceivedUnload> {
  const method = 'wallet.unloadReceived';
  const arg = new pb.ArgPack({ codec: pb.Codec.PROTO, body: new Uint8Array(0) });
  const env = decodeFramedEnvelopeV3(await routerInvokeBin(method, new Uint8Array(arg.toBinary())));
  if (env.payload.case === 'error') {
    throw new Error(env.payload.value.message || `${method}: error code ${env.payload.value.code}`);
  }
  if (env.payload.case !== 'unloadReceivedResponse') {
    throw new Error(`${method}: the SDK answered ${String(env.payload.case)}, not unloadReceivedResponse`);
  }
  const res = env.payload.value;
  if (res.message.length === 0) {
    throw new Error(`STRICT: ${method} answered without its sentence`);
  }
  return { moved: res.moved, waiting: res.waiting, message: res.message };
}
