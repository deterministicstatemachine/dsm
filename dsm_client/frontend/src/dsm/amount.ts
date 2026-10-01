// SPDX-License-Identifier: MIT OR Apache-2.0
//
// An amount in both its forms, as Rust converts it. One rule in Rust parses
// what a person typed into base units and renders base units for display; the
// client converts no amount itself, and asks here when it holds one form and
// needs the other.

import * as pb from '../proto/dsm_app_pb';
import { routerQueryBin } from './WebViewBridge';
import { decodeFramedEnvelopeV3 } from './decoding';

/**
 * What an amount is counted in: a token Rust knows, at the decimals of its
 * committed policy, or a stated count of decimals for a token no policy on this
 * device commits (the tour's practice coin).
 */
export type AmountUnit = { tokenId: string } | { decimals: number };

/** The amount: as a person typed it, in token units, or canonical base units. */
export type AmountInput = { entered: string } | { baseUnits: bigint };

/** Both forms of one amount, and the decimals they are at, as Rust answered. */
export interface AmountForms {
  baseUnits: bigint;
  displayAmount: string;
  decimals: number;
}

/** `wallet.amount`: the amount in both forms. A refusal is Rust's, in its words. */
export async function walletAmount(unit: AmountUnit, amount: AmountInput): Promise<AmountForms> {
  const req = new pb.WalletAmountRequest({
    unit: 'tokenId' in unit
      ? { case: 'tokenId', value: unit.tokenId }
      : { case: 'decimals', value: unit.decimals },
    amount: 'entered' in amount
      ? { case: 'entered', value: amount.entered }
      : { case: 'baseUnits', value: amount.baseUnits },
  });
  const arg = new pb.ArgPack({ codec: pb.Codec.PROTO, body: new Uint8Array(req.toBinary()) });
  const env = decodeFramedEnvelopeV3(await routerQueryBin('wallet.amount', new Uint8Array(arg.toBinary())));
  if (env.payload.case === 'error') {
    throw new Error(env.payload.value.message || `wallet.amount: error code ${env.payload.value.code}`);
  }
  if (env.payload.case !== 'walletAmountResponse') {
    throw new Error(`wallet.amount: the SDK answered ${String(env.payload.case)}, not walletAmountResponse`);
  }
  const res = env.payload.value;
  if (res.displayAmount.length === 0) {
    throw new Error('STRICT: wallet.amount answered without its rendered amount');
  }
  return { baseUnits: res.baseUnits, displayAmount: res.displayAmount, decimals: res.decimals };
}
