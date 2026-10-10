// SPDX-License-Identifier: Apache-2.0
// Email receipts (DSM Amendment A17): after a send, the page asks the SDK to
// have the receipt service email one to the person paid. The SDK adds their
// email (from the contact's details), the sender's name and the signature.
// Outside the DSM protocol: a receipt decides nothing.

import * as pb from '../proto/dsm_app_pb';
import { routerInvokeBin } from './WebViewBridge';
import { decodeFramedEnvelopeV3 } from './decoding';
import { decodeBase32Crockford } from '../utils/textId';

export type ReceiptIntent = {
  /** The person paid, by device id (Base32). */
  recipientDeviceId: string;
  token: string;
  amount: string;
  memo: string;
  /** The transfer's hash, Base32. */
  reference: string;
  /** The phone's clock when the send was made, as shown to the person. */
  sentAtLocal: string;
};

/** Emails the receipt; answers where it went, masked (j…@example.com). */
export async function emailReceipt(intent: ReceiptIntent): Promise<string> {
  const req = new pb.ReceiptEmailIntentV1({
    recipientDeviceId: new Uint8Array(decodeBase32Crockford(intent.recipientDeviceId)),
    token: intent.token,
    amount: intent.amount,
    memo: intent.memo,
    reference: intent.reference,
    sentAtLocal: intent.sentAtLocal,
  });
  const pack = new pb.ArgPack({ codec: pb.Codec.PROTO, body: new Uint8Array(req.toBinary()) });
  const env = decodeFramedEnvelopeV3(await routerInvokeBin('receipts.email', pack.toBinary()));
  if (env.payload.case === 'error') {
    throw new Error(env.payload.value.message || `receipts.email failed with code ${env.payload.value.code}`);
  }
  if (env.payload.case !== 'receiptEmailResult') {
    throw new Error(`STRICT: receipts.email answered ${env.payload.case}`);
  }
  return env.payload.value.sentToMasked;
}
