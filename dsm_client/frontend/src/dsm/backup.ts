// SPDX-License-Identifier: MIT OR Apache-2.0

// The wallet's backup taken by hand (owner, 2026-11-24): a wallet set to back
// up only when its owner asks presses Back up on the send screen. Rust takes
// and writes the backup and answers in the words the screen shows.
import * as pb from '../proto/dsm_app_pb';
import { routerInvokeBin } from './WebViewBridge';
import { decodeFramedEnvelopeV3 } from './decoding';

/** Back the wallet up now; what came of it, in words. */
export async function backUpNow(): Promise<string> {
  const argPack = new pb.ArgPack({
    codec: pb.Codec.PROTO,
    body: new Uint8Array(new pb.AppStateRequest({ key: 'wallet_backup_mode' }).toBinary()),
  });
  const env = decodeFramedEnvelopeV3(
    await routerInvokeBin('wallet.backupNow', new Uint8Array(argPack.toBinary())),
  );
  if (env.payload.case === 'error') throw new Error(env.payload.value.message);
  if (env.payload.case !== 'appStateResponse') {
    throw new Error(`Expected appStateResponse, got ${env.payload.case}`);
  }
  const words = env.payload.value.value;
  if (words === undefined) throw new Error('wallet.backupNow answered nothing');
  return words;
}
