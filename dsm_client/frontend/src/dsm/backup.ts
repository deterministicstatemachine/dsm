// SPDX-License-Identifier: MIT OR Apache-2.0

// When the wallet backs up, and the backup taken by hand (owner, 2026-11-24).
// The mode is Rust's setting (`wallet_backup_flow::BACKUP_MODE`), read and
// written through Rust's own preferences, never the page's: Rust reads it to
// decide whether to back up after a transaction. A wallet set to back up by
// hand presses Back up on the send screen; Rust takes and writes the backup
// and answers in the words the screen shows.
import * as pb from '../proto/dsm_app_pb';
import { routerInvokeBin, routerQueryBin } from './WebViewBridge';
import { decodeFramedEnvelopeV3 } from './decoding';
import type { BackupMode } from '../runtime/appRuntimeStore';

/** Rust's setting naming when the wallet backs up. */
const BACKUP_MODE = 'wallet_backup_mode';

function argPack(key: string, value?: string): Uint8Array {
  return new Uint8Array(new pb.ArgPack({
    codec: pb.Codec.PROTO,
    body: new Uint8Array(new pb.AppStateRequest({ key, value }).toBinary()),
  }).toBinary());
}

/** The value an `AppStateResponse` answer carries; `undefined` when unset. */
function answered(bytes: Uint8Array, route: string): string | undefined {
  const env = decodeFramedEnvelopeV3(bytes);
  if (env.payload.case === 'error') throw new Error(env.payload.value.message);
  if (env.payload.case !== 'appStateResponse') {
    throw new Error(`${route}: expected appStateResponse, got ${env.payload.case}`);
  }
  return env.payload.value.value;
}

/** When this wallet backs up, as Rust holds it: unset is after every transaction. */
export async function getBackupMode(): Promise<BackupMode> {
  return answered(await routerQueryBin('prefs.get', argPack(BACKUP_MODE)), 'prefs.get') === 'manual'
    ? 'manual'
    : 'auto';
}

/** Set when this wallet backs up. */
export async function putBackupMode(mode: BackupMode): Promise<void> {
  answered(await routerInvokeBin('prefs.set', argPack(BACKUP_MODE, mode)), 'prefs.set');
}

/** Back the wallet up now; what came of it, in words. */
export async function backUpNow(): Promise<string> {
  const words = answered(await routerInvokeBin('wallet.backupNow', argPack(BACKUP_MODE)), 'wallet.backupNow');
  if (words === undefined) throw new Error('wallet.backupNow answered nothing');
  return words;
}
