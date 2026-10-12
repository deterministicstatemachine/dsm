// SPDX-License-Identifier: Apache-2.0
// The app lock via the router. Rust is its only authority (sdk::app_lock): it
// enrolls the PIN or pattern, checks every try, counts the misses and decides
// when only the recovery phrase opens it. Each route answers with Rust's
// session snapshot, which is what the app shows.

import {
  ArgPack,
  Codec,
  SessionConfigureLockRequest,
  SessionUnlockRequest,
} from "../../proto/dsm_app_pb";
import { bridgeEvents } from "../../bridge/bridgeEvents";
import { decodeSessionState } from "../sessionState";
import type { NativeSessionLockMethod, NativeSessionReport } from "../../runtime/nativeSessionTypes";
import { routerInvokeBin } from "./transportCore";

function protoArgs(req: { toBinary(): Uint8Array }): Uint8Array {
  return new ArgPack({ codec: Codec.PROTO, body: new Uint8Array(req.toBinary()) }).toBinary();
}

/** Hand Rust's snapshot to the session store, which every screen reads. */
export function applySessionSnapshot(snapshot: NativeSessionReport): void {
  bridgeEvents.emit("session.state", snapshot);
}

export async function lockSessionViaRouter(): Promise<NativeSessionReport> {
  const snapshot = decodeSessionState(await routerInvokeBin("session.lock", new Uint8Array(0)));
  applySessionSnapshot(snapshot);
  return snapshot;
}

/** What the user entered to open the lock. */
export type UnlockKey = { secret: string } | { recoveryPhrase: string };

/**
 * Try to open the lock. Rust checks the key; the answer is its snapshot, still
 * locked after a miss, with the tries left or the phrase required. The caller
 * hands it to the store with {@link applySessionSnapshot} once it has shown
 * the result, so the lock screen can finish showing it before it closes.
 */
export async function tryUnlockViaRouter(key: UnlockKey): Promise<NativeSessionReport> {
  const req = new SessionUnlockRequest({
    key: "secret" in key
      ? { case: "secret", value: key.secret }
      : { case: "recoveryPhrase", value: key.recoveryPhrase },
  });
  return decodeSessionState(await routerInvokeBin("session.unlock", protoArgs(req)));
}

/**
 * Turn the lock on by "pin" or "combo", enrolling `secret` (the PIN, or the
 * pattern's buttons joined by ","), or off by "none". Rust refuses a secret
 * that is not one the method enrolls, and any change while the wallet is
 * locked.
 */
export async function configureLockViaRouter(args: {
  method: NativeSessionLockMethod;
  lockOnPause: boolean;
  secret: string;
}): Promise<NativeSessionReport> {
  const req = new SessionConfigureLockRequest({
    method: args.method,
    lockOnPause: args.lockOnPause,
    secret: args.secret,
  });
  const snapshot = decodeSessionState(await routerInvokeBin("session.configure_lock", protoArgs(req)));
  applySessionSnapshot(snapshot);
  return snapshot;
}
