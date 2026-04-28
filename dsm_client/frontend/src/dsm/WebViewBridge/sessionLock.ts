// SPDX-License-Identifier: Apache-2.0
// Session lock/unlock + lock configuration via the router.

import { ArgPack, Codec, SessionConfigureLockRequest } from "../../proto/dsm_app_pb";
import { routerInvokeBin } from "./transportCore";

export async function lockSessionViaRouter(): Promise<void> {
  await routerInvokeBin("session.lock", new Uint8Array(0));
}

export async function unlockSessionViaRouter(): Promise<void> {
  await routerInvokeBin("session.unlock", new Uint8Array(0));
}

export async function configureLockViaRouter(args: {
  enabled: boolean;
  method: "pin" | "combo" | "biometric";
  lockOnPause: boolean;
}): Promise<void> {
  const req = new SessionConfigureLockRequest({
    enabled: args.enabled,
    method: args.method,
    lockOnPause: args.lockOnPause,
  });
  const argPack = new ArgPack({
    codec: Codec.PROTO,
    body: new Uint8Array(req.toBinary()),
  });
  await routerInvokeBin("session.configure_lock", argPack.toBinary());
}
