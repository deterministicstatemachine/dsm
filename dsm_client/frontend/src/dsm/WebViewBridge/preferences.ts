// SPDX-License-Identifier: Apache-2.0
// Persisted preference get/set via the native bridge.

import { bridgeGate } from "../BridgeGate";
import { PreferencePayload } from "../../proto/dsm_app_pb";
import { callBin } from "./transportCore";
import { log } from "./log";

export async function getPreference(key: string): Promise<string | null> {
  return bridgeGate.enqueue(async () => {
    try {
      const req = new PreferencePayload({ key: String(key) });
      const res = await callBin("getPreference", req.toBinary());
      if (!res || res.length === 0) return null;
      return new TextDecoder().decode(res);
    } catch (e) {
      log.warn("getPreference failed", e);
      return null;
    }
  });
}

export async function setPreference(key: string, value: string): Promise<void> {
  await bridgeGate.enqueue(async () => {
    try {
      const req = new PreferencePayload({
        key: String(key),
        value: String(value ?? ""),
      });
      await callBin("setPreference", req.toBinary());
    } catch (e) {
      log.warn("setPreference failed", e);
    }
  });
}
