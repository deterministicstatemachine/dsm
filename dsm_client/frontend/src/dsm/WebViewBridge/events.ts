// SPDX-License-Identifier: Apache-2.0
// UI-only listeners for the binary 'dsm-event-bin' channel.

import { normalizeToBytes } from "./transportCore";
import { log } from "./log";

export type DsmEvent = { topic: string; payload: Uint8Array };

export function addDsmEventListener(fn: (evt: DsmEvent) => void): () => void {
  const handler = (evt: Event) => {
    try {
      const detail = (evt as CustomEvent).detail as
        | { topic?: unknown; payload?: unknown }
        | undefined;
      const topic: string | undefined =
        typeof detail?.topic === "string" ? detail.topic : undefined;
      const payloadRaw = detail?.payload;
      if (!topic) return;
      const payload = normalizeToBytes(payloadRaw ?? new Uint8Array(0));
      fn({ topic, payload });
    } catch (e) {
      log.warn("[WebViewBridge] dsm-event handler threw:", e);
    }
  };

  window.addEventListener("dsm-event-bin", handler as EventListener);
  return () => window.removeEventListener("dsm-event-bin", handler as EventListener);
}
