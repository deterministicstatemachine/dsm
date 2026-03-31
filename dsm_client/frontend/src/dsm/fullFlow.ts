import { ContactQrV3 } from "../proto/dsm_app_pb";
import type { ContactAddEvent, ContactAddFailure, ContactAddProgress, ContactAddSuccess, DsmEventListener } from "./types";
import { callBin } from "./WebViewBridge";
import { decodeBase32Crockford } from "../utils/textId";

type StartAddContactOptions = {
  qr: string | Uint8Array;
};

type FlowController = {
  onUpdate: (listener: DsmEventListener) => () => void;
  cancel: () => void;
};

const emit = (listener: DsmEventListener, event: ContactAddEvent) => {
  try {
    listener(event);
  } catch {
    // best-effort
  }
};

const decodeBase32CrockfordToBytes = (s: string): Uint8Array => {
  // QR payloads use Base32-Crockford for human transport.
  // Protocol calls remain bytes-only.
  return decodeBase32Crockford(s.trim());
};

const parseQrToProto = (qr: string | Uint8Array): ContactQrV3 => {
  // Prefer protobuf binary; if a string is provided it is usually either:
  //  - base32 Crockford of ContactQrV3 bytes, OR
  //  - a native-scanner payload like: dsm:contact/v3:<base32>
  const buf = (() => {
    if (typeof qr !== "string") return qr;
    const s = qr.trim();
    // Native scanner may return a URI-ish prefix.
    const prefix = "dsm:contact/v3:";
    const payload = s.startsWith(prefix) ? s.slice(prefix.length) : s;
    return decodeBase32CrockfordToBytes(payload);
  })();
  return ContactQrV3.fromBinary(buf);
};

export const startAddContactFlow = (opts: StartAddContactOptions): FlowController => {
  let cancelled = false;
  const listeners = new Set<DsmEventListener>();

  const notify = (e: ContactAddEvent) => listeners.forEach((l) => emit(l, e));

  // Step 1: parse QR
  let qrMsg: ContactQrV3;
  try {
    qrMsg = parseQrToProto(opts.qr);
    notify({ kind: "contact:add:progress", step: "qr:parsed" } as ContactAddProgress);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    notify({ kind: "contact:add:failure", error: `QR parse failed: ${msg}` } as ContactAddFailure);
    return {
      onUpdate: (l: DsmEventListener) => {
        // immediately deliver failure to new listener
        emit(l, { kind: "contact:add:failure", error: "QR parse failed" } as ContactAddFailure);
        return () => {};
      },
      cancel: () => {
        cancelled = true;
      },
    };
  }

  // Step 2: QR validated (genesis verification happens on the network side)
  notify({ kind: "contact:add:progress", step: "qr:validated" } as ContactAddProgress);

  // If we're not in a browser (SSR/unit), fail fast with a clear error
  if (typeof window === 'undefined') {
    notify({ kind: "contact:add:failure", error: "DsmBridge not available (no window)" } as ContactAddFailure);
    return {
      onUpdate: (l: DsmEventListener) => {
        emit(l, { kind: "contact:add:failure", error: "DsmBridge not available (no window)" } as ContactAddFailure);
        return () => {};
      },
      cancel: () => {
        cancelled = true;
      },
    };
  }

  // Step 3: wire dsm-event listener to surface progress back to UI
  const domListener = (ev: Event) => {
    if (cancelled) return;
  const ce = ev as CustomEvent<unknown>;
  const detail: Record<string, unknown> = (ce?.detail && typeof ce.detail === 'object') ? (ce.detail as Record<string, unknown>) : {};
    // Pass through raw events so UI can decide
    listeners.forEach((l) => {
      try {
        l(detail);
      } catch {}
    });

    // Opportunistically map to our typed events when possible
    const t = (detail?.type ?? "") as string;
    if (t.includes("contact") && t.includes("verified")) {
  const payload = (detail?.payload && typeof detail.payload === 'object') ? detail.payload as Record<string, unknown> : {};
      const success: ContactAddSuccess = {
        kind: "contact:add:success",
        deviceId: (payload?.deviceIdBase32 as string) || undefined,
        verifyingNodes: (payload?.verifyingNodes as string[]) || undefined,
        genesisHashBase32: (payload?.genesisHashBase32 as string) || undefined,
      };
      notify(success);
    } else if (t.includes("contact") && t.includes("error")) {
      const error: ContactAddFailure = { kind: "contact:add:failure", error: String(detail?.error || "Unknown error"), info: detail };
      notify(error);
    } else if (t.includes("contact") && t.includes("verifying")) {
      notify({ kind: "contact:add:progress", step: "storage:verifying", info: detail } as ContactAddProgress);
    }
  };
  window.addEventListener("dsm-event", domListener as EventListener);

  // Step 4: send bridge request (async, but keep API sync)
  void (async () => {
    try {
      // Always send protobuf binary. Base32 is UI/debug-only (events/QR), not transport.
      const payloadBytes = qrMsg.toBinary();

      notify({ kind: "contact:add:progress", step: "bridge:request_sent" } as ContactAddProgress);

      // Single-path bridge call.
      // Android expects raw ContactQrV3 bytes for `handleContactQrV3`.
      await callBin('handleContactQrV3', payloadBytes);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      notify({ kind: "contact:add:failure", error: `Bridge send failed: ${msg}` } as ContactAddFailure);
    }
  })();

  return {
    onUpdate: (listener: DsmEventListener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    cancel: () => {
      cancelled = true;
      try {
        window.removeEventListener("dsm-event", domListener as EventListener);
      } catch {}
      listeners.clear();
    },
  };
};
