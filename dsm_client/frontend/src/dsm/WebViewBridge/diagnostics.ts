// SPDX-License-Identifier: Apache-2.0
// Diagnostics, architecture info, identity helpers, telemetry exports.

import { ArchitectureInfoProto } from "../../proto/dsm_app_pb";
import { callBin, mustBridge, normalizeToBytes, queryTransportHeadersV3 } from "./transportCore";
import { log } from "./log";

export interface ArchitectureInfo {
  status: "COMPATIBLE" | "UNSUPPORTED_ABI" | "INCOMPATIBLE_JVM" | "UNKNOWN";
  deviceArch: string;
  supportedAbis: string;
  message: string;
  recommendation: string;
}

export async function captureCdbrwOrbitTimings(): Promise<Uint8Array> {
  return callBin("captureCdbrwOrbitTimings", new Uint8Array(0));
}

/** Export persisted bridge diagnostics log (if present). */
export async function getDiagnosticsLogStrict(): Promise<Uint8Array> {
  try {
    const resBytes = await callBin("getDiagnosticsLog", new Uint8Array(0));
    return resBytes instanceof Uint8Array ? resBytes : new Uint8Array(0);
  } catch {
    return new Uint8Array(0);
  }
}

/**
 * Get device architecture compatibility information for diagnostics.
 */
export async function getArchitectureInfo(): Promise<ArchitectureInfo> {
  try {
    const bytes = await callBin("getArchitectureInfo");
    if (!bytes || bytes.length === 0) {
      return {
        status: "UNKNOWN",
        deviceArch: "unavailable",
        supportedAbis: "",
        message: "Architecture info not available (empty response)",
        recommendation: "",
      };
    }
    const parsed = ArchitectureInfoProto.fromBinary(bytes);
    return {
      status: (parsed.status || "UNKNOWN") as ArchitectureInfo["status"],
      deviceArch: parsed.deviceArch || "unknown",
      supportedAbis: parsed.supportedAbis || "",
      message: parsed.message || "Unknown",
      recommendation: parsed.recommendation || "",
    };
  } catch (e) {
    log.warn("Failed to get architecture info from bridge:", e);
    return {
      status: "UNKNOWN",
      deviceArch: "error",
      supportedAbis: "",
      message: "Architecture check error",
      recommendation: "",
    };
  }
}

/** Get the 32-byte device ID via the headers bypass route. */
export async function getDeviceIdBinBridgeAsync(): Promise<Uint8Array> {
  try {
    const headers = await queryTransportHeadersV3();
    const hdr = (await import("../../proto/dsm_app_pb")).Headers.fromBinary(headers);
    const result = hdr.deviceId instanceof Uint8Array ? hdr.deviceId : new Uint8Array(0);
    if (result.length === 0) {
      log.warn("[WebViewBridge] getDeviceIdBin returned empty");
    }
    return result;
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    log.warn("[WebViewBridge] getDeviceIdBin failed:", msg);
    return new Uint8Array(0);
  }
}

/** Get the 64-byte SPHINCS+ signing public key. */
export async function getSigningPublicKeyBinBridgeAsync(): Promise<Uint8Array> {
  try {
    const result = await callBin("getSigningPublicKeyBin", new Uint8Array(0));
    if (result.length === 0) {
      log.warn("[WebViewBridge] getSigningPublicKeyBin returned empty");
    }
    return result;
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    log.warn("[WebViewBridge] getSigningPublicKeyBin failed:", msg);
    return new Uint8Array(0);
  }
}

export function getRouterStatusBridge(): number {
  const b = mustBridge();
  if (typeof b.getAppRouterStatus !== "function") {
    log.warn("[WebViewBridge] getAppRouterStatus not available");
    return -1;
  }
  try {
    const res = b.getAppRouterStatus();
    if (typeof res === "number") return res;
    return -1;
  } catch (e: unknown) {
    log.error("[WebViewBridge] getAppRouterStatus failed:", e);
    return -1;
  }
}

export function computeB0xAddressBridge(
  genesis: Uint8Array,
  deviceId: Uint8Array,
  tip: Uint8Array
): string {
  const b = mustBridge();
  if (typeof b.computeB0xAddress !== "function") {
    log.warn("[WebViewBridge] computeB0xAddress not available");
    return "";
  }
  try {
    const g = normalizeToBytes(genesis);
    const d = normalizeToBytes(deviceId);
    const t = normalizeToBytes(tip);
    if (g.length !== 32 || d.length !== 32 || t.length !== 32) {
      log.warn("[WebViewBridge] computeB0xAddress: inputs must be 32 bytes");
      return "";
    }
    const res = b.computeB0xAddress(g, d, t);
    if (typeof res === "string") return res;
    return "";
  } catch (e: unknown) {
    log.error("[WebViewBridge] computeB0xAddress failed:", e);
    return "";
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function runNativeBridgeSelfTest(): Record<string, any> {
  const b = mustBridge();
  if (typeof b.runNativeBridgeSelfTest !== "function") {
    return { error: "method_missing" };
  }
  try {
    const raw = b.runNativeBridgeSelfTest();
    // STRICT: Do not JSON-parse runtime bridge output. If native returns
    // structured data, it should do so via the binary bridge.
    if (typeof raw === "string") return { raw };
    if (raw && typeof raw === "object") return { raw };
    return { error: "invalid_return_type", rawType: typeof raw };
  } catch (e: unknown) {
    return { error: e instanceof Error ? e.message : "exception" };
  }
}
