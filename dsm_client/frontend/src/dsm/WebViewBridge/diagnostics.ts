// SPDX-License-Identifier: Apache-2.0
// Diagnostics and identity helpers over the native bridge. Each helper answers
// what the bridge answered, or throws with the failure as it happened; nothing
// is answered in a failure's place.

import { ArchitectureInfoProto, Headers } from "../../proto/dsm_app_pb";
import { callBin, queryTransportHeadersV3 } from "./transportCore";

export interface ArchitectureInfo {
  status: "COMPATIBLE" | "UNSUPPORTED_ABI" | "INCOMPATIBLE_JVM";
  deviceArch: string;
  supportedAbis: string;
  message: string;
  recommendation: string;
}

/** The statuses the native checker can measure (`ArchitectureChecker.ArchStatus`). */
const ARCH_STATUSES: ReadonlySet<string> = new Set(["COMPATIBLE", "UNSUPPORTED_ABI", "INCOMPATIBLE_JVM"]);

/** The persisted bridge log (its last ~5 MB) as the native side holds it. */
export async function getDiagnosticsLog(): Promise<Uint8Array> {
  return callBin("getDiagnosticsLog", new Uint8Array(0));
}

/**
 * Has the native side write the debug report (this summary, the app's log,
 * the bridge log) and open the Android share sheet with it. Answers the
 * report's size in bytes. A WebView cannot save a file, so the report is
 * written and shared natively.
 */
export async function shareDiagnosticsReport(summary: string): Promise<number> {
  const bytes = await callBin("shareDiagnosticsReport", new TextEncoder().encode(summary));
  const size = Number(new TextDecoder().decode(bytes));
  if (!Number.isInteger(size) || size <= 0) {
    throw new Error(`shareDiagnosticsReport answered no report size (${bytes.length} bytes)`);
  }
  return size;
}

/**
 * The device's architecture compatibility as the native checker measured it.
 * A check that failed is the bridge's error, not a status.
 */
export async function getArchitectureInfo(): Promise<ArchitectureInfo> {
  const bytes = await callBin("getArchitectureInfo");
  if (bytes.length === 0) {
    throw new Error("getArchitectureInfo answered no bytes");
  }
  const parsed = ArchitectureInfoProto.fromBinary(bytes);
  if (!ARCH_STATUSES.has(parsed.status) || !parsed.deviceArch) {
    throw new Error(
      `STRICT: getArchitectureInfo answered status "${parsed.status}" for device "${parsed.deviceArch}"`,
    );
  }
  return {
    status: parsed.status as ArchitectureInfo["status"],
    deviceArch: parsed.deviceArch,
    supportedAbis: parsed.supportedAbis,
    message: parsed.message,
    recommendation: parsed.recommendation,
  };
}

/** This device's 32-byte id, from Rust's transport headers. */
export async function getDeviceIdBinBridgeAsync(): Promise<Uint8Array> {
  const hdr = Headers.fromBinary(await queryTransportHeadersV3());
  if (hdr.deviceId.length !== 32) {
    throw new Error(`the transport headers carry a ${hdr.deviceId.length}-byte device id`);
  }
  return hdr.deviceId;
}
