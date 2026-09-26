// SPDX-License-Identifier: Apache-2.0
// BLE-related bridge calls the screens make: permissions, Bluetooth settings,
// the pairing loop, and the peer relationship read. When the radio advertises
// and scans is native policy; nothing here starts or stops it.

import { bridgeGate } from "../BridgeGate";
import { callBin } from "./transportCore";
import { log } from "./log";

export async function requestBlePermissions(): Promise<void> {
  await callBin("requestBlePermissions", new Uint8Array(0));
}

export async function openBluetoothSettings(): Promise<void> {
  await callBin("openBluetoothSettings", new Uint8Array(0));
}

/**
 * Start the Rust-driven pairing orchestrator loop. Status updates arrive via
 * the 'ble.pairingStatus' bridgeEvents topic.
 */
export async function startPairingAll(): Promise<void> {
  try {
    await callBin("startPairingAll", new Uint8Array(0));
  } catch (e) {
    log.warn("[BLE] startPairingAll failed:", e);
  }
}

export async function stopPairingAll(): Promise<void> {
  try {
    await callBin("stopPairingAll", new Uint8Array(0));
  } catch (e) {
    log.warn("[BLE] stopPairingAll failed:", e);
  }
}

export async function resolveBleAddressForDeviceIdBridge(
  deviceId: Uint8Array
): Promise<string | undefined> {
  const bytes = deviceId instanceof Uint8Array ? deviceId : new Uint8Array(0);
  if (bytes.length !== 32) return undefined;
  const resp = await callBin("resolveBleAddressForDeviceId", bytes);
  if (!resp || resp.length === 0) return undefined;
  const s = new TextDecoder().decode(resp).trim();
  return s || undefined;
}

export async function readPeerRelationshipStatusBridge(bleAddress: string): Promise<Uint8Array> {
  const normalized = String(bleAddress ?? "").trim();
  if (!normalized) return new Uint8Array(0);
  return bridgeGate.enqueue(() =>
    callBin("readPeerRelationshipStatus", new TextEncoder().encode(normalized))
  );
}
