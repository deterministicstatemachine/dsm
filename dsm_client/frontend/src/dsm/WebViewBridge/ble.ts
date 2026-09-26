// SPDX-License-Identifier: Apache-2.0
// BLE-related bridge calls the screens make: permissions, Bluetooth settings
// and the pairing loop. When the radio advertises and scans is native policy;
// nothing here starts or stops it.

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

