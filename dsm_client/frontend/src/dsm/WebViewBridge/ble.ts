// SPDX-License-Identifier: Apache-2.0
// BLE-related transport: pairing orchestrator, advertising, scanning, identity
// injection, and bilateral offline send.

import { bridgeGate } from "../BridgeGate";
import { BleIdentityPayload } from "../../proto/dsm_app_pb";
import {
  startBleAdvertisingHost,
  startBleScanHost,
  stopBleAdvertisingHost,
  stopBleScanHost,
} from "../NativeHostBridge";
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

export async function startBleScanViaRouter(): Promise<void> {
  await startBleScanHost();
}

export async function stopBleScanViaRouter(): Promise<void> {
  await stopBleScanHost();
}

export async function startBleAdvertisingViaRouter(): Promise<{
  success: boolean;
  error?: { message?: string };
}> {
  try {
    const ack = await startBleAdvertisingHost();
    return { success: Boolean(ack.success) };
  } catch (e) {
    return {
      success: false,
      error: { message: e instanceof Error ? e.message : "device.ble.advertise.start failed" },
    };
  }
}

export async function stopBleAdvertisingViaRouter(): Promise<{
  success: boolean;
  error?: { message?: string };
}> {
  try {
    const ack = await stopBleAdvertisingHost();
    return { success: Boolean(ack.success) };
  } catch (e) {
    return {
      success: false,
      error: { message: e instanceof Error ? e.message : "device.ble.advertise.stop failed" },
    };
  }
}

/**
 * Inject genesis + device_id into native BLE layer to enable advertising after
 * genesis creation.
 */
export async function setBleIdentityForAdvertising(
  genesisHash: Uint8Array,
  deviceId: Uint8Array
): Promise<void> {
  if (genesisHash.length !== 32) {
    throw new Error("setBleIdentityForAdvertising: genesis_hash must be 32 bytes");
  }
  if (deviceId.length !== 32) {
    throw new Error("setBleIdentityForAdvertising: device_id must be 32 bytes");
  }

  const req = new BleIdentityPayload({
    genesisHash: new Uint8Array(genesisHash),
    deviceId: new Uint8Array(deviceId),
  });

  await bridgeGate.enqueue(() => callBin("setBleIdentityForAdvertising", req.toBinary()));
}
