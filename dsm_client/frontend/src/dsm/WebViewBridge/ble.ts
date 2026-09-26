// SPDX-License-Identifier: Apache-2.0
// BLE-related bridge calls the screens make: permissions and Bluetooth
// settings. When the radio advertises and scans, and when pairing runs, is
// native policy; nothing here starts or stops either.

import { callBin } from "./transportCore";

export async function requestBlePermissions(): Promise<void> {
  await callBin("requestBlePermissions", new Uint8Array(0));
}

export async function openBluetoothSettings(): Promise<void> {
  await callBin("openBluetoothSettings", new Uint8Array(0));
}

