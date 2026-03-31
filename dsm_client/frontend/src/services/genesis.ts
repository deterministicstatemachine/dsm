// SPDX-License-Identifier: Apache-2.0
// Genesis helpers.
// IMPORTANT: Genesis creation is handled via the bytes-only MessagePort bridge
// (see `src/dsm/WebViewBridge.ts` / `createGenesisBin`).

import { addSecondaryDeviceBin } from '../dsm/WebViewBridge';
import { SecondaryDeviceResponse } from '../proto/dsm_app_pb';

/**
 * Add a secondary device to an existing genesis
 * @param genesisHash - The genesis hash from QR code scan (32 bytes)
 * @param deviceEntropy - New device's entropy (32 bytes)
 * @returns The new device ID bound to the genesis
 */
export async function addSecondaryDevice(args: {
  genesisHash: Uint8Array;      // 32 bytes - scanned from root device QR
  deviceEntropy: Uint8Array;    // 32 bytes - new device entropy
}): Promise<{ deviceId: Uint8Array; genesisHash: Uint8Array }> {
  if (!(args.genesisHash instanceof Uint8Array) || args.genesisHash.length !== 32) {
    throw new Error('DSM: genesisHash must be 32 bytes');
  }
  if (!(args.deviceEntropy instanceof Uint8Array) || args.deviceEntropy.length !== 32) {
    throw new Error('DSM: deviceEntropy must be 32 bytes');
  }

  // Call native bridge with binary data
  const responseBytes = await addSecondaryDeviceBin(args.genesisHash, args.deviceEntropy);

  // Decode SecondaryDeviceResponse from protobuf
  const response = SecondaryDeviceResponse.fromBinary(responseBytes);

  if (!response.success) {
    throw new Error('Secondary device binding failed');
  }

  if (!response.deviceId || response.deviceId.length !== 32) {
    throw new Error('DSM: SecondaryDeviceResponse missing valid deviceId');
  }

  const genesisHash = response.genesisHash?.v || args.genesisHash;
  if (genesisHash.length !== 32) {
    throw new Error('DSM: SecondaryDeviceResponse missing valid genesisHash');
  }

  return { deviceId: response.deviceId, genesisHash };
}