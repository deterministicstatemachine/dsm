/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/services/genesis/secondaryDeviceSetupService.ts
// SPDX-License-Identifier: Apache-2.0
// Secondary device setup helpers (QR -> add device) isolated from UI.

import { decodeBase32Crockford, encodeBase32Crockford } from '../../utils/textId';
import { addSecondaryDevice } from '../genesis';

function parseGenesisQr(scannedData: string): Uint8Array {
  const input = String(scannedData || '').trim();
  if (!input.startsWith('dsm:genesis:')) {
    throw new Error('Invalid QR code format (expected dsm:genesis prefix)');
  }
  const raw = input.replace(/^dsm:genesis:/, '');
  const genesisHash = decodeBase32Crockford(raw);
  if (!(genesisHash instanceof Uint8Array) || genesisHash.length !== 32) {
    throw new Error('Invalid genesis hash length (must be 32 bytes)');
  }
  return genesisHash;
}

export async function addSecondaryDeviceFromQr(scannedData: string): Promise<{
  deviceIdBase32: string;
  genesisHashBase32: string;
}> {
  const genesisHash = parseGenesisQr(scannedData);

  const deviceEntropy = new Uint8Array(32);
  crypto.getRandomValues(deviceEntropy);

  const result = await addSecondaryDevice({ genesisHash, deviceEntropy });

  return {
    deviceIdBase32: encodeBase32Crockford(result.deviceId),
    genesisHashBase32: encodeBase32Crockford(result.genesisHash),
  };
}
