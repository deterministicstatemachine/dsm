/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/services/dlv/b0xService.ts
// SPDX-License-Identifier: Apache-2.0
// b0x computation helpers (base32 inputs -> binary bridge call).

import { decodeBase32Crockford } from '../../utils/textId';
import { computeB0xAddressBridge } from '../../dsm/WebViewBridge';

function decodeB32To32Bytes(value: string, label: string, allowEmpty = false): Uint8Array {
  const trimmed = String(value || '').trim();
  if (!trimmed && allowEmpty) return new Uint8Array(32);
  const bytes = decodeBase32Crockford(trimmed);
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    throw new Error(`${label} must decode to 32 bytes`);
  }
  return bytes;
}

export function computeB0xAddressFromBase32(params: {
  genesisHashB32: string;
  deviceIdB32: string;
  chainTipB32?: string;
}): string {
  const g = decodeB32To32Bytes(params.genesisHashB32, 'genesisHash');
  const d = decodeB32To32Bytes(params.deviceIdB32, 'deviceId');
  const t = decodeB32To32Bytes(params.chainTipB32 || '', 'chainTip', true);
  return computeB0xAddressBridge(g, d, t);
}
