/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/services/qr/genesisQrService.ts
// SPDX-License-Identifier: Apache-2.0
// Transport-layer Genesis QR encoding.

import * as pb from '../../proto/dsm_app_pb';
import { decodeBase32Crockford, encodeBase32Crockford as base32CrockfordEncode } from '../../utils/textId';

export function encodeGenesisQrData(genesisHash: Uint8Array): string {
  const genesisBytes = Uint8Array.from(genesisHash);
  const headers = new pb.Headers({ genesisHash: genesisBytes });
  const bytes = headers.toBinary();
  return base32CrockfordEncode(bytes);
}

export function encodeGenesisQrDataFromBase32(genesisHashBase32: string): string {
  const bytes = decodeBase32Crockford(String(genesisHashBase32 || '').trim());
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    throw new Error('genesisHash must decode to 32 bytes');
  }
  return encodeGenesisQrData(bytes);
}
