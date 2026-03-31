/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/services/qr/pairingQrService.ts
// SPDX-License-Identifier: Apache-2.0
// Fetch and encode pairing ContactQrV3 URI from router.

import { encodeBase32Crockford as base32CrockfordEncode } from '../../utils/textId';
import { appRouterQueryBin } from '../../dsm/WebViewBridge';

import { decodeFramedEnvelopeV3 } from '../../dsm/decoding';

export async function fetchPairingContactUri(): Promise<string> {
  const resp = await appRouterQueryBin('identity.pairing_qr');

  try {
    const env = decodeFramedEnvelopeV3(resp);
    if (env.payload.case === 'error') {
      throw new Error(`identity.pairing_qr failed: ${env.payload.value.message}`);
    }
    if (env.payload.case !== 'contactQrResponse') {
      throw new Error(`Expected contactQrResponse, got ${env.payload.case}`);
    }
    const qr = env.payload.value;
    
    if (!qr.signingPublicKey || qr.signingPublicKey.byteLength !== 64) {
      throw new Error(`Invalid signing public key size: ${qr.signingPublicKey?.byteLength} (expected 64)`);
    }

    const payload = qr.toBinary();
    const b32 = base32CrockfordEncode(payload);
    return `dsm:contact/v3:${b32}`;
  } catch (e: any) { // eslint-disable-line @typescript-eslint/no-explicit-any
    throw new Error(`identity.pairing_qr failed: ${e.message}`);
  }
}
