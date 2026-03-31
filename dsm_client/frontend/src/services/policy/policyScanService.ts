/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/services/policy/policyScanService.ts
// SPDX-License-Identifier: Apache-2.0
// Policy scan/import helper to keep base32 decoding out of UI.

import { decodeBase32Crockford, encodeBase32Crockford } from '../../utils/textId';
import { shortId } from '../../utils/anchorDisplay';
import { dsmClient } from '../dsmClient';

export async function importTokenPolicyFromScanData(scanData: string): Promise<{
  ok: boolean;
  message?: string;
  shortId?: string;
}> {
  try {
    let b32 = String(scanData || '').trim();
    if (b32.startsWith('dsm:policy:')) {
      b32 = b32.slice('dsm:policy:'.length).trim();
    }

    const bytes = decodeBase32Crockford(b32);
    if (!bytes || bytes.length === 0) {
      return { ok: false, message: 'Empty payload' };
    }
    if (bytes.length !== 32) {
      return { ok: false, message: 'This screen only supports importing existing tokens (Anchors). To publish new policies, use the Developer Settings.' };
    }

    const canonicalB32 = encodeBase32Crockford(bytes);
    const res = await dsmClient.importTokenPolicy({ anchorBase32: canonicalB32 });
    if (!res.success) {
      return { ok: false, message: res.error || 'Import failed' };
    }

    return { ok: true, shortId: shortId(bytes) };
  } catch (e: any) {
    return { ok: false, message: e?.message || 'Scan failed' };
  }
}
