/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/dsm/sofi.ts
// SPDX-License-Identifier: Apache-2.0
// SoFi (Deterministic Token Finance) launch helpers.
// All calls go through the normal AppRouter protobuf envelope path:
//   TypeScript → routerInvokeBin → MessagePort → Kotlin → JNI → Rust

import * as pb from '../proto/dsm_app_pb';
import { routerInvokeBin } from './WebViewBridge';
import { decodeBase32Crockford } from '../utils/textId';
import { decodeFramedEnvelopeV3 } from './decoding';

/** Header byte meanings for a compiled SoFi spec blob. */
const SOFI_TYPE_NAMES: Record<number, string> = { 0: 'vault', 1: 'policy' };
const SOFI_MODE_NAMES: Record<number, string> = { 0: 'local', 1: 'posted' };

export type SoFiHeader = {
  version: number;
  mode: string;
  type: string;
  sizeBytes: number;
};

/**
 * Parse just the 3-byte header of a compiled SoFi spec blob for UI preview.
 *
 * Header layout:
 *   byte 0 — version (must be 1)
 *   byte 1 — mode    (0 = local, 1 = posted)
 *   byte 2 — type    (0 = vault, 1 = policy)
 */
export function parseSoFiHeader(blob: string): {
  success: boolean;
  header?: SoFiHeader;
  error?: string;
} {
  try {
    const trimmed = typeof blob === 'string' ? blob.trim() : '';
    if (!trimmed) return { success: false, error: 'blob is empty' };

    const bytes = decodeBase32Crockford(trimmed);
    if (!bytes || bytes.length < 3) {
      return { success: false, error: 'decoded blob too short (need >= 3 header bytes)' };
    }

    const version = bytes[0];
    const mode = bytes[1];
    const type = bytes[2];

    if (version !== 1) {
      return { success: false, error: `unsupported version: ${version} (expected 1)` };
    }
    if (mode !== 0 && mode !== 1) {
      return { success: false, error: `invalid mode: ${mode} (expected 0 or 1)` };
    }
    if (type !== 0 && type !== 1) {
      return { success: false, error: `invalid type: ${type} (expected 0 or 1)` };
    }

    return {
      success: true,
      header: {
        version,
        mode: SOFI_MODE_NAMES[mode],
        type: SOFI_TYPE_NAMES[type],
        sizeBytes: bytes.length,
      },
    };
  } catch (e: any) {
    return { success: false, error: e?.message || 'parseSoFiHeader failed' };
  }
}

/**
 * Launch a compiled SoFi spec.
 *
 * @param blob  Base32 Crockford encoding of the compiled SoFi spec bytes.
 * @returns { success, id?, type?, mode?, error? }
 */
export async function launchSoFi(blob: string): Promise<{
  success: boolean;
  id?: string;
  type?: string;
  mode?: string;
  error?: string;
}> {
  try {
    const trimmed = typeof blob === 'string' ? blob.trim() : '';
    if (!trimmed) return { success: false, error: 'SoFi spec blob required' };

    const specBytes = decodeBase32Crockford(trimmed);
    if (!specBytes || specBytes.length === 0) {
      return { success: false, error: 'decoded SoFi spec bytes empty' };
    }

    // Validate the 3-byte header.
    if (specBytes.length < 3) {
      return { success: false, error: 'SoFi spec too short (need >= 3 header bytes)' };
    }

    const version = specBytes[0];
    const mode = specBytes[1];
    const type = specBytes[2];

    if (version !== 1) {
      return { success: false, error: `unsupported SoFi version: ${version} (expected 1)` };
    }
    if (mode !== 0 && mode !== 1) {
      return { success: false, error: `invalid SoFi mode: ${mode} (expected 0 or 1)` };
    }
    if (type !== 0 && type !== 1) {
      return { success: false, error: `invalid SoFi type: ${type} (expected 0 or 1)` };
    }

    // Pack the raw spec bytes into an ArgPack for transport.
    const argPack = new pb.ArgPack({
      codec: pb.Codec.PROTO as any,
      body: new Uint8Array(specBytes),
    });

    const resBytes = await routerInvokeBin('sofi.launch', new Uint8Array(argPack.toBinary()));
    const env = decodeFramedEnvelopeV3(resBytes);

    if (env.payload.case === 'error') {
      return { success: false, error: env.payload.value.message || 'sofi.launch failed' };
    }

    if (env.payload.case === 'appStateResponse') {
      return {
        success: true,
        id: env.payload.value.value ?? undefined,
        type: SOFI_TYPE_NAMES[type],
        mode: SOFI_MODE_NAMES[mode],
      };
    }

    return {
      success: false,
      error: `Unexpected response payload: ${env.payload.case}`,
    };
  } catch (e: any) {
    return { success: false, error: e?.message || 'launchSoFi failed' };
  }
}
