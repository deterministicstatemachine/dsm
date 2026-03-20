/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/dsm/detfi.ts
// SPDX-License-Identifier: Apache-2.0
// DeTFi (Deterministic Token Finance) launch helpers.
// All calls go through the normal AppRouter protobuf envelope path:
//   TypeScript → appRouterInvokeBin → MessagePort → Kotlin → JNI → Rust

import * as pb from '../proto/dsm_app_pb';
import { appRouterInvokeBin } from './WebViewBridge';
import { decodeBase32Crockford } from '../utils/textId';
import { decodeFramedEnvelopeV3 } from './decoding';

/** Header byte meanings for a compiled DeTFi spec blob. */
const DETFI_TYPE_NAMES: Record<number, string> = { 0: 'vault', 1: 'policy' };
const DETFI_MODE_NAMES: Record<number, string> = { 0: 'local', 1: 'posted' };

export type DeTFiHeader = {
  version: number;
  mode: string;
  type: string;
  sizeBytes: number;
};

/**
 * Parse just the 3-byte header of a compiled DeTFi spec blob for UI preview.
 *
 * Header layout:
 *   byte 0 — version (must be 1)
 *   byte 1 — mode    (0 = local, 1 = posted)
 *   byte 2 — type    (0 = vault, 1 = policy)
 */
export function parseDeTFiHeader(blob: string): {
  success: boolean;
  header?: DeTFiHeader;
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
        mode: DETFI_MODE_NAMES[mode],
        type: DETFI_TYPE_NAMES[type],
        sizeBytes: bytes.length,
      },
    };
  } catch (e: any) {
    return { success: false, error: e?.message || 'parseDeTFiHeader failed' };
  }
}

/**
 * Launch a compiled DeTFi spec.
 *
 * @param blob  Base32 Crockford encoding of the compiled DeTFi spec bytes.
 * @returns { success, id?, type?, mode?, error? }
 */
export async function launchDeTFi(blob: string): Promise<{
  success: boolean;
  id?: string;
  type?: string;
  mode?: string;
  error?: string;
}> {
  try {
    const trimmed = typeof blob === 'string' ? blob.trim() : '';
    if (!trimmed) return { success: false, error: 'DeTFi spec blob required' };

    const specBytes = decodeBase32Crockford(trimmed);
    if (!specBytes || specBytes.length === 0) {
      return { success: false, error: 'decoded DeTFi spec bytes empty' };
    }

    // Validate the 3-byte header.
    if (specBytes.length < 3) {
      return { success: false, error: 'DeTFi spec too short (need >= 3 header bytes)' };
    }

    const version = specBytes[0];
    const mode = specBytes[1];
    const type = specBytes[2];

    if (version !== 1) {
      return { success: false, error: `unsupported DeTFi version: ${version} (expected 1)` };
    }
    if (mode !== 0 && mode !== 1) {
      return { success: false, error: `invalid DeTFi mode: ${mode} (expected 0 or 1)` };
    }
    if (type !== 0 && type !== 1) {
      return { success: false, error: `invalid DeTFi type: ${type} (expected 0 or 1)` };
    }

    // Pack the raw spec bytes into an ArgPack for transport.
    const argPack = new pb.ArgPack({
      codec: pb.Codec.PROTO as any,
      body: new Uint8Array(specBytes),
    });

    const resBytes = await appRouterInvokeBin('detfi.launch', new Uint8Array(argPack.toBinary()));
    const env = decodeFramedEnvelopeV3(resBytes);

    if (env.payload.case === 'error') {
      return { success: false, error: env.payload.value.message || 'detfi.launch failed' };
    }

    if (env.payload.case === 'appStateResponse') {
      return {
        success: true,
        id: env.payload.value.value ?? undefined,
        type: DETFI_TYPE_NAMES[type],
        mode: DETFI_MODE_NAMES[mode],
      };
    }

    return {
      success: false,
      error: `Unexpected response payload: ${env.payload.case}`,
    };
  } catch (e: any) {
    return { success: false, error: e?.message || 'launchDeTFi failed' };
  }
}
