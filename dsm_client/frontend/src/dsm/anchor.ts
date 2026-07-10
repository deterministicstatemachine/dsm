// SPDX-License-Identifier: MIT OR Apache-2.0

import * as pb from '../proto/dsm_app_pb';
import { routerQueryBin } from './WebViewBridge';
import { decodeFramedEnvelopeV3 } from './decoding';
import { bytesToBase32CrockfordPrefix } from '../utils/textId';
import logger from '../utils/logger';

/**
 * Read-only offline-bearer anchor status for the diagnostics panel (Stage 4 Slice 3, signal c).
 * Pure render data derived from the `anchor.status` route — no protocol logic lives here.
 */
export interface AnchorStatus {
  /** Appliance attached and OP_STATUS read OK. */
  connected: boolean;
  /** Enrolled anchor identity (Crockford base32 prefix); '' when disconnected. */
  anchorIdB32: string;
  /** Resident Ed25519 chip pubkey (σ^chip) prefix; '' when disconnected. */
  pkChipB32: string;
  /** Live counter floor u_i. */
  anchorCounter: bigint;
  /** Current offline frontier h_i (base32 prefix). */
  frontierRootB32: string;
  /** Counter floor at enrollment. */
  enrolledCounter: bigint;
  /** Human-readable status line supplied by Rust. */
  statusText: string;
}

/** Base32-encode a 32-byte field for display, treating an all-zero/empty field as "not present". */
function b32OrEmpty(bytes: Uint8Array | undefined, prefixLen: number): string {
  if (!bytes || bytes.length === 0 || bytes.every((x) => x === 0)) return '';
  return bytesToBase32CrockfordPrefix(bytes, prefixLen);
}

/**
 * Query the sender's anchor appliance status (`anchor.status` route). Read-only diagnostics: the
 * Rust handler never mutates device or appliance state. A disconnected appliance returns a
 * `connected=false` snapshot rather than throwing — that is an expected, renderable state.
 */
export async function getAnchorStatus(): Promise<AnchorStatus> {
  const arg = new pb.ArgPack({ codec: pb.Codec.PROTO, body: new Uint8Array(0) });
  const resBytes = await routerQueryBin('anchor.status', new Uint8Array(arg.toBinary()));
  if (!resBytes || resBytes.length === 0) {
    throw new Error('getAnchorStatus: empty response from bridge');
  }

  const env = decodeFramedEnvelopeV3(resBytes);
  if (env.payload.case === 'error') {
    throw new Error(`getAnchorStatus: ${env.payload.value.message || 'unknown error'}`);
  }
  if (env.payload.case !== 'anchorStatusResponse') {
    throw new Error(`getAnchorStatus: unexpected payload ${env.payload.case}`);
  }

  const resp = env.payload.value;
  if (!resp) {
    throw new Error('getAnchorStatus: anchorStatusResponse payload is null');
  }

  logger.debug('[DSM:getAnchorStatus] snapshot', {
    connected: resp.anchorConnected,
    counter: String(resp.anchorCounter),
  });

  return {
    connected: resp.anchorConnected,
    anchorIdB32: b32OrEmpty(resp.anchorId, 12),
    pkChipB32: b32OrEmpty(resp.pkChip, 12),
    anchorCounter: resp.anchorCounter,
    frontierRootB32: b32OrEmpty(resp.frontierRoot, 12),
    enrolledCounter: resp.enrolledCounter,
    statusText: resp.status,
  };
}
