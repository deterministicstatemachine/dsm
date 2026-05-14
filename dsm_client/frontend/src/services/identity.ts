/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/services/identityService.ts
/**
 * SPDX-License-Identifier: Apache-2.0
 * Identity service (protobuf-only). No JSON, no clocks.
 */

import * as pb from '../proto/dsm_app_pb';
import { queryTransportHeadersV3 } from '../dsm/WebViewBridge';
import { getNetworkId } from '../config/network';
import { bytesToBase32CrockfordPrefix } from '../utils/textId';

export type IdentityInfo = {
  deviceId: Uint8Array;
  chainTip: Uint8Array;
  genesisHash?: Uint8Array;
  locale: string;
  networkId: string;
};

/**
 * Lightweight gate: true only when WebView bridge is installed.
 * Keep name/export for external callers that rely on it.
 */
export function bridgeReady(): boolean {
  const b: any = (globalThis as any)?.DsmBridge;
  if (!b) return false;

  // Preferred (runtime): bytes-only MessagePort bridge.
  if (b.__binary && typeof b.sendMessageBin === 'function') return true;

  // Test harness surface.
  if (typeof b.__callBin === 'function') return true;

  return false;
}

/** Read a small string flag from native app state (best-effort). */
async function appStateGet(key: string): Promise<string | undefined> {
  try {
    const b: any = (globalThis as any)?.DsmBridge;
    if (b && typeof b.getAppStateString === 'function') {
      const v = b.getAppStateString(key);
      return typeof v === 'string' ? v : undefined;
    }
  } catch {
    // best-effort only
  }
  return undefined;
}


export class IdentityService {
  /** True if device already has a non-zero genesis hash or cached flag. */
  async hasIdentity(): Promise<boolean> {
    if (!bridgeReady()) return false;

    const hdrBytes = await queryTransportHeadersV3();
    if (!hdrBytes?.length) return false;

    // Defensive parsing: when malformed bytes arrive, log a short preview to aid debugging.
    let hdr: any;
    try {
      hdr = pb.Headers.fromBinary(hdrBytes);
    } catch (e) {
      try {
        const preview = bytesToBase32CrockfordPrefix(hdrBytes, 24);
        console.warn('[IdentityService] hasIdentity: failed to parse Headers, preview_b32=', preview, 'len=', hdrBytes.length, 'error=', e);
      } catch (_err) {
        console.warn('[IdentityService] hasIdentity: failed to parse Headers (and failed to create preview)');
      }
      return false;
    }
    const gh = hdr.genesisHash && hdr.genesisHash.length === 32 ? hdr.genesisHash : undefined;

    if (gh) {
      for (let i = 0; i < 32; i++) {
        if (gh[i] !== 0) return true;
      }
    }

    const flag = await appStateGet('has_identity');
    return flag === 'true' || flag === '1';
  }

  /** Return current identity headers + locale/network hint. */
  async getIdentityInfo(): Promise<IdentityInfo> {
    if (!bridgeReady()) throw new Error('DSM bridge not ready');

    try {
      const hdrBytes = await queryTransportHeadersV3();
      let hdr: any;
      try {
        hdr = pb.Headers.fromBinary(hdrBytes);
      } catch (e) {
        try {
          const preview = bytesToBase32CrockfordPrefix(hdrBytes, 24);
          console.warn('[IdentityService] getIdentityInfo: failed to parse Headers, preview_b32=', preview, 'len=', hdrBytes.length, 'error=', e);
        } catch (_err) {
          console.warn('[IdentityService] getIdentityInfo: failed to parse Headers (and failed to create preview)');
        }
        throw e;
      }

      const deviceId = hdr.deviceId ?? new Uint8Array(32);
      const chainTip = hdr.chainTip ?? new Uint8Array(32);
      const genesisHash =
        hdr.genesisHash && hdr.genesisHash.length === 32 ? hdr.genesisHash : undefined;

      const locale =
        typeof navigator !== 'undefined' && (navigator as any).language
          ? (navigator as any).language
          : 'en-US';

      const networkId = getNetworkId();

      return { deviceId, chainTip, genesisHash, locale, networkId };
    } catch (error) {
      // If transport headers are not available (e.g., during genesis creation),
      // return default/empty identity info
      console.warn('[IdentityService] Transport headers not available, returning defaults:', error);
      
      const locale =
        typeof navigator !== 'undefined' && (navigator as any).language
          ? (navigator as any).language
          : 'en-US';

      const networkId = getNetworkId();

      return { 
        deviceId: new Uint8Array(32), 
        chainTip: new Uint8Array(32), 
        genesisHash: undefined, 
        locale, 
        networkId 
      };
    }
  }
}

export const identityService = new IdentityService();
