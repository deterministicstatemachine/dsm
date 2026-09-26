// SPDX-License-Identifier: MIT OR Apache-2.0

/* eslint-disable @typescript-eslint/no-explicit-any */
import * as pb from '../proto/dsm_app_pb';
import { queryTransportHeadersV3, getPreference as getPreferenceBridge, setPreference as setPreferenceBridge } from './WebViewBridge';
import { encodeBase32Crockford } from '../utils/textId';
import { IdentityInfo } from './types';
import logger from '../utils/logger';
import { nativeSessionStore } from '../runtime/nativeSessionStore';
import { bridgeEvents } from '../bridge/bridgeEvents';
import { IdentityUnavailableError } from './identityUnavailable';

// Cache the last known-good identity to avoid flip-flops.
const g: any = globalThis as any;
if (!g.__dsmLastGoodHeaders) {
  g.__dsmLastGoodHeaders = { deviceId: undefined as Uint8Array | undefined, genesisHash: undefined as Uint8Array | undefined };
}

export async function getHeaders(): Promise<pb.Headers> {
  const isAllZero = (u: Uint8Array) => u.every((v) => v === 0);

  const readFromBridge = async (): Promise<{ deviceId?: Uint8Array; genesisHash?: Uint8Array }> => {
    try {
      const bin = await queryTransportHeadersV3();
      const size = bin?.length ?? 0;
      if (size > 0) {
        if (size < 16) {
          logger.warn(`[readFromBridge] Response too short (${size} bytes); treating as not-ready`);
          return { deviceId: undefined, genesisHash: undefined };
        }
        
        const h = pb.Headers.fromBinary(bin);
        return {
          deviceId: h.deviceId,
          genesisHash: h.genesisHash,
        };
      }
      return { deviceId: undefined, genesisHash: undefined };
    } catch (e) {
      logger.warn('[getHeaders] readFromBridge decode error:', e);
      throw e;
    }
  };

  const cached = g.__dsmLastGoodHeaders as { deviceId?: Uint8Array; genesisHash?: Uint8Array };
  const cachedDevOk = cached.deviceId instanceof Uint8Array && cached.deviceId.length === 32 && !isAllZero(cached.deviceId);
  const cachedGhOk = cached.genesisHash instanceof Uint8Array && cached.genesisHash.length === 32 && !isAllZero(cached.genesisHash);
  
  if (cachedDevOk && cachedGhOk) {
    return new pb.Headers({ deviceId: cached.deviceId as any, genesisHash: cached.genesisHash as any } as any);
  }

  let lastSeen: { deviceId?: Uint8Array; genesisHash?: Uint8Array } = {};

  try {
    lastSeen = await readFromBridge();
  } catch {
    lastSeen = {};
  }

  const devOk = lastSeen.deviceId instanceof Uint8Array && lastSeen.deviceId.length === 32 && !isAllZero(lastSeen.deviceId);
  const ghOk = lastSeen.genesisHash instanceof Uint8Array && lastSeen.genesisHash.length === 32 && !isAllZero(lastSeen.genesisHash);

  if (devOk && ghOk) {
    cached.deviceId = lastSeen.deviceId;
    cached.genesisHash = lastSeen.genesisHash;
    return new pb.Headers({
      deviceId: lastSeen.deviceId as any,
      genesisHash: lastSeen.genesisHash as any,
    } as any);
  }

  throw new Error('DSM bridge identity not ready');
}

export { IdentityUnavailableError, isIdentityUnavailable } from './identityUnavailable';
export type { IdentityUnavailableState } from './identityUnavailable';

export async function getIdentity(): Promise<IdentityInfo> {
  // Retry with increasing yields to handle the cold-start race where React
  // mounts before the Android MessagePort is delivered. The port arrival fires
  // 'dsm-bridge-ready' but loadWalletData may already be in-flight by then.
  // Use a broader bounded window for slower devices (e.g., Samsung A54) where
  // bridge transport can be ready before headers become immediately readable.
  // This remains deterministic and bounded.
  //
  // Two distinct failure modes during cold start:
  //   "DSM binary bridge not ready"  — MessagePort not yet delivered from Android. Keep retrying.
  //   "DSM bridge identity not ready" — Bridge is up but SDK hasn't finished loading genesis
  //     from SQLite yet (common on slower devices). Keep retrying through the full window.
  // Do NOT fast-exit on "identity not ready" — genesis may already exist in the DB but the
  // SDK initialization is still in-flight. Let the full delay window play out.
  //
  // The one fast exit is Rust's own word: a native session reporting the
  // identity `missing` means there is nothing to wait for, and it is answered
  // as missing at once rather than as the same null a failed read produced.
  const retryDelays = [0, 150, 300, 600, 1000, 1500, 2200];
  let lastFailure: unknown = null;
  for (let attempt = 0; attempt < retryDelays.length; attempt++) {
    if (attempt > 0) {
      // Yield to event loop to allow bridge port delivery / gate drain, and
      // wake early on Rust's `identity.ready` — on the bus, where the event
      // bridge puts it; it used to be listened for on `window` after being
      // dispatched on `document`, and never woke anything.
      const delay = retryDelays[attempt];
      await new Promise<void>(resolve => {
        let settled = false;
        const offReady = bridgeEvents.on('identity.ready', () => settle());
        const settle = () => {
          if (settled) return;
          settled = true;
          offReady();
          resolve();
        };
        setTimeout(settle, delay);
      });
    }
    const session = nativeSessionStore.getSnapshot();
    if (session.received && session.identity_status === 'missing') {
      throw new IdentityUnavailableError('missing', 'no identity on this device (native session: missing)');
    }
    try {
      const h = await getHeaders();
      return {
        deviceId: encodeBase32Crockford(h.deviceId),
        genesisHash: encodeBase32Crockford(h.genesisHash),
      };
    } catch (e) {
      lastFailure = e;
      logger.warn(`[getIdentity] attempt ${attempt + 1}/${retryDelays.length} failed:`, e);
    }
  }
  const waited = retryDelays.reduce((a, b) => a + b, 0);
  const reason = lastFailure instanceof Error ? lastFailure.message : String(lastFailure);
  const session = nativeSessionStore.getSnapshot();
  if (!session.received || session.identity_status !== 'ready') {
    throw new IdentityUnavailableError(
      'runtime_not_ready',
      `native session not ready after ${waited} ms (${session.received ? session.identity_status : 'no session state received'}); last read: ${reason}`,
    );
  }
  throw new IdentityUnavailableError(
    'read_failed',
    `identity not read although the native session reports it ready: ${reason}`,
  );
}

// Preferences (strict bridge)
export async function getPreference(key: string): Promise<string | null> {
  return getPreferenceBridge(String(key));
}

export async function setPreference(key: string, value: string): Promise<void> {
  await setPreferenceBridge(String(key), String(value));
}
