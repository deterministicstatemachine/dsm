/* eslint-disable @typescript-eslint/no-explicit-any */
import * as pb from '../proto/dsm_app_pb';
import { queryTransportHeadersV3, getDeviceIdBinBridgeAsync, getPreference as getPreferenceBridge, setPreference as setPreferenceBridge } from './WebViewBridge';
import { encodeBase32Crockford } from '../utils/textId';
import { IdentityInfo } from './types';
import logger from '../utils/logger';
import { nativeSessionStore } from '../runtime/nativeSessionStore';

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

export async function getIdentity(): Promise<IdentityInfo | null> {
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
  const retryDelays = [0, 150, 300, 600, 1000, 1500, 2200];
  for (let attempt = 0; attempt < retryDelays.length; attempt++) {
    if (attempt > 0) {
      // Yield to event loop to allow bridge port delivery / gate drain.
      // Also listen for the bridge-ready event so we wake up early if it fires.
      const delay = retryDelays[attempt];
      await new Promise<void>(resolve => {
        let settled = false;
        const settle = () => { if (!settled) { settled = true; resolve(); } };
        const onReady = () => { settle(); };
        if (typeof window !== 'undefined') {
          window.addEventListener('dsm-bridge-ready', onReady, { once: true });
        }
        setTimeout(() => {
          if (typeof window !== 'undefined') {
            window.removeEventListener('dsm-bridge-ready', onReady);
          }
          settle();
        }, delay);
      });
    }
    try {
      const h = await getHeaders();
      return {
        deviceId: encodeBase32Crockford(h.deviceId),
        deviceEntropy: '',
        isRegistered: h.deviceId.length === 32,
        genesisHash: encodeBase32Crockford(h.genesisHash),
        networkId: 'dsm-main',
      };
    } catch (e) {
      logger.warn(`[getIdentity] attempt ${attempt + 1}/${retryDelays.length} failed:`, e);
    }
  }
  return null;
}

export async function getDeviceIdentity(): Promise<string | null> {
  try {
    const deviceIdBytes = await getDeviceIdBinBridgeAsync();
    if (deviceIdBytes.length === 0) return null;
    return encodeBase32Crockford(deviceIdBytes);
  } catch (e) {
    logger.warn('getDeviceIdentity failed:', e);
    return null;
  }
}

export async function getBluetoothStatus(): Promise<{ enabled: boolean; advertising: boolean; scanning: boolean }> {
  const session = nativeSessionStore.getSnapshot();
  return {
    enabled: session.hardware_status.ble.enabled,
    advertising: session.hardware_status.ble.advertising,
    scanning: session.hardware_status.ble.scanning,
  };
}

export function isReady(): Promise<boolean> {
  return getDeviceIdentity().then(id => !!id).catch(() => false);
}

// Preferences (strict bridge)
export async function getPreference(key: string): Promise<string | null> {
  return getPreferenceBridge(String(key));
}

export async function setPreference(key: string, value: string): Promise<void> {
  await setPreferenceBridge(String(key), String(value));
}
