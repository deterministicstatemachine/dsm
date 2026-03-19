/* eslint-disable @typescript-eslint/no-explicit-any */
import { encodeBase32Crockford, decodeBase32Crockford } from '../utils/textId';
import { bridgeEvents } from '../bridge/bridgeEvents';
import { resolveBleAddressForDeviceIdBridge } from './WebViewBridge';



// BLE identity mapping cache
const bleIdentityMap = {
  byDeviceId: new Map<string, string>(),
  byGenesis: new Map<string, string>(),
};

function base32Key32(bytes: Uint8Array): string {
  return encodeBase32Crockford(bytes);
}

export function normalizeBleAddress(input: string): string | undefined {
  if (typeof input !== 'string') return undefined;
  const s = input.trim();
  if (!s) return undefined;
  // Already a colon-separated 6-byte form.
  // eslint-disable-next-line security/detect-unsafe-regex
  if (/^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/.test(s)) {
    return s.toUpperCase();
  }
  // Contiguous 12-hex form.
  if (/^[0-9a-fA-F]{12}$/.test(s)) {
    const parts: string[] = [];
    for (let i = 0; i < 12; i += 2) parts.push(s.slice(i, i + 2));
    return parts.join(':').toUpperCase();
  }
  return undefined;
}

export function persistBleMapping(args: {
  bleAddress: string;
  deviceId?: Uint8Array;
  genesisHash?: Uint8Array;
  deviceIdStr?: string;
  genesisHashStr?: string;
}): void {
  const norm = normalizeBleAddress(args.bleAddress);
  if (!norm) return;
  const dev = args.deviceId instanceof Uint8Array && args.deviceId.length ? args.deviceId : undefined;
  const gen = args.genesisHash instanceof Uint8Array && args.genesisHash.length ? args.genesisHash : undefined;

  let devKey: string | undefined = args.deviceIdStr && String(args.deviceIdStr);
  let genKey: string | undefined = args.genesisHashStr && String(args.genesisHashStr);
  if (!devKey && dev) {
    devKey = base32Key32(dev);
  }
  if (!genKey && gen) {
    genKey = base32Key32(gen);
  }
  if (devKey) {
    bleIdentityMap.byDeviceId.set(String(devKey), norm);
  }
  if (genKey) {
    bleIdentityMap.byGenesis.set(String(genKey), norm);
  }

  // Emit deterministic mapping event for UI (Base32 Crockford only).
  try {
    bridgeEvents.emit('contact.bleMapped', {
      address: norm,
      deviceId: devKey,
      genesisHash: genKey,
    });
  } catch {}
}

export function loadPersistedBleMappings(): void {
  // No-op: BLE address persistence is native.
}

export function clearBleIdentityCache(): void {
  bleIdentityMap.byDeviceId.clear();
  bleIdentityMap.byGenesis.clear();
}

export function getBleIdentitySnapshot(): { deviceIds: Record<string, string>; genesis: Record<string, string> } {
  const deviceIds: Record<string, string> = {};
  const genesis: Record<string, string> = {};
  for (const [k, v] of bleIdentityMap.byDeviceId.entries()) deviceIds[k] = v;
  for (const [k, v] of bleIdentityMap.byGenesis.entries()) genesis[k] = v;
  return { deviceIds, genesis };
}

export function pruneBleIdentityMappings(args: { deviceIds?: Uint8Array[]; genesisHashes?: Uint8Array[] }): void {
  const devKeys = (args.deviceIds || []).filter((b) => b instanceof Uint8Array).map((b) => base32Key32(b));
  const genKeys = (args.genesisHashes || []).filter((b) => b instanceof Uint8Array).map((b) => base32Key32(b));
  for (const k of devKeys) {
    bleIdentityMap.byDeviceId.delete(k);
  }
  for (const k of genKeys) {
    bleIdentityMap.byGenesis.delete(k);
  }
}

// Strict version: single deterministic resolution path
export async function resolveBleAddressForContact(contact: any): Promise<string | undefined> {
  if (!contact) return undefined;

  const deviceField = contact.deviceId;
  const genesisField = contact.genesisHash;

  // 1) Stored directly on contact
  const rawAddr = contact.bleAddress;
  
  const direct = normalizeBleAddress(String(rawAddr || ''));
  if (direct) {
    persistBleMapping({
      bleAddress: direct,
      deviceId: deviceField instanceof Uint8Array ? deviceField : undefined,
      genesisHash: genesisField instanceof Uint8Array ? genesisField : undefined,
      deviceIdStr: typeof deviceField === 'string' ? deviceField : undefined,
      genesisHashStr: typeof genesisField === 'string' ? genesisField : undefined,
    });
    return direct;
  }

  // 2) Resolve via Bridge
  const devBytes: Uint8Array | undefined = (() => {
    if (deviceField instanceof Uint8Array) return deviceField;
    if (typeof deviceField === 'string') {
      try {
        return decodeBase32Crockford(deviceField);
      } catch {
        return undefined;
      }
    }
    return undefined;
  })();

  if (!devBytes || devBytes.length !== 32) return undefined;

  const cached = bleIdentityMap.byDeviceId.get(base32Key32(devBytes));
  if (cached) return cached;

  const nativeAddr = await resolveBleAddressForDeviceIdBridge(devBytes);
  const norm = normalizeBleAddress(String(nativeAddr || ''));
  if (norm) {
    persistBleMapping({
      bleAddress: norm,
      deviceId: devBytes,
      genesisHash: genesisField instanceof Uint8Array ? genesisField : undefined,
      genesisHashStr: typeof genesisField === 'string' ? genesisField : undefined,
    });
    return norm;
  }
  return undefined;
}

export function subscribeBleEvents(callback: (event: any) => void): () => void {
  const unsubs: Array<() => void> = [];

  unsubs.push(bridgeEvents.on('ble.deviceFound', (d) => {
    try { callback({ type: 'deviceFound', ...d }); } catch {}
  }));
  unsubs.push(bridgeEvents.on('ble.deviceConnected', (d) => {
    try { callback({ type: 'deviceConnected', ...d }); } catch {}
  }));
  unsubs.push(bridgeEvents.on('ble.deviceDisconnected', (d) => {
    try { callback({ type: 'deviceDisconnected', ...d }); } catch {}
  }));

  return () => {
    for (const u of unsubs) {
      try { u(); } catch {}
    }
  };
}
