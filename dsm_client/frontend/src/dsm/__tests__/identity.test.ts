jest.mock('../WebViewBridge', () => ({
  queryTransportHeadersV3: jest.fn(),
  getDeviceIdBinBridgeAsync: jest.fn(),
  getPreference: jest.fn(),
  setPreference: jest.fn(),
}));

jest.mock('../../runtime/nativeSessionStore', () => ({
  nativeSessionStore: {
    getSnapshot: jest.fn(() => ({
      hardware_status: { ble: { enabled: false, advertising: false, scanning: false } },
    })),
  },
}));

import * as pb from '../../proto/dsm_app_pb';
import {
  getHeaders,
  getIdentity,
  getDeviceIdentity,
  getBluetoothStatus,
  isReady,
  getPreference,
  setPreference,
} from '../identity';
import {
  queryTransportHeadersV3,
  getDeviceIdBinBridgeAsync,
  getPreference as getPreferenceBridge,
  setPreference as setPreferenceBridge,
} from '../WebViewBridge';
import { nativeSessionStore } from '../../runtime/nativeSessionStore';
import { encodeBase32Crockford } from '../../utils/textId';

function makeValidDeviceId(): Uint8Array {
  const id = new Uint8Array(32);
  id.fill(0xAB);
  return id;
}

function makeValidGenesisHash(): Uint8Array {
  const gh = new Uint8Array(32);
  gh.fill(0xCD);
  return gh;
}

function makeHeadersBinary(deviceId: Uint8Array, genesisHash: Uint8Array): Uint8Array {
  const headers = new pb.Headers({ deviceId: deviceId as any, genesisHash: genesisHash as any } as any);
  return new Uint8Array(headers.toBinary());
}

describe('identity.ts', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    const g = globalThis as any;
    g.__dsmLastGoodHeaders = { deviceId: undefined, genesisHash: undefined };
  });

  // ── getHeaders ─────────────────────────────────────────────────────

  describe('getHeaders', () => {
    test('returns Headers when bridge provides valid 32-byte fields', async () => {
      const deviceId = makeValidDeviceId();
      const genesisHash = makeValidGenesisHash();
      (queryTransportHeadersV3 as jest.Mock).mockResolvedValue(makeHeadersBinary(deviceId, genesisHash));

      const headers = await getHeaders();
      expect(headers.deviceId).toEqual(deviceId);
      expect(headers.genesisHash).toEqual(genesisHash);
    });

    test('caches valid headers for subsequent calls', async () => {
      const deviceId = makeValidDeviceId();
      const genesisHash = makeValidGenesisHash();
      (queryTransportHeadersV3 as jest.Mock).mockResolvedValue(makeHeadersBinary(deviceId, genesisHash));

      await getHeaders();
      const headers2 = await getHeaders();
      // Second call should use cache, only 1 bridge call total
      expect(queryTransportHeadersV3).toHaveBeenCalledTimes(1);
      expect(headers2.deviceId).toEqual(deviceId);
    });

    test('throws when bridge returns empty bytes', async () => {
      (queryTransportHeadersV3 as jest.Mock).mockResolvedValue(new Uint8Array(0));
      await expect(getHeaders()).rejects.toThrow('DSM bridge identity not ready');
    });

    test('throws when bridge returns all-zero device id', async () => {
      const deviceId = new Uint8Array(32); // all zeros
      const genesisHash = makeValidGenesisHash();
      (queryTransportHeadersV3 as jest.Mock).mockResolvedValue(makeHeadersBinary(deviceId, genesisHash));

      await expect(getHeaders()).rejects.toThrow('DSM bridge identity not ready');
    });

    test('throws when response is too short (<16 bytes)', async () => {
      (queryTransportHeadersV3 as jest.Mock).mockResolvedValue(new Uint8Array(8));
      await expect(getHeaders()).rejects.toThrow('DSM bridge identity not ready');
    });

    test('throws when bridge rejects', async () => {
      (queryTransportHeadersV3 as jest.Mock).mockRejectedValue(new Error('bridge not ready'));
      await expect(getHeaders()).rejects.toThrow('DSM bridge identity not ready');
    });
  });

  // ── getIdentity ────────────────────────────────────────────────────

  describe('getIdentity', () => {
    test('returns identity info on success', async () => {
      const deviceId = makeValidDeviceId();
      const genesisHash = makeValidGenesisHash();
      (queryTransportHeadersV3 as jest.Mock).mockResolvedValue(makeHeadersBinary(deviceId, genesisHash));

      const identity = await getIdentity();
      expect(identity).not.toBeNull();
      expect(identity!.deviceId).toBe(encodeBase32Crockford(deviceId));
      expect(identity!.genesisHash).toBe(encodeBase32Crockford(genesisHash));
      expect(identity!.isRegistered).toBe(true);
      expect(identity!.networkId).toBe('dsm-main');
    });

    test('returns null after all retries fail', async () => {
      (queryTransportHeadersV3 as jest.Mock).mockResolvedValue(new Uint8Array(0));

      const identity = await getIdentity();
      expect(identity).toBeNull();
    }, 30_000);

    test('succeeds on later retry attempt', async () => {
      const deviceId = makeValidDeviceId();
      const genesisHash = makeValidGenesisHash();
      let callCount = 0;
      (queryTransportHeadersV3 as jest.Mock).mockImplementation(async () => {
        callCount++;
        if (callCount < 3) return new Uint8Array(0);
        return makeHeadersBinary(deviceId, genesisHash);
      });

      const identity = await getIdentity();
      expect(identity).not.toBeNull();
      expect(identity!.deviceId).toBe(encodeBase32Crockford(deviceId));
    }, 30_000);
  });

  // ── getDeviceIdentity ──────────────────────────────────────────────

  describe('getDeviceIdentity', () => {
    test('returns base32-encoded device id', async () => {
      const deviceId = makeValidDeviceId();
      (getDeviceIdBinBridgeAsync as jest.Mock).mockResolvedValue(deviceId);

      const result = await getDeviceIdentity();
      expect(result).toBe(encodeBase32Crockford(deviceId));
    });

    test('returns null for empty bytes', async () => {
      (getDeviceIdBinBridgeAsync as jest.Mock).mockResolvedValue(new Uint8Array(0));
      expect(await getDeviceIdentity()).toBeNull();
    });

    test('returns null on bridge error', async () => {
      (getDeviceIdBinBridgeAsync as jest.Mock).mockRejectedValue(new Error('fail'));
      expect(await getDeviceIdentity()).toBeNull();
    });
  });

  // ── getBluetoothStatus ─────────────────────────────────────────────

  describe('getBluetoothStatus', () => {
    test('reads from native session store', async () => {
      (nativeSessionStore.getSnapshot as jest.Mock).mockReturnValue({
        hardware_status: { ble: { enabled: true, advertising: true, scanning: false } },
      });

      const status = await getBluetoothStatus();
      expect(status).toEqual({ enabled: true, advertising: true, scanning: false });
    });
  });

  // ── isReady ────────────────────────────────────────────────────────

  describe('isReady', () => {
    test('returns true when device identity exists', async () => {
      (getDeviceIdBinBridgeAsync as jest.Mock).mockResolvedValue(makeValidDeviceId());
      expect(await isReady()).toBe(true);
    });

    test('returns false when device identity is empty', async () => {
      (getDeviceIdBinBridgeAsync as jest.Mock).mockResolvedValue(new Uint8Array(0));
      expect(await isReady()).toBe(false);
    });

    test('returns false on error', async () => {
      (getDeviceIdBinBridgeAsync as jest.Mock).mockRejectedValue(new Error('nope'));
      expect(await isReady()).toBe(false);
    });
  });

  // ── Preferences ────────────────────────────────────────────────────

  describe('getPreference', () => {
    test('delegates to bridge', async () => {
      (getPreferenceBridge as jest.Mock).mockResolvedValue('dark');
      expect(await getPreference('theme')).toBe('dark');
      expect(getPreferenceBridge).toHaveBeenCalledWith('theme');
    });
  });

  describe('setPreference', () => {
    test('delegates to bridge', async () => {
      (setPreferenceBridge as jest.Mock).mockResolvedValue(undefined);
      await setPreference('theme', 'dark');
      expect(setPreferenceBridge).toHaveBeenCalledWith('theme', 'dark');
    });
  });
});
