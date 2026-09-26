// SPDX-License-Identifier: MIT OR Apache-2.0

jest.mock('../WebViewBridge', () => ({
  queryTransportHeadersV3: jest.fn(),
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
  getPreference,
  setPreference,
  isIdentityUnavailable,
} from '../identity';
import {
  queryTransportHeadersV3,
  getPreference as getPreferenceBridge,
  setPreference as setPreferenceBridge,
} from '../WebViewBridge';
import { nativeSessionStore } from '../../runtime/nativeSessionStore';
import { bridgeEvents } from '../../bridge/bridgeEvents';
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

      // Exactly what the headers carry: nothing the frontend made up beside it.
      expect(await getIdentity()).toEqual({
        deviceId: encodeBase32Crockford(deviceId),
        genesisHash: encodeBase32Crockford(genesisHash),
      });
    });

    /** The native session as Rust reported it, beside the store's hardware fields. */
    function session(state: { received: boolean; identity_status: string }) {
      (nativeSessionStore.getSnapshot as jest.Mock).mockReturnValue({
        ...state,
        hardware_status: { ble: { enabled: false, advertising: false, scanning: false } },
      });
    }

    // The three answers that used to be one null.
    test('with no session state and no readable headers, the answer is runtime-not-ready after the window', async () => {
      session({ received: false, identity_status: 'runtime_not_ready' });
      (queryTransportHeadersV3 as jest.Mock).mockResolvedValue(new Uint8Array(0));

      const failure = await getIdentity().catch((e) => e);
      expect(isIdentityUnavailable(failure)).toBe(true);
      expect(failure.state).toBe('runtime_not_ready');
      expect(failure.message).toMatch(/no session state received/);
      expect(failure.message).toMatch(/DSM bridge identity not ready/);
    }, 30_000);

    test('a missing identity is answered as missing at once, without the retry window', async () => {
      session({ received: true, identity_status: 'missing' });
      (queryTransportHeadersV3 as jest.Mock).mockResolvedValue(new Uint8Array(0));

      const started = Date.now();
      const failure = await getIdentity().catch((e) => e);
      expect(isIdentityUnavailable(failure)).toBe(true);
      expect(failure.state).toBe('missing');
      expect(Date.now() - started).toBeLessThan(1000);
      expect(queryTransportHeadersV3).not.toHaveBeenCalled();
    });

    // The wait between attempts ends early on Rust's `identity.ready`, on the
    // bus. It used to listen on `window` for an event dispatched on
    // `document`, and never woke.
    test('the wait wakes early on identity.ready from the bus', async () => {
      jest.useFakeTimers();
      try {
        session({ received: true, identity_status: 'ready' });
        const deviceId = makeValidDeviceId();
        const genesisHash = makeValidGenesisHash();
        (queryTransportHeadersV3 as jest.Mock)
          .mockResolvedValueOnce(new Uint8Array(0))
          .mockResolvedValueOnce(makeHeadersBinary(deviceId, genesisHash));

        const pending = getIdentity();
        // The first attempt fails and the wait begins; the announcement ends it.
        // No timer is advanced: only the wake can end the wait.
        for (let i = 0; i < 20; i++) {
          bridgeEvents.emit('identity.ready', undefined as never);
          await Promise.resolve();
        }
        const identity = await pending;
        expect(identity.deviceId).toBe(encodeBase32Crockford(deviceId));
        expect(queryTransportHeadersV3).toHaveBeenCalledTimes(2);
      } finally {
        jest.useRealTimers();
      }
    });

    test('a ready session whose headers never read is answered as not read, with the reason', async () => {
      session({ received: true, identity_status: 'ready' });
      (queryTransportHeadersV3 as jest.Mock).mockRejectedValue(new Error('port closed'));

      const failure = await getIdentity().catch((e) => e);
      expect(isIdentityUnavailable(failure)).toBe(true);
      expect(failure.state).toBe('read_failed');
      expect(failure.message).toMatch(/reports it ready/);
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
      expect(identity.deviceId).toBe(encodeBase32Crockford(deviceId));
    }, 30_000);
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
