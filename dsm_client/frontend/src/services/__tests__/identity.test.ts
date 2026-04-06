/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

const mockQueryTransportHeadersV3 = jest.fn();
jest.mock('../../dsm/WebViewBridge', () => ({
  queryTransportHeadersV3: (...args: any[]) => mockQueryTransportHeadersV3(...args),
}));

const mockFromBinary = jest.fn();
jest.mock('../../proto/dsm_app_pb', () => ({
  Headers: { fromBinary: (...args: any[]) => mockFromBinary(...args) },
}));

jest.mock('../../config/network', () => ({
  getNetworkId: () => 'dsm-local',
}));

jest.mock('../../utils/textId', () => ({
  bytesToBase32CrockfordPrefix: jest.fn(() => 'PREVIEW_B32'),
}));

import { IdentityService, bridgeReady } from '../identity';

beforeEach(() => {
  mockQueryTransportHeadersV3.mockReset();
  mockFromBinary.mockReset();
  delete (globalThis as any).DsmBridge;
  jest.spyOn(console, 'warn').mockImplementation(() => {});
});

afterEach(() => {
  jest.restoreAllMocks();
});

describe('bridgeReady', () => {
  it('returns false when DsmBridge is absent', () => {
    expect(bridgeReady()).toBe(false);
  });

  it('returns true when __binary + sendMessageBin present', () => {
    (globalThis as any).DsmBridge = {
      __binary: true,
      sendMessageBin: jest.fn(),
    };
    expect(bridgeReady()).toBe(true);
  });

  it('returns true when __callBin present', () => {
    (globalThis as any).DsmBridge = { __callBin: jest.fn() };
    expect(bridgeReady()).toBe(true);
  });

  it('returns false when DsmBridge has no known methods', () => {
    (globalThis as any).DsmBridge = { somethingElse: true };
    expect(bridgeReady()).toBe(false);
  });
});

describe('IdentityService', () => {
  let svc: IdentityService;

  beforeEach(() => {
    svc = new IdentityService();
    (globalThis as any).DsmBridge = {
      __binary: true,
      sendMessageBin: jest.fn(),
    };
  });

  describe('hasIdentity', () => {
    it('returns false when bridge is not ready', async () => {
      delete (globalThis as any).DsmBridge;
      expect(await svc.hasIdentity()).toBe(false);
    });

    it('returns false when headers are empty', async () => {
      mockQueryTransportHeadersV3.mockResolvedValue(null);
      expect(await svc.hasIdentity()).toBe(false);
    });

    it('returns true when genesis hash has non-zero bytes', async () => {
      const genesisHash = new Uint8Array(32);
      genesisHash[0] = 0xFF;
      mockQueryTransportHeadersV3.mockResolvedValue(new Uint8Array([1, 2, 3]));
      mockFromBinary.mockReturnValue({ genesisHash });

      expect(await svc.hasIdentity()).toBe(true);
    });

    it('returns false when genesis hash is all zeros', async () => {
      mockQueryTransportHeadersV3.mockResolvedValue(new Uint8Array([1, 2, 3]));
      mockFromBinary.mockReturnValue({ genesisHash: new Uint8Array(32) });

      // Falls through to appStateGet which checks has_identity flag
      expect(await svc.hasIdentity()).toBe(false);
    });

    it('returns false when genesis hash is wrong length', async () => {
      mockQueryTransportHeadersV3.mockResolvedValue(new Uint8Array([1, 2, 3]));
      mockFromBinary.mockReturnValue({ genesisHash: new Uint8Array(16) });

      expect(await svc.hasIdentity()).toBe(false);
    });

    it('returns false when Headers.fromBinary throws', async () => {
      mockQueryTransportHeadersV3.mockResolvedValue(new Uint8Array([1, 2, 3]));
      mockFromBinary.mockImplementation(() => { throw new Error('bad proto'); });

      expect(await svc.hasIdentity()).toBe(false);
    });

    it('checks appStateGet flag when genesis hash is all-zero', async () => {
      (globalThis as any).DsmBridge.getAppStateString = jest.fn(() => 'true');
      mockQueryTransportHeadersV3.mockResolvedValue(new Uint8Array([1, 2, 3]));
      mockFromBinary.mockReturnValue({ genesisHash: new Uint8Array(32) });

      expect(await svc.hasIdentity()).toBe(true);
    });

    it('returns false when appStateGet returns non-truthy', async () => {
      (globalThis as any).DsmBridge.getAppStateString = jest.fn(() => 'false');
      mockQueryTransportHeadersV3.mockResolvedValue(new Uint8Array([1, 2, 3]));
      mockFromBinary.mockReturnValue({ genesisHash: new Uint8Array(32) });

      expect(await svc.hasIdentity()).toBe(false);
    });
  });

  describe('getIdentityInfo', () => {
    it('throws when bridge is not ready', async () => {
      delete (globalThis as any).DsmBridge;
      await expect(svc.getIdentityInfo()).rejects.toThrow('DSM bridge not ready');
    });

    it('returns identity info from headers', async () => {
      const deviceId = new Uint8Array(32).fill(0x01);
      const chainTip = new Uint8Array(32).fill(0x02);
      const genesisHash = new Uint8Array(32).fill(0x03);

      mockQueryTransportHeadersV3.mockResolvedValue(new Uint8Array([1, 2, 3]));
      mockFromBinary.mockReturnValue({ deviceId, chainTip, genesisHash });

      const info = await svc.getIdentityInfo();

      expect(info.deviceId).toEqual(deviceId);
      expect(info.chainTip).toEqual(chainTip);
      expect(info.genesisHash).toEqual(genesisHash);
      expect(info.networkId).toBe('dsm-local');
      expect(typeof info.locale).toBe('string');
    });

    it('returns defaults when headers are missing', async () => {
      mockQueryTransportHeadersV3.mockResolvedValue(new Uint8Array([1, 2, 3]));
      mockFromBinary.mockReturnValue({});

      const info = await svc.getIdentityInfo();

      expect(info.deviceId).toEqual(new Uint8Array(32));
      expect(info.chainTip).toEqual(new Uint8Array(32));
      expect(info.genesisHash).toBeUndefined();
    });

    it('returns default info when transport throws', async () => {
      mockQueryTransportHeadersV3.mockRejectedValue(new Error('transport fail'));

      const info = await svc.getIdentityInfo();

      expect(info.deviceId).toEqual(new Uint8Array(32));
      expect(info.chainTip).toEqual(new Uint8Array(32));
      expect(info.genesisHash).toBeUndefined();
      expect(info.networkId).toBe('dsm-local');
    });

    it('returns default info when fromBinary throws', async () => {
      mockQueryTransportHeadersV3.mockResolvedValue(new Uint8Array([1, 2, 3]));
      mockFromBinary.mockImplementation(() => { throw new Error('bad proto'); });

      const info = await svc.getIdentityInfo();

      expect(info.deviceId).toEqual(new Uint8Array(32));
      expect(info.genesisHash).toBeUndefined();
    });

    it('ignores genesisHash with wrong length', async () => {
      mockQueryTransportHeadersV3.mockResolvedValue(new Uint8Array([1]));
      mockFromBinary.mockReturnValue({
        deviceId: new Uint8Array(32),
        chainTip: new Uint8Array(32),
        genesisHash: new Uint8Array(16),
      });

      const info = await svc.getIdentityInfo();

      expect(info.genesisHash).toBeUndefined();
    });
  });
});
