// SPDX-License-Identifier: Apache-2.0

const mockFromBinary = jest.fn();

jest.mock('../../proto/dsm_app_pb', () => ({
  Headers: Object.assign(
    jest.fn().mockImplementation((data: Record<string, unknown>) => data),
    { fromBinary: mockFromBinary },
  ),
}));

jest.mock('../../dsm/WebViewBridge', () => ({
  queryTransportHeadersV3: jest.fn(),
}));

jest.mock('../../utils/identity', () => ({
  checkIdentityState: jest.fn(),
}));

import { headerService, TransportHeaders } from '../headerService';
import { queryTransportHeadersV3 } from '../../dsm/WebViewBridge';
import { checkIdentityState } from '../../utils/identity';

const mockQueryHeaders = queryTransportHeadersV3 as jest.Mock;
const mockCheckIdentity = checkIdentityState as jest.Mock;

describe('HeaderService', () => {
  beforeEach(() => {
    headerService.invalidateCache();
    delete (globalThis as Record<string, unknown>).DsmBridge;
  });

  describe('isBridgeAvailable', () => {
    it('returns false when DsmBridge is absent', () => {
      expect(headerService.isBridgeAvailable()).toBe(false);
    });

    it('returns true when DsmBridge.__binary is true', () => {
      (globalThis as Record<string, unknown>).DsmBridge = { __binary: true };
      expect(headerService.isBridgeAvailable()).toBe(true);
    });

    it('returns true when DsmBridge.__callBin is a function', () => {
      (globalThis as Record<string, unknown>).DsmBridge = { __callBin: jest.fn() };
      expect(headerService.isBridgeAvailable()).toBe(true);
    });

    it('returns false when DsmBridge is an empty object', () => {
      (globalThis as Record<string, unknown>).DsmBridge = {};
      expect(headerService.isBridgeAvailable()).toBe(false);
    });
  });

  describe('ensureBridge', () => {
    it('throws when bridge is not available', () => {
      expect(() => headerService.ensureBridge()).toThrow('DSM bridge not available');
    });

    it('does not throw when bridge is available', () => {
      (globalThis as Record<string, unknown>).DsmBridge = { __binary: true };
      expect(() => headerService.ensureBridge()).not.toThrow();
    });
  });

  describe('invalidateCache', () => {
    it('forces next fetchHeaders to re-fetch', async () => {
      const devId = new Uint8Array(32).fill(0x01);
      const chainTip = new Uint8Array(32).fill(0x02);

      mockCheckIdentity.mockResolvedValue('READY');
      mockFromBinary.mockReturnValue({
        deviceId: devId,
        chainTip,
        genesisHash: null,
        seq: 1n,
      });
      mockQueryHeaders.mockResolvedValue(new Uint8Array([1, 2, 3]));

      await headerService.fetchHeaders();
      expect(mockQueryHeaders).toHaveBeenCalledTimes(1);

      // Cached — should not re-fetch
      await headerService.fetchHeaders();
      expect(mockQueryHeaders).toHaveBeenCalledTimes(1);

      // Invalidate — should re-fetch
      headerService.invalidateCache();
      await headerService.fetchHeaders();
      expect(mockQueryHeaders).toHaveBeenCalledTimes(2);
    });
  });

  describe('fetchHeaders', () => {
    const devId = new Uint8Array(32).fill(0xaa);
    const chainTip = new Uint8Array(32).fill(0xbb);
    const genesisHash = new Uint8Array(32).fill(0xcc);

    it('returns transport headers on success', async () => {
      mockCheckIdentity.mockResolvedValue('READY');
      mockFromBinary.mockReturnValue({
        deviceId: devId,
        chainTip,
        genesisHash,
        seq: 42n,
      });
      mockQueryHeaders.mockResolvedValue(new Uint8Array([10, 20]));

      const h = await headerService.fetchHeaders();
      expect(h.deviceId).toEqual(devId);
      expect(h.chainTip).toEqual(chainTip);
      expect(h.genesisHash).toEqual(genesisHash);
      expect(h.seq).toBe('42');
      // Verify it's a clone, not the same reference
      expect(h.deviceId).not.toBe(devId);
    });

    it('sets seq to "0" when proto seq is falsy', async () => {
      mockCheckIdentity.mockResolvedValue('READY');
      mockFromBinary.mockReturnValue({
        deviceId: devId,
        chainTip,
        genesisHash: null,
        seq: 0n,
      });
      mockQueryHeaders.mockResolvedValue(new Uint8Array([1]));

      const h = await headerService.fetchHeaders();
      expect(h.seq).toBe('0');
      expect(h.genesisHash).toBeNull();
    });

    it('throws when identity is not ready', async () => {
      mockCheckIdentity.mockResolvedValue('PENDING');
      await expect(headerService.fetchHeaders()).rejects.toThrow(/identity not ready/);
    });

    it('throws when header bytes are empty', async () => {
      mockCheckIdentity.mockResolvedValue('READY');
      mockQueryHeaders.mockResolvedValue(new Uint8Array(0));
      await expect(headerService.fetchHeaders()).rejects.toThrow(/empty transport headers/);
    });

    it('throws when deviceId is wrong length', async () => {
      mockCheckIdentity.mockResolvedValue('READY');
      mockFromBinary.mockReturnValue({
        deviceId: new Uint8Array(16),
        chainTip,
        genesisHash: null,
        seq: 0n,
      });
      mockQueryHeaders.mockResolvedValue(new Uint8Array([1]));

      await expect(headerService.fetchHeaders()).rejects.toThrow(/invalid deviceId length/);
    });

    it('throws when chainTip is wrong length', async () => {
      mockCheckIdentity.mockResolvedValue('READY');
      mockFromBinary.mockReturnValue({
        deviceId: devId,
        chainTip: new Uint8Array(8),
        genesisHash: null,
        seq: 0n,
      });
      mockQueryHeaders.mockResolvedValue(new Uint8Array([1]));

      await expect(headerService.fetchHeaders()).rejects.toThrow(/invalid chainTip length/);
    });
  });

  describe('createPbHeaders', () => {
    it('constructs proto Headers with all fields', () => {
      const h: TransportHeaders = {
        deviceId: new Uint8Array(32).fill(0xdd),
        chainTip: new Uint8Array(32).fill(0xee),
        genesisHash: new Uint8Array(32).fill(0xff),
        seq: '99',
      };

      const pbH = headerService.createPbHeaders(h);
      expect(pbH).toBeDefined();
      expect((pbH as Record<string, unknown>).seq).toBe(99n);
    });

    it('omits genesisHash when null', () => {
      const h: TransportHeaders = {
        deviceId: new Uint8Array(32).fill(0x11),
        chainTip: new Uint8Array(32).fill(0x22),
        genesisHash: null,
        seq: '0',
      };

      const pbH = headerService.createPbHeaders(h);
      expect((pbH as Record<string, unknown>).genesisHash).toBeUndefined();
    });
  });
});
