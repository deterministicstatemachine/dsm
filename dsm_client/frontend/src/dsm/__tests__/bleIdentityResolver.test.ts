// SPDX-License-Identifier: Apache-2.0
import { encodeBase32Crockford32 as base32CrockfordEncode32 } from '../../utils/textId';
// Tests for dynamic BLE identity mapping / resolveBleAddressForContact
import { dsmClient } from '../index';
const enc = new TextEncoder();

// Helper to wrap response in DSM_BRIDGE format with BridgeRpcResponse
function createDsmBridgeSuccessResponse(data: Uint8Array): Uint8Array {
  return (global as any).createDsmBridgeSuccessResponse(data);
}

function mkBytes(seed: number): Uint8Array {
  const b = new Uint8Array(32);
  for (let i = 0; i < 32; i++) b[i] = (seed + i) & 0xff;
  return b;
}

describe('resolveBleAddressForContact', () => {
  beforeEach(() => {
    (globalThis as any).window = (globalThis as any).window || {};
  });

  it('returns undefined when no mapping or stored address', async () => {
    (globalThis as any).window.DsmBridge = {
      __binary: true,
      __callBin: async () => createDsmBridgeSuccessResponse(new Uint8Array(0)),
    };
    const contact = { alias: 'A', deviceId: mkBytes(1), genesisHash: mkBytes(2) };
    await expect(dsmClient.resolveBleAddressForContact?.(contact as any)).resolves.toBeUndefined();
  });

  it('uses stored ble_address directly', async () => {
    (globalThis as any).window.DsmBridge = {
      __binary: true,
      __callBin: async () => new Uint8Array(0),
    };
    const contact = { alias: 'B', deviceId: mkBytes(3), genesisHash: mkBytes(4), bleAddress: '11:22:33:44:55:66' };
    await expect(dsmClient.resolveBleAddressForContact?.(contact as any)).resolves.toBe('11:22:33:44:55:66');
  });

  it('resolves via native lookup when no stored ble_address', async () => {
    const devId = mkBytes(10);
    const genesis = mkBytes(11);
    const address = 'AA:BB:CC:DD:EE:FF';
    (globalThis as any).window.DsmBridge = {
      __binary: true,
      __callBin: async (_reqBytes: Uint8Array) => {
        return createDsmBridgeSuccessResponse(new Uint8Array(Array.from(enc.encode(address))));
      },
    };

    const contact = { alias: 'Peer', deviceId: devId, genesisHash: genesis };
    const resolved = await dsmClient.resolveBleAddressForContact?.(contact as any);
    expect(resolved).toBe(address);

    // Snapshot should surface mapping (in-memory only)
    const devHex = base32CrockfordEncode32(devId);
    const ghHex = base32CrockfordEncode32(genesis);
    const snap = dsmClient.getBleIdentitySnapshot?.();
    expect(snap?.deviceIds?.[devHex]).toBe(address);
    expect(snap?.genesis?.[ghHex]).toBe(address);
  });

  it('resolves via native lookup when device_id is Base32 string', async () => {
    const devId = mkBytes(12);
    const genesis = mkBytes(13);
    const devIdB32 = base32CrockfordEncode32(devId);
    const genesisB32 = base32CrockfordEncode32(genesis);
    const address = 'AB:CD:EF:12:34:56';

    (globalThis as any).window.DsmBridge = {
      __binary: true,
      __callBin: async (reqBytes: Uint8Array) => {
        const pb = require('../../proto/dsm_app_pb');
        const req = pb.BridgeRpcRequest.fromBinary(reqBytes);
        const method = req.method || '';
        const payload = req.payload?.case === 'bytes' ? req.payload.value.data : new Uint8Array(0);
        if (method === 'resolveBleAddressForDeviceId') {
          if (payload.length === devId.length && payload.every((b: number, i: number) => b === devId[i])) {
            return createDsmBridgeSuccessResponse(new Uint8Array(Array.from(enc.encode(address))));
          }
        }
        return createDsmBridgeSuccessResponse(new Uint8Array(0));
      },
    };

    const contact = { alias: 'PeerB32', deviceId: devIdB32, genesisHash: genesisB32 };
    const resolved = await dsmClient.resolveBleAddressForContact?.(contact as any);
    expect(resolved).toBe(address);

    const snap = dsmClient.getBleIdentitySnapshot?.();
    expect(snap?.deviceIds?.[devIdB32]).toBe(address);
    expect(snap?.genesis?.[genesisB32]).toBe(address);
  });

  it('clears cached identities via clearBleIdentityCache', async () => {
    // Precondition: ensure at least one mapping exists (reuse previous test logic)
    const devId = mkBytes(20);
    const genesis = mkBytes(21);
    const address = 'AA:11:22:33:44:55';
    (globalThis as any).window.DsmBridge = {
      __binary: true,
      __callBin: async (reqBytes: Uint8Array) => {
        const pb = require('../../proto/dsm_app_pb');
        const req = pb.BridgeRpcRequest.fromBinary(reqBytes);
        const method = req.method || '';
        const payload = req.payload?.case === 'bytes' ? req.payload.value.data : new Uint8Array(0);
        if (method === 'resolveBleAddressForDeviceId') {
          if (payload.length === devId.length && payload.every((b, i) => b === devId[i])) {
            return createDsmBridgeSuccessResponse(new Uint8Array(enc.encode(address)));
          }
        }
        return createDsmBridgeSuccessResponse(new Uint8Array(0));
      },
    };
    const contact = { alias: 'Peer2', deviceId: devId, genesisHash: genesis };
    const resolved = await dsmClient.resolveBleAddressForContact?.(contact as any);
    expect(resolved).toBe(address);
    // Clear cache
    dsmClient.clearBleIdentityCache?.();
    // Snapshot empty
    const snap = dsmClient.getBleIdentitySnapshot?.();
    expect(Object.keys(snap?.deviceIds || {}).length).toBe(0);
    expect(Object.keys(snap?.genesis || {}).length).toBe(0);

    // Native mapping still resolves and repopulates cache on demand.
    const resolvedAgain = await dsmClient.resolveBleAddressForContact?.(contact as any);
    expect(resolvedAgain).toBe(address);
  });
});
