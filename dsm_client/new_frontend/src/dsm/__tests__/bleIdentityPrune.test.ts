// SPDX-License-Identifier: Apache-2.0
import { encodeBase32Crockford32 as base32CrockfordEncode32 } from '../../utils/textId';
// Tests for selective pruning of BLE identity mappings
import { dsmClient } from '../index';
const enc = new TextEncoder();
// Jest globals declaration (type-only) for TypeScript without importing @types explicitly in test file
declare const describe: any; // provided by Jest environment
declare const it: any; // provided by Jest environment
declare const expect: any; // provided by Jest environment

// Helper to wrap response in DSM_BRIDGE format
function wrapSuccessEnvelope(data: Uint8Array): Uint8Array {
  return (global as any).createDsmBridgeSuccessResponse(data);
}

function mkBytes(seed: number): Uint8Array {
  const b = new Uint8Array(32);
  for (let i = 0; i < 32; i++) b[i] = (seed + i) & 0xff;
  return b;
}

describe('pruneBleIdentityMappings', () => {
  it('removes only specified mappings while preserving others', async () => {
    (globalThis as any).window = (globalThis as any).window || {};
    // three mappings
    const devA = mkBytes(1); const genA = mkBytes(2); const addrA = 'AA:AA:AA:AA:AA:AA';
    const devB = mkBytes(3); const genB = mkBytes(4); const addrB = 'BB:BB:BB:BB:BB:BB';
    const devC = mkBytes(5); const genC = mkBytes(6); const addrC = 'CC:CC:CC:CC:CC:CC';
    const map = new Map<string, string>([
      [base32CrockfordEncode32(devA), addrA],
      [base32CrockfordEncode32(devB), addrB],
      [base32CrockfordEncode32(devC), addrC],
    ]);
    (globalThis as any).window.DsmBridge = {
      __binary: true,
      __callBin: async (reqBytes: Uint8Array) => {
        const pb = require('../../proto/dsm_app_pb');
        const req = pb.BridgeRpcRequest.fromBinary(reqBytes);
        const method = req.method || '';
        const payload = req.payload?.case === 'bytes' ? req.payload.value.data : new Uint8Array(0);
        if (method === 'resolveBleAddressForDeviceId') {
          const key = base32CrockfordEncode32(payload);
          const addr = map.get(key) || '';
          return addr ? wrapSuccessEnvelope(new Uint8Array(enc.encode(addr))) : wrapSuccessEnvelope(new Uint8Array(0));
        }
        return wrapSuccessEnvelope(new Uint8Array(0));
      },
    };

    await dsmClient.resolveBleAddressForContact?.({ deviceId: devA, genesisHash: genA } as any);
    await dsmClient.resolveBleAddressForContact?.({ deviceId: devB, genesisHash: genB } as any);
    await dsmClient.resolveBleAddressForContact?.({ deviceId: devC, genesisHash: genC } as any);

    const devHexA = base32CrockfordEncode32(devA); const devHexB = base32CrockfordEncode32(devB); const devHexC = base32CrockfordEncode32(devC);
    const genHexA = base32CrockfordEncode32(genA); const genHexB = base32CrockfordEncode32(genB); const genHexC = base32CrockfordEncode32(genC);

    // snapshot before prune
    const snapBefore = dsmClient.getBleIdentitySnapshot?.();
    expect(Object.keys(snapBefore?.deviceIds || {}).length).toBeGreaterThanOrEqual(3);
    expect(Object.keys(snapBefore?.genesis || {}).length).toBeGreaterThanOrEqual(3);

    // prune devB and genesis C only (API accepts raw bytes; return value is void)
    dsmClient.pruneBleIdentityMappings?.({ deviceIds: [devB], genesisHashes: [genC] } as any);

    const snapAfter = dsmClient.getBleIdentitySnapshot?.();
    // devA & devC remain; devB removed
    expect(snapAfter?.deviceIds?.[devHexA]).toBe(addrA);
    expect(snapAfter?.deviceIds?.[devHexB]).toBeUndefined();
    expect(snapAfter?.deviceIds?.[devHexC]).toBe(addrC);
    // genesis A & B remain; C removed
    expect(snapAfter?.genesis?.[genHexA]).toBe(addrA);
    expect(snapAfter?.genesis?.[genHexB]).toBe(addrB);
    expect(snapAfter?.genesis?.[genHexC]).toBeUndefined();

    // No localStorage persistence; native mapping is source of truth.
  });
});
