// SPDX-License-Identifier: Apache-2.0
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-env jest */
/// <reference types="jest" />
export {};
// Declare globals for type-check environments lacking jest types
declare const describe: any; // provided by jest at runtime
declare const it: any; // provided by jest at runtime
declare const expect: any; // provided by jest at runtime
// Tests that resolveBleAddressForContact normalizes MAC addresses.
import { dsmClient } from '../index';

function mkBytes(seed: number): Uint8Array {
  const b = new Uint8Array(32);
  for (let i = 0; i < 32; i++) b[i] = (seed + i) & 0xff;
  return b;
}

describe('BlePairingRequest normalization & mapping', () => {
  it('normalizes lowercase colon MAC', async () => {
    const devId = mkBytes(60);
    const genesis = mkBytes(61);
    const rawAddress = 'aa:bb:cc:dd:ee:ff'; // lower-case; should normalize to upper-case
    (globalThis as any).window = (globalThis as any).window || {};
    (globalThis as any).window.DsmBridge = { __binary: true, __callBin: async () => new Uint8Array(0) };

    const contact = { alias: 'PeerLC', deviceId: devId, genesisHash: genesis, bleAddress: rawAddress };
    const resolved = await dsmClient.resolveBleAddressForContact?.(contact as any);
    expect(resolved).toBe('AA:BB:CC:DD:EE:FF');
  });

  it('normalizes contiguous hex MAC (no alias)', async () => {
    const devId = mkBytes(70);
    const genesis = mkBytes(71);
    const rawAddress = '112233445566'; // contiguous hex
    (globalThis as any).window.DsmBridge = { __binary: true, __callBin: async () => new Uint8Array(0) };

    const contact = { alias: 'PeerHex', deviceId: devId, genesisHash: genesis, bleAddress: rawAddress };
    const resolved = await dsmClient.resolveBleAddressForContact?.(contact as any);
    expect(resolved).toBe('11:22:33:44:55:66');
  });
});
