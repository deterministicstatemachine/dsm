// SPDX-License-Identifier: Apache-2.0
import { encodeBase32Crockford } from '../../utils/textId';

jest.mock('../../bridge/bridgeEvents', () => ({
  bridgeEvents: { emit: jest.fn(), on: jest.fn(() => jest.fn()) },
}));
jest.mock('../WebViewBridge', () => ({
  resolveBleAddressForDeviceIdBridge: jest.fn(),
}));

import {
  normalizeBleAddress,
  persistBleMapping,
  clearBleIdentityCache,
  getBleIdentitySnapshot,
  pruneBleIdentityMappings,
} from '../resolution';

describe('normalizeBleAddress', () => {
  it('returns uppercase colon-separated form for valid colon address', () => {
    expect(normalizeBleAddress('aa:bb:cc:dd:ee:ff')).toBe('AA:BB:CC:DD:EE:FF');
  });

  it('passes through already-uppercase colon address', () => {
    expect(normalizeBleAddress('11:22:33:44:55:66')).toBe('11:22:33:44:55:66');
  });

  it('converts contiguous 12-hex to colon-separated uppercase', () => {
    expect(normalizeBleAddress('aabbccddeeff')).toBe('AA:BB:CC:DD:EE:FF');
  });

  it('handles uppercase contiguous hex', () => {
    expect(normalizeBleAddress('AABBCCDDEEFF')).toBe('AA:BB:CC:DD:EE:FF');
  });

  it('handles mixed-case contiguous hex', () => {
    expect(normalizeBleAddress('aAbBcCdDeEfF')).toBe('AA:BB:CC:DD:EE:FF');
  });

  it('returns undefined for empty string', () => {
    expect(normalizeBleAddress('')).toBeUndefined();
  });

  it('returns undefined for whitespace-only string', () => {
    expect(normalizeBleAddress('   ')).toBeUndefined();
  });

  it('returns undefined for non-string input', () => {
    expect(normalizeBleAddress(123 as unknown as string)).toBeUndefined();
  });

  it('returns undefined for too-short hex', () => {
    expect(normalizeBleAddress('aabbcc')).toBeUndefined();
  });

  it('returns undefined for too-long hex', () => {
    expect(normalizeBleAddress('aabbccddeeff00')).toBeUndefined();
  });

  it('returns undefined for partial colon format', () => {
    expect(normalizeBleAddress('AA:BB:CC')).toBeUndefined();
  });

  it('returns undefined for invalid hex characters', () => {
    expect(normalizeBleAddress('GG:HH:II:JJ:KK:LL')).toBeUndefined();
  });

  it('trims leading/trailing whitespace', () => {
    expect(normalizeBleAddress('  aa:bb:cc:dd:ee:ff  ')).toBe('AA:BB:CC:DD:EE:FF');
  });

  it('returns undefined for colon format with wrong byte count', () => {
    expect(normalizeBleAddress('AA:BB:CC:DD:EE')).toBeUndefined();
  });

  it('returns undefined for colon format with extra byte', () => {
    expect(normalizeBleAddress('AA:BB:CC:DD:EE:FF:00')).toBeUndefined();
  });
});

describe('BLE identity cache operations', () => {
  beforeEach(() => {
    clearBleIdentityCache();
  });

  it('starts with an empty snapshot', () => {
    const snap = getBleIdentitySnapshot();
    expect(snap.deviceIds).toEqual({});
    expect(snap.genesis).toEqual({});
  });

  it('persistBleMapping stores deviceId mapping', () => {
    const devId = new Uint8Array(32).fill(0x01);
    persistBleMapping({ bleAddress: 'AA:BB:CC:DD:EE:FF', deviceId: devId });
    const snap = getBleIdentitySnapshot();
    const key = encodeBase32Crockford(devId);
    expect(snap.deviceIds[key]).toBe('AA:BB:CC:DD:EE:FF');
  });

  it('persistBleMapping stores genesisHash mapping', () => {
    const gen = new Uint8Array(32).fill(0x02);
    persistBleMapping({ bleAddress: 'aabbccddeeff', genesisHash: gen });
    const snap = getBleIdentitySnapshot();
    const key = encodeBase32Crockford(gen);
    expect(snap.genesis[key]).toBe('AA:BB:CC:DD:EE:FF');
  });

  it('persistBleMapping accepts string deviceIdStr', () => {
    persistBleMapping({ bleAddress: '11:22:33:44:55:66', deviceIdStr: 'MYDEVICE' });
    const snap = getBleIdentitySnapshot();
    expect(snap.deviceIds['MYDEVICE']).toBe('11:22:33:44:55:66');
  });

  it('persistBleMapping ignores invalid bleAddress', () => {
    const devId = new Uint8Array(32).fill(0x03);
    persistBleMapping({ bleAddress: 'invalid', deviceId: devId });
    const snap = getBleIdentitySnapshot();
    expect(Object.keys(snap.deviceIds).length).toBe(0);
  });

  it('persistBleMapping ignores empty Uint8Array deviceId', () => {
    persistBleMapping({ bleAddress: 'AA:BB:CC:DD:EE:FF', deviceId: new Uint8Array(0) });
    const snap = getBleIdentitySnapshot();
    expect(Object.keys(snap.deviceIds).length).toBe(0);
  });

  it('clearBleIdentityCache empties both maps', () => {
    const devId = new Uint8Array(32).fill(0x04);
    const gen = new Uint8Array(32).fill(0x05);
    persistBleMapping({ bleAddress: 'AA:BB:CC:DD:EE:FF', deviceId: devId, genesisHash: gen });
    expect(Object.keys(getBleIdentitySnapshot().deviceIds).length).toBe(1);

    clearBleIdentityCache();
    const snap = getBleIdentitySnapshot();
    expect(snap.deviceIds).toEqual({});
    expect(snap.genesis).toEqual({});
  });

  it('pruneBleIdentityMappings removes specified deviceIds', () => {
    const devA = new Uint8Array(32).fill(0x0a);
    const devB = new Uint8Array(32).fill(0x0b);
    persistBleMapping({ bleAddress: 'AA:BB:CC:DD:EE:01', deviceId: devA });
    persistBleMapping({ bleAddress: 'AA:BB:CC:DD:EE:02', deviceId: devB });
    expect(Object.keys(getBleIdentitySnapshot().deviceIds).length).toBe(2);

    pruneBleIdentityMappings({ deviceIds: [devA] });
    const snap = getBleIdentitySnapshot();
    expect(Object.keys(snap.deviceIds).length).toBe(1);
    expect(snap.deviceIds[encodeBase32Crockford(devB)]).toBe('AA:BB:CC:DD:EE:02');
  });

  it('pruneBleIdentityMappings removes specified genesisHashes', () => {
    const gen = new Uint8Array(32).fill(0x0c);
    persistBleMapping({ bleAddress: 'AA:BB:CC:DD:EE:FF', genesisHash: gen });
    expect(Object.keys(getBleIdentitySnapshot().genesis).length).toBe(1);

    pruneBleIdentityMappings({ genesisHashes: [gen] });
    expect(Object.keys(getBleIdentitySnapshot().genesis).length).toBe(0);
  });

  it('pruneBleIdentityMappings with empty arrays is a no-op', () => {
    const devId = new Uint8Array(32).fill(0x0d);
    persistBleMapping({ bleAddress: 'AA:BB:CC:DD:EE:FF', deviceId: devId });
    pruneBleIdentityMappings({ deviceIds: [], genesisHashes: [] });
    expect(Object.keys(getBleIdentitySnapshot().deviceIds).length).toBe(1);
  });
});
