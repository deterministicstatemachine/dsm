/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

const mockToBinary = jest.fn(() => new Uint8Array([1, 2, 3, 4]));
const mockFromBinary = jest.fn();
const mockContactQrV3 = jest.fn().mockImplementation(() => ({
  toBinary: mockToBinary,
}));

jest.mock('../../../proto/dsm_app_pb', () => ({
  ContactQrV3: Object.assign(mockContactQrV3, {
    fromBinary: (...args: any[]) => mockFromBinary(...args),
  }),
}));

const mockDecodeBase32 = jest.fn();
const mockEncodeBase32 = jest.fn();
jest.mock('../../../utils/textId', () => ({
  decodeBase32Crockford: (...args: any[]) => mockDecodeBase32(...args),
  encodeBase32Crockford: (...args: any[]) => mockEncodeBase32(...args),
}));

import {
  encodeContactQrV3Payload,
  decodeContactQrV3Payload,
  decodeQrPayloadBase32ToText,
} from '../contactQrService';

beforeEach(() => {
  mockToBinary.mockClear();
  mockFromBinary.mockClear();
  mockContactQrV3.mockClear();
  mockDecodeBase32.mockClear();
  mockEncodeBase32.mockClear();
  delete (window as any).__QR_DEBUG__;
});

describe('encodeContactQrV3Payload', () => {
  it('encodes valid 32-byte genesis hash and device id', async () => {
    const genesisHash = new Uint8Array(32).fill(0xAA);
    const deviceId = new Uint8Array(32).fill(0xBB);

    const result = await encodeContactQrV3Payload({ genesisHash, deviceId });

    expect(mockContactQrV3).toHaveBeenCalledWith(expect.objectContaining({
      network: 'dsm-local',
      storageNodes: [],
    }));
    expect(result).toEqual(new Uint8Array([1, 2, 3, 4]));
  });

  it('passes signing public key when provided', async () => {
    const genesisHash = new Uint8Array(32).fill(0xAA);
    const deviceId = new Uint8Array(32).fill(0xBB);
    const signingPublicKey = new Uint8Array(64).fill(0xCC);

    await encodeContactQrV3Payload({ genesisHash, deviceId, signingPublicKey });

    const ctorArg = mockContactQrV3.mock.calls[0][0];
    expect(ctorArg.signingPublicKey).toBeTruthy();
    expect(ctorArg.signingPublicKey.length).toBe(64);
  });

  it('passes empty signing key when not provided', async () => {
    const genesisHash = new Uint8Array(32).fill(0xAA);
    const deviceId = new Uint8Array(32).fill(0xBB);

    await encodeContactQrV3Payload({ genesisHash, deviceId });

    const ctorArg = mockContactQrV3.mock.calls[0][0];
    expect(ctorArg.signingPublicKey.length).toBe(0);
  });

  it('uses custom network when provided', async () => {
    const genesisHash = new Uint8Array(32).fill(0xAA);
    const deviceId = new Uint8Array(32).fill(0xBB);

    await encodeContactQrV3Payload({ genesisHash, deviceId, network: 'testnet' });

    const ctorArg = mockContactQrV3.mock.calls[0][0];
    expect(ctorArg.network).toBe('testnet');
  });

  it('trims preferredAlias', async () => {
    const genesisHash = new Uint8Array(32).fill(0xAA);
    const deviceId = new Uint8Array(32).fill(0xBB);

    await encodeContactQrV3Payload({ genesisHash, deviceId, preferredAlias: '  Alice  ' });

    const ctorArg = mockContactQrV3.mock.calls[0][0];
    expect(ctorArg.preferredAlias).toBe('Alice');
  });

  it('rejects genesis hash that is not 32 bytes', async () => {
    const genesisHash = new Uint8Array(16);
    const deviceId = new Uint8Array(32);

    await expect(encodeContactQrV3Payload({ genesisHash, deviceId }))
      .rejects.toThrow('genesis_hash must be 32 bytes');
  });

  it('rejects device id that is not 32 bytes', async () => {
    const genesisHash = new Uint8Array(32);
    const deviceId = new Uint8Array(16);

    await expect(encodeContactQrV3Payload({ genesisHash, deviceId }))
      .rejects.toThrow('device_id must be exactly 32 bytes');
  });

  it('rejects payload that exceeds max size', async () => {
    const genesisHash = new Uint8Array(32).fill(0xAA);
    const deviceId = new Uint8Array(32).fill(0xBB);
    mockToBinary.mockReturnValueOnce(new Uint8Array(1000));

    await expect(encodeContactQrV3Payload({ genesisHash, deviceId }))
      .rejects.toThrow('exceeds safe limit');
  });
});

describe('decodeContactQrV3Payload', () => {
  it('decodes dsm:contact/v3: URI format', () => {
    const fakeBytes = new Uint8Array([10, 20, 30]);
    mockDecodeBase32.mockReturnValue(fakeBytes);
    const fakeContact = {
      deviceId: new Uint8Array(32).fill(1),
      genesisHash: new Uint8Array(32).fill(2),
      network: 'mainnet',
      signingPublicKey: new Uint8Array(64).fill(3),
      toBinary: () => new Uint8Array([99]),
    };
    mockFromBinary.mockReturnValue(fakeContact);
    mockEncodeBase32.mockReturnValue('ENCODED_SPK');

    const result = decodeContactQrV3Payload('dsm:contact/v3:ABCDEF');

    expect(mockDecodeBase32).toHaveBeenCalledWith('ABCDEF');
    expect(result).not.toBeNull();
    expect(result!.contact.deviceId).toEqual(fakeContact.deviceId);
    expect(result!.contact.genesisHash).toEqual(fakeContact.genesisHash);
    expect(result!.contact.network).toBe('mainnet');
    expect(result!.contact.signingPublicKeyB32).toBe('ENCODED_SPK');
    expect(result!.contact.signingPublicKeyLength).toBe(64);
  });

  it('decodes raw base32 payload', () => {
    mockDecodeBase32.mockReturnValue(new Uint8Array([10]));
    mockFromBinary.mockReturnValue({
      deviceId: new Uint8Array(32).fill(1),
      genesisHash: new Uint8Array(32).fill(2),
      network: '',
      signingPublicKey: new Uint8Array(0),
      toBinary: () => new Uint8Array([99]),
    });

    const result = decodeContactQrV3Payload('RAW_B32_PAYLOAD');

    expect(mockDecodeBase32).toHaveBeenCalledWith('RAW_B32_PAYLOAD');
    expect(result).not.toBeNull();
    expect(result!.contact.signingPublicKeyB32).toBeUndefined();
    expect(result!.contact.signingPublicKeyLength).toBe(0);
  });

  it('returns null for empty device id', () => {
    mockDecodeBase32.mockReturnValue(new Uint8Array([10]));
    mockFromBinary.mockReturnValue({
      deviceId: new Uint8Array(0),
      genesisHash: new Uint8Array(32).fill(2),
      toBinary: () => new Uint8Array(0),
    });

    expect(decodeContactQrV3Payload('test')).toBeNull();
  });

  it('returns null for empty genesis hash', () => {
    mockDecodeBase32.mockReturnValue(new Uint8Array([10]));
    mockFromBinary.mockReturnValue({
      deviceId: new Uint8Array(32).fill(1),
      genesisHash: new Uint8Array(0),
      toBinary: () => new Uint8Array(0),
    });

    expect(decodeContactQrV3Payload('test')).toBeNull();
  });

  it('returns null on decode error', () => {
    mockDecodeBase32.mockImplementation(() => { throw new Error('bad base32'); });

    expect(decodeContactQrV3Payload('invalid')).toBeNull();
  });

  it('returns null on protobuf parse error', () => {
    mockDecodeBase32.mockReturnValue(new Uint8Array([10]));
    mockFromBinary.mockImplementation(() => { throw new Error('bad proto'); });

    expect(decodeContactQrV3Payload('test')).toBeNull();
  });

  it('treats empty network as undefined', () => {
    mockDecodeBase32.mockReturnValue(new Uint8Array([10]));
    mockFromBinary.mockReturnValue({
      deviceId: new Uint8Array(32).fill(1),
      genesisHash: new Uint8Array(32).fill(2),
      network: '',
      signingPublicKey: new Uint8Array(0),
      toBinary: () => new Uint8Array([99]),
    });

    const result = decodeContactQrV3Payload('test');
    expect(result!.contact.network).toBeUndefined();
  });
});

describe('decodeQrPayloadBase32ToText', () => {
  it('decodes base32 to text', () => {
    const textBytes = new TextEncoder().encode('hello world');
    mockDecodeBase32.mockReturnValue(textBytes);

    const result = decodeQrPayloadBase32ToText('SOME_B32');

    expect(result).toBe('hello world');
  });

  it('returns null on error', () => {
    mockDecodeBase32.mockImplementation(() => { throw new Error('bad'); });

    expect(decodeQrPayloadBase32ToText('invalid')).toBeNull();
  });

  it('handles empty string input', () => {
    mockDecodeBase32.mockReturnValue(new Uint8Array(0));

    const result = decodeQrPayloadBase32ToText('');

    expect(result).toBe('');
    expect(mockDecodeBase32).toHaveBeenCalledWith('');
  });
});
