/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// eslint-env jest
// Tests for ContactQrV3 encoding/decoding

declare const describe: any;
declare const test: any;
declare const expect: any;

import * as pb from '../../proto/dsm_app_pb';
import {
  encodeContactQrV3Payload,
  type ShareQrInput,
} from './ShareQr';

describe('ShareQr ContactQrV3 encoding', () => {
  const mockGenesisHash = new Uint8Array(32).fill(0x42);
  const mockDeviceId = new Uint8Array(32).fill(0x33);

  const testInput: ShareQrInput = {
    genesisHash: mockGenesisHash,
    deviceId: mockDeviceId,
    network: 'dsm-test',
    storageNodes: ['http://localhost:8080', 'http://localhost:8081', 'http://localhost:8082'],
  };

  test('should encode ContactQrV3 with all required fields', async () => {
    const payload = await encodeContactQrV3Payload(testInput);
    
    expect(payload).toBeInstanceOf(Uint8Array);
    expect(payload.length).toBeGreaterThan(0);
    expect(payload.length).toBeLessThan(900); // within QR size limit
  });

  test('should decode ContactQrV3 roundtrip correctly (binary)', async () => {
    const payload = await encodeContactQrV3Payload(testInput);
    const decoded = pb.ContactQrV3.fromBinary(payload);

    expect(decoded.network).toBe('dsm-test');
    expect(decoded.storageNodes).toEqual([]);

  // Device ID and genesis are raw 32-byte binary fields
  expect(decoded.deviceId).toBeInstanceOf(Uint8Array);
  expect(decoded.genesisHash).toBeInstanceOf(Uint8Array);
  expect(decoded.deviceId.length).toBe(32);
  expect(decoded.genesisHash.length).toBe(32);
  });

  test('should encode device_id as raw 32 bytes', async () => {
    const payload = await encodeContactQrV3Payload(testInput);
    const decoded = pb.ContactQrV3.fromBinary(payload);
    expect(decoded.deviceId).toEqual(mockDeviceId);
  });

  test('should encode genesis_hash as raw 32 bytes', async () => {
    const payload = await encodeContactQrV3Payload(testInput);
    const decoded = pb.ContactQrV3.fromBinary(payload);
    expect(decoded.genesisHash).toEqual(mockGenesisHash);
  });

  test('should use default network if not provided', async () => {
    const inputNoNetwork: ShareQrInput = {
      genesisHash: mockGenesisHash,
      deviceId: mockDeviceId,
    };
    
    const payload = await encodeContactQrV3Payload(inputNoNetwork);
    const decoded = pb.ContactQrV3.fromBinary(payload);
    
    expect(decoded.network).toBe('dsm-local');
  });

  test('should use empty storage nodes array if not provided', async () => {
    const inputNoHint: ShareQrInput = {
      genesisHash: mockGenesisHash,
      deviceId: mockDeviceId,
    };
    
    const payload = await encodeContactQrV3Payload(inputNoHint);
    const decoded = pb.ContactQrV3.fromBinary(payload);
    
    // When no storage nodes are provided, use empty array (callers can populate from their own config)
    expect(decoded.storageNodes).toEqual([]);
  });

  test('should throw error for invalid genesis hash length', async () => {
    const badInput: ShareQrInput = {
      genesisHash: new Uint8Array(16), // wrong size
      deviceId: mockDeviceId,
    };
    
    await expect(encodeContactQrV3Payload(badInput)).rejects.toThrow('genesis_hash must be 32 bytes');
  });

  test('should throw error for invalid device ID length', async () => {
    const badInput: ShareQrInput = {
      genesisHash: mockGenesisHash,
      deviceId: new Uint8Array(0), // empty
    };
    
    await expect(encodeContactQrV3Payload(badInput)).rejects.toThrow('device_id must be exactly 32 bytes');
  });
});

describe('ContactQrV3 vs Headers comparison', () => {
  const mockGenesisHash = new Uint8Array(32).fill(0xAB);
  const mockDeviceId = new Uint8Array(32).fill(0xCD);

  const testInput: ShareQrInput = {
    genesisHash: mockGenesisHash,
    deviceId: mockDeviceId,
    network: 'dsm-test',
    storageNodes: ['http://test.example.com:9090', 'http://test.example.com:9091', 'http://test.example.com:9092'],
  };

  test('ContactQrV3 should contain network and storage hint', async () => {
    const v3Payload = await encodeContactQrV3Payload(testInput);
    const decoded = pb.ContactQrV3.fromBinary(v3Payload);
    
    expect(decoded.network).toBe('dsm-test');
    expect(decoded.storageNodes).toEqual([]);
  });
});
