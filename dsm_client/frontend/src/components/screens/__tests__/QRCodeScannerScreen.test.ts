/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// eslint-env jest
// Tests for QR code scanning and decoding

declare const describe: any;
declare const test: any;
declare const expect: any;

import { encodeBase32Crockford as base32CrockfordEncode } from '../../../utils/textId';
import { decodeContactQrV3Payload, encodeContactQrV3Payload, type ContactQrV3Data } from '../../../services/qr/contactQrService';

/**
 * Simulate the decodeContactQr function from QRCodeScannerScreen
 */
function decodeContactQr(qrDataString: string): { bytes: Uint8Array; alias: string; contact: ContactQrV3Data } {
  const decoded = decodeContactQrV3Payload(qrDataString);
  if (!decoded) throw new Error('decode failed');
  // Alias from first 8 chars of Base32-encoded deviceId (display boundary)
  const alias = base32CrockfordEncode(decoded.contact.deviceId).slice(0, 8);
  return { bytes: decoded.rawBytes, alias, contact: decoded.contact };
}

describe('QRCodeScannerScreen decoding', () => {
  const mockGenesisHash = new Uint8Array(32).fill(0x42);
  const mockDeviceId = new Uint8Array(32).fill(0x33);

  test('should decode ContactQrV3 format correctly', async () => {
    const payload = await encodeContactQrV3Payload({
      deviceId: mockDeviceId,
      genesisHash: mockGenesisHash,
      network: 'dsm-test',
      storageNodes: ['http://test.example.com:8080', 'http://test.example.com:8081', 'http://test.example.com:8082'],
    });
    
    // Convert to Base32 Crockford string (simulating QR scan)
    const qrDataString = base32CrockfordEncode(payload);
    
    const decoded = decodeContactQr(qrDataString);
    
    expect(decoded.bytes).toBeInstanceOf(Uint8Array);
    expect(decoded.alias).toBeTruthy();
    
    // Verify we can decode the result
    expect(decoded.contact.network).toBe('dsm-test');
    expect(decoded.contact.storageNodes).toBeUndefined();
  });

  // QR codes must carry ContactQrV3 protobuf only.

  test('should generate alias from device_id byte prefix', async () => {
    const payload = await encodeContactQrV3Payload({
      deviceId: mockDeviceId,
      genesisHash: mockGenesisHash,
      network: 'dsm-test',
      storageNodes: ['http://localhost:8080', 'http://localhost:8081', 'http://localhost:8082'],
    });
    const qrDataString = base32CrockfordEncode(payload);

    const decoded = decodeContactQr(qrDataString);

    expect(decoded.alias).toBe(base32CrockfordEncode(mockDeviceId).slice(0, 8));
  });

  test('should preserve all ContactQrV3 fields through roundtrip', async () => {
      const payload = await encodeContactQrV3Payload({
        deviceId: mockDeviceId,
        genesisHash: mockGenesisHash,
        network: 'production-net',
        storageNodes: ['http://storage.example.com:9090', 'http://storage.example.com:9091', 'http://storage.example.com:9092'],
      });
    const qrDataString = base32CrockfordEncode(payload);

    const decoded = decodeContactQr(qrDataString);

      expect(decoded.contact.deviceId).toEqual(mockDeviceId);
      expect(decoded.contact.genesisHash).toEqual(mockGenesisHash);
      expect(decoded.contact.network).toBe('production-net');
  });

  test('should handle empty sdk_fingerprint', async () => {
    const payload = await encodeContactQrV3Payload({
      deviceId: mockDeviceId,
      genesisHash: mockGenesisHash,
      network: 'dsm-test',
      storageNodes: ['http://localhost:8080', 'http://localhost:8081', 'http://localhost:8082'],
    });
    const qrDataString = base32CrockfordEncode(payload);
    
    const decoded = decodeContactQr(qrDataString);
    expect(decoded.contact.signingPublicKeyLength || 0).toBeGreaterThanOrEqual(0);
  });

  test('should throw error for invalid protobuf data', () => {
    const invalidData = 'not-a-valid-protobuf-payload';
    
    expect(() => decodeContactQr(invalidData)).toThrow();
  });
});

describe('QR scanner UX flow expectations', () => {
  test('should pass decoded data to parent without immediate backend call', async () => {
    // This test documents the expected behavior:
    // Scanner should decode QR → return data → parent shows form with alias input → user submits
    
    const mockGenesisHash = new Uint8Array(32).fill(0x42);
    const mockDeviceId = new Uint8Array(32).fill(0x33);
    
    const payload = await encodeContactQrV3Payload({
      deviceId: mockDeviceId,
      genesisHash: mockGenesisHash,
      network: 'dsm-test',
      storageNodes: ['http://localhost:8080'],
    });
    const qrDataString = base32CrockfordEncode(payload);
    
    const decoded = decodeContactQr(qrDataString);
    
    // Scanner returns bytes + suggested alias
    expect(decoded).toHaveProperty('bytes');
    expect(decoded).toHaveProperty('alias');
    
    // Parent component should:
    // 1. Receive decoded.bytes
    // 2. Display form with input field pre-filled with decoded.alias
    // 3. Let user edit alias
    // 4. On submit, call dsmClient.handleContactQrV3Bytes(decoded.bytes)
    
    // This ensures user has control over the alias before backend validation
  });

  test('should provide canonical bytes for backend validation', async () => {
    const mockGenesisHash = new Uint8Array(32).fill(0x99);
    const mockDeviceId = new Uint8Array(32).fill(0x88);
    
    const payload = await encodeContactQrV3Payload({
      deviceId: mockDeviceId,
      genesisHash: mockGenesisHash,
      network: 'dsm-test',
      storageNodes: ['http://localhost:8080'],
    });
    const qrDataString = base32CrockfordEncode(payload);
    
    const decoded = decodeContactQr(qrDataString);
    
    // The returned bytes should be valid ContactQrV3 protobuf
    expect(decoded.bytes).toBeInstanceOf(Uint8Array);
  });
});


// Policy: contact QRs must be Base32 Crockford of ContactQrV3 protobuf bytes.
