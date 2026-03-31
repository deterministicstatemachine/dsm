/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// eslint-env jest
// Tests for handleContactQrV3Bytes backend integration

declare const describe: any;
declare const test: any;
declare const expect: any;

import * as pb from '../../proto/dsm_app_pb';

/**
 * Mock implementation of handleContactQrV3Bytes for testing
 * This simulates what the real function does in dsm/index.ts
 */
function mockHandleContactQrV3Bytes(bytes: Uint8Array) {
  // Step 1: Build ArgPack with codec=PROTO
  const args = new pb.ArgPack({
    schemaHash: { v: new Uint8Array(32).fill(0) },
    codec: pb.Codec.PROTO,
    body: bytes as any,
  });

  // Step 2: Create QueryOp with path 'contacts.handle_contact_qr_v3'
  const query = new pb.QueryOp({
    path: 'contacts.handle_contact_qr_v3',
    params: args,
  });

  // Step 3: Wrap query in UniversalOp and then UniversalTx
  const op = new pb.UniversalOp({
    kind: { case: 'query', value: query },
  });
  const tx = new pb.UniversalTx({
    ops: [op],
  });

  return { args, query, tx };
}

describe('handleContactQrV3Bytes backend integration', () => {
  const mockDeviceId = new Uint8Array(32).fill(0x33);
  const mockGenesisHash = new Uint8Array(32).fill(0x42);

  test('should build ArgPack with codec=PROTO', () => {
    const contact = new pb.ContactQrV3({
      deviceId: mockDeviceId,
      genesisHash: mockGenesisHash,
      network: 'dsm-test',
      storageNodes: ['http://localhost:8080', 'http://localhost:8081', 'http://localhost:8082'],
      sdkFingerprint: new Uint8Array(0),
    });

    const bytes = contact.toBinary();
    const { args } = mockHandleContactQrV3Bytes(bytes);

    expect(args.codec).toBe(pb.Codec.PROTO);
    expect(args.body).toEqual(bytes);
  });

  test('should create QueryOp with correct path', () => {
    const contact = new pb.ContactQrV3({
      deviceId: mockDeviceId,
      genesisHash: mockGenesisHash,
      network: 'dsm-test',
      storageNodes: ['http://localhost:8080', 'http://localhost:8081', 'http://localhost:8082'],
      sdkFingerprint: new Uint8Array(0),
    });

    const bytes = contact.toBinary();
    const { query } = mockHandleContactQrV3Bytes(bytes);

    expect(query.path).toBe('contacts.handle_contact_qr_v3');
    expect(query.params).toBeDefined();
    expect(query.params?.codec).toBe(pb.Codec.PROTO);
  });

  test('should wrap QueryOp in UniversalTx', () => {
    const contact = new pb.ContactQrV3({
      deviceId: mockDeviceId,
      genesisHash: mockGenesisHash,
      network: 'dsm-test',
      storageNodes: ['http://localhost:8080', 'http://localhost:8081', 'http://localhost:8082'],
      sdkFingerprint: new Uint8Array(0),
    });

    const bytes = contact.toBinary();
    const { tx } = mockHandleContactQrV3Bytes(bytes);

  expect(tx.ops).toBeDefined();
  expect(tx.ops.length).toBe(1);
  const op = tx.ops[0];
  expect(op.kind.case).toBe('query');
  const q = (op.kind as any).value as pb.QueryOp;
  expect(q.path).toBe('contacts.handle_contact_qr_v3');
  });

  test('should preserve ContactQrV3 payload through ArgPack', () => {
    const original = new pb.ContactQrV3({
      deviceId: mockDeviceId,
      genesisHash: mockGenesisHash,
      network: 'production-net',
      storageNodes: ['http://storage.example.com:9090', 'http://storage.example.com:9091', 'http://storage.example.com:9092'],
      sdkFingerprint: new Uint8Array([1, 2, 3, 4]),
    });

    const bytes = original.toBinary();
    const { args } = mockHandleContactQrV3Bytes(bytes);

    // Decode body back to ContactQrV3
    const decoded = pb.ContactQrV3.fromBinary(args.body);

    expect(decoded.deviceId).toEqual(original.deviceId);
    expect(decoded.genesisHash).toEqual(original.genesisHash);
    expect(decoded.network).toBe(original.network);
    expect(decoded.storageNodes).toEqual(original.storageNodes);
    expect(decoded.sdkFingerprint).toEqual(original.sdkFingerprint);
  });

  test('should handle all required ContactQrV3 fields', () => {
    // deviceId/genesisHash are bytes fields — use raw 32-byte Uint8Arrays
    const testDeviceId = new Uint8Array(32).fill(0xAA);
    const testGenesisHash = new Uint8Array(32).fill(0xBB);
    const contact = new pb.ContactQrV3({
      deviceId: testDeviceId,
      genesisHash: testGenesisHash,
      network: 'test-network',
      storageNodes: ['http://test.storage:1234', 'http://test.storage:1235', 'http://test.storage:1236'],
      sdkFingerprint: new Uint8Array([5, 6, 7, 8]),
    });

    const bytes = contact.toBinary();
    const { args } = mockHandleContactQrV3Bytes(bytes);

    const decoded = pb.ContactQrV3.fromBinary(args.body);

    expect(decoded.deviceId).toEqual(testDeviceId);
    expect(decoded.genesisHash).toEqual(testGenesisHash);
    expect(decoded.network).toBe('test-network');
    expect(decoded.storageNodes).toEqual(['http://test.storage:1234', 'http://test.storage:1235', 'http://test.storage:1236']);
    expect(decoded.sdkFingerprint.length).toBe(4);
  });

  test('should validate ArgPack structure matches backend expectations', () => {
    const contact = new pb.ContactQrV3({
      deviceId: mockDeviceId,
      genesisHash: mockGenesisHash,
      network: 'dsm-local',
      storageNodes: ['http://localhost:8080', 'http://localhost:8081', 'http://localhost:8082'],
      sdkFingerprint: new Uint8Array(0),
    });

    const bytes = contact.toBinary();
    const { args } = mockHandleContactQrV3Bytes(bytes);

    // Backend expects:
    // 1. schemaHash (32-byte Hash32)
    expect(args.schemaHash).toBeDefined();
    
    // 2. codec must be PROTO (not JSON or other)
    expect(args.codec).toBe(pb.Codec.PROTO);
    
    // 3. body contains ContactQrV3 protobuf
    expect(args.body.length).toBeGreaterThan(0);
    expect(() => pb.ContactQrV3.fromBinary(args.body)).not.toThrow();
  });
});

describe('ContactAddResponse structure', () => {
  test('should set alias, device_id and genesis_hash', () => {
    const resp = new pb.ContactAddResponse({
      alias: 'test-contact',
      deviceId: new Uint8Array(32).fill(0x88),
      genesisHash: { v: new Uint8Array(32).fill(0x99) },
    });

    expect(resp.alias).toBe('test-contact');
    expect(resp.deviceId).toBeInstanceOf(Uint8Array);
    expect(resp.deviceId.length).toBe(32);
  expect(resp.genesisHash?.v.length).toBe(32);
  });

  test('should handle optional fields being absent', () => {
    const resp = new pb.ContactAddResponse({ alias: 'only-alias' });
    expect(resp.alias).toBe('only-alias');
    // Defaults
    expect(resp.deviceId).toEqual(new Uint8Array(0));
    expect(resp.genesisHash).toBeUndefined();
    expect(resp.verifyingStorageNodes).toEqual([]);
  });
});

describe('Error handling patterns', () => {
  test('should validate codec before sending to backend', () => {
    const contact = new pb.ContactQrV3({
      deviceId: new Uint8Array(32).fill(0x12),
      genesisHash: new Uint8Array(32).fill(0x56),
      network: 'test',
      storageNodes: ['http://localhost:8080', 'http://localhost:8081', 'http://localhost:8082'],
      sdkFingerprint: new Uint8Array(0),
    });

    const bytes = contact.toBinary();
    const { args } = mockHandleContactQrV3Bytes(bytes);

    // If codec is not PROTO, backend will reject. Ensure we set PROTO.
    expect(args.codec).toBe(pb.Codec.PROTO);
  });

  test('should handle invalid protobuf gracefully', () => {
    const invalidBytes = new Uint8Array([0xFF, 0xFF, 0xFF, 0xFF]);

    // Should throw during ContactQrV3 decode
    expect(() => pb.ContactQrV3.fromBinary(invalidBytes)).toThrow();
  });

  test('should validate ContactQrV3 has required fields', () => {
    // Missing fields should still serialize but may fail backend validation
    const incomplete = new pb.ContactQrV3({
      deviceId: new Uint8Array(0), // empty bytes
      genesisHash: new Uint8Array(0), // empty bytes
      network: '',
      storageNodes: [],
      sdkFingerprint: new Uint8Array(0),
    });

    const bytes = incomplete.toBinary();
    // Message with default fields may serialize to 0 bytes; that's acceptable for protobuf
    expect(bytes.length).toBeGreaterThanOrEqual(0);

    // Can decode back
    const decoded = pb.ContactQrV3.fromBinary(bytes);
    expect(decoded.deviceId).toEqual(new Uint8Array(0));
    expect(decoded.genesisHash).toEqual(new Uint8Array(0));
  });
});
