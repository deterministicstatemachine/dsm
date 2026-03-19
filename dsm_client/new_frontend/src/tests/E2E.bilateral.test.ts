/// <reference types="jest" />
/* eslint-disable @typescript-eslint/no-explicit-any */
/* E2E Test: Bilateral (Offline/Bluetooth) Transaction Flow
 * Simulates offline transaction patterns and Bluetooth encoding
 * Tests the protobuf structures used for offline bilateral transfers
 */

(global as any).window = {
  ...(global as any).window,
};

import { dsmClient } from '../dsm/index';
import * as pb from '../proto/dsm_app_pb';

describe('E2E: Bilateral (Offline) Transaction Flow', () => {
  const ALICE_DEVICE_ID = new Uint8Array(32).fill(1);
  const ALICE_GENESIS = new Uint8Array(32).fill(2);
  const BOB_DEVICE_ID = new Uint8Array(32).fill(10);
  const BOB_GENESIS = new Uint8Array(32).fill(11);

  test('OfflineBilateralTransaction protobuf structure', () => {
    // === Prepare offline bilateral transaction ===
    const offlineTx = new pb.OfflineBilateralTransaction({
      id: 'offline-tx-001',
      senderId: ALICE_DEVICE_ID,
      recipientId: BOB_DEVICE_ID,
      commitmentHash: new Uint8Array(32).fill(0xAA),
      senderStateHash: new Uint8Array(32).fill(0xBB),
      recipientStateHash: new Uint8Array(32).fill(0xCC),
      status: pb.OfflineBilateralTransactionStatus.OFFLINE_TX_PENDING,
      metadata: {
        token: 'ROOT',
        amount: '100000000',
      },
    });

    const bytes = offlineTx.toBinary();
    expect(bytes.length).toBeGreaterThan(0);

    // Verify deserialization preserves data
    const decoded = pb.OfflineBilateralTransaction.fromBinary(bytes);
    expect(decoded.id).toBe('offline-tx-001');
    expect(decoded.senderId).toEqual(ALICE_DEVICE_ID);
    expect(decoded.recipientId).toEqual(BOB_DEVICE_ID);
    expect(decoded.status).toBe(pb.OfflineBilateralTransactionStatus.OFFLINE_TX_PENDING);
    expect(decoded.metadata['token']).toBe('ROOT');
    expect(decoded.metadata['amount']).toBe('100000000');
  });

  test('BilateralAcceptRequest signature flow', () => {
    // === Bilateral accept requires both party signatures ===
    const acceptRequest = new pb.BilateralAcceptRequest({
      counterpartyDeviceId: BOB_DEVICE_ID,
      commitmentHash: { v: new Uint8Array(32).fill(0xDD) } as any,
      localSignature: new Uint8Array(64).fill(0xEE),
      expectedCounterpartyStateHash: { v: new Uint8Array(32).fill(0xFF) } as any,
    });

    const bytes = acceptRequest.toBinary();
    const decoded = pb.BilateralAcceptRequest.fromBinary(bytes);

    // Signature preserved
    expect(decoded.localSignature).toHaveLength(64);
    expect(decoded.localSignature[0]).toBe(0xEE);
    
    // Device IDs preserved
    expect(decoded.counterpartyDeviceId).toEqual(BOB_DEVICE_ID);
  });

  test('Bluetooth Envelope v3 wrapping', () => {
    // === Bluetooth transmission requires Envelope v3 ===
    const headers = new pb.Headers({
      deviceId: ALICE_DEVICE_ID,
      genesisHash: { v: ALICE_GENESIS } as any,
      chainTip: new Uint8Array(32).fill(5),
    });

    const uTx = new pb.UniversalTx({
      ops: [],
      atomic: true,
    });

    const bleEnvelope = new pb.Envelope({
      version: 3,
      headers,
      messageId: new Uint8Array(16).fill(0),
      payload: {
        case: 'universalTx',
        value: uTx,
      },
    });

    const bleBytes = bleEnvelope.toBinary();
    expect(bleBytes.length).toBeGreaterThan(0);

    // Verify receiver can decode
    const received = pb.Envelope.fromBinary(bleBytes);
    expect(received.version).toBe(3);
    expect(received.payload?.case).toBe('universalTx');
    expect(received.headers?.deviceId).toEqual(ALICE_DEVICE_ID);
  });

  test('offline transaction status enumeration', () => {
    // Verify status enum values
    expect(pb.OfflineBilateralTransactionStatus.OFFLINE_TX_STATUS_UNSPECIFIED).toBe(0);
    expect(pb.OfflineBilateralTransactionStatus.OFFLINE_TX_PENDING).toBe(1);
    expect(pb.OfflineBilateralTransactionStatus.OFFLINE_TX_IN_PROGRESS).toBe(2);
    expect(pb.OfflineBilateralTransactionStatus.OFFLINE_TX_CONFIRMED).toBe(3);
    expect(pb.OfflineBilateralTransactionStatus.OFFLINE_TX_FAILED).toBe(4);
    expect(pb.OfflineBilateralTransactionStatus.OFFLINE_TX_REJECTED).toBe(5);

    // Status transitions in metadata
    const tx = new pb.OfflineBilateralTransaction({
      id: 'test-tx',
      senderId: ALICE_DEVICE_ID,
      recipientId: BOB_DEVICE_ID,
      commitmentHash: new Uint8Array(32),
      senderStateHash: new Uint8Array(32),
      recipientStateHash: new Uint8Array(32),
      status: pb.OfflineBilateralTransactionStatus.OFFLINE_TX_CONFIRMED,
    });

    expect(tx.status).toBe(3); // CONFIRMED
  });

  test('Bluetooth binary transport encoding (ISO-8859-1)', () => {
    // Verify BLE transport uses Latin-1 binary strings for Envelope bytes
    const mockEnvelope = new pb.Envelope({
      version: 3,
      headers: new pb.Headers({
        deviceId: ALICE_DEVICE_ID,
        genesisHash: { v: ALICE_GENESIS } as any,
        chainTip: new Uint8Array(32),
      }),
      messageId: new Uint8Array(16),
      payload: {
        case: 'universalRx',
        value: new pb.UniversalRx({ results: [] }),
      },
    });

    const envelopeBytes = mockEnvelope.toBinary();
    
    // Encode for BLE (Latin-1)
    const binString = String.fromCharCode(...envelopeBytes);
    expect(binString.length).toBe(envelopeBytes.length);
    
    // Decode from BLE
    const decoded = Uint8Array.from(binString, c => c.charCodeAt(0));
    expect(decoded).toEqual(envelopeBytes);
    
    // Verify envelope round-trip
    const receivedEnvelope = pb.Envelope.fromBinary(decoded);
    expect(receivedEnvelope.version).toBe(3);
  });

  test('commitment hash validation (32 bytes)', () => {
    // Commitment hashes must be exactly 32 bytes
    const commitmentHash = new Uint8Array(32).fill(0x42);
    
    const tx = new pb.OfflineBilateralTransaction({
      id: 'test',
      senderId: ALICE_DEVICE_ID,
      recipientId: BOB_DEVICE_ID,
      commitmentHash,
      senderStateHash: new Uint8Array(32),
      recipientStateHash: new Uint8Array(32),
      status: pb.OfflineBilateralTransactionStatus.OFFLINE_TX_PENDING,
    });

    expect(tx.commitmentHash).toHaveLength(32);
    expect(tx.senderStateHash).toHaveLength(32);
    expect(tx.recipientStateHash).toHaveLength(32);
  });

  test('bilateral transaction metadata encoding', () => {
    // Metadata is string key-value map for transport/UI
    const tx = new pb.OfflineBilateralTransaction({
      id: 'meta-test',
      senderId: ALICE_DEVICE_ID,
      recipientId: BOB_DEVICE_ID,
      commitmentHash: new Uint8Array(32),
      senderStateHash: new Uint8Array(32),
      recipientStateHash: new Uint8Array(32),
      status: pb.OfflineBilateralTransactionStatus.OFFLINE_TX_PENDING,
      metadata: {
        token_id: 'ROOT',
        amount: '500000000', // 5 ERA
        memo: 'Offline payment',
        tick: '1234567890',
      },
    });

    const bytes = tx.toBinary();
    const decoded = pb.OfflineBilateralTransaction.fromBinary(bytes);
    
    expect(decoded.metadata['token_id']).toBe('ROOT');
    expect(decoded.metadata['amount']).toBe('500000000');
    expect(decoded.metadata['memo']).toBe('Offline payment');
    expect(Object.keys(decoded.metadata)).toHaveLength(4);
  });
});
