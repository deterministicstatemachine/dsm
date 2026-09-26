// SPDX-License-Identifier: MIT OR Apache-2.0

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
      phase: pb.OfflineBilateralPhase.OFFLINE_PHASE_PREPARED,
      direction: pb.OfflineBilateralDirection.OFFLINE_DIRECTION_OUTGOING,
      amount: BigInt(100000000),
      displayAmount: '1.00000000',
      tokenId: 'ROOT',
      counterpartyAlias: 'bob',
      cancellable: true,
    });

    const bytes = offlineTx.toBinary();
    expect(bytes.length).toBeGreaterThan(0);

    // Verify deserialization preserves data
    const decoded = pb.OfflineBilateralTransaction.fromBinary(bytes);
    expect(decoded.id).toBe('offline-tx-001');
    expect(decoded.senderId).toEqual(ALICE_DEVICE_ID);
    expect(decoded.recipientId).toEqual(BOB_DEVICE_ID);
    expect(decoded.phase).toBe(pb.OfflineBilateralPhase.OFFLINE_PHASE_PREPARED);
    expect(decoded.direction).toBe(pb.OfflineBilateralDirection.OFFLINE_DIRECTION_OUTGOING);
    expect(decoded.amount).toBe(BigInt(100000000));
    expect(decoded.displayAmount).toBe('1.00000000');
    expect(decoded.tokenId).toBe('ROOT');
    expect(decoded.counterpartyAlias).toBe('bob');
    expect(decoded.cancellable).toBe(true);
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

  test('offline bilateral phase and direction numbering', () => {
    expect(pb.OfflineBilateralPhase.OFFLINE_PHASE_UNSPECIFIED).toBe(0);
    expect(pb.OfflineBilateralPhase.OFFLINE_PHASE_PREPARING).toBe(1);
    expect(pb.OfflineBilateralPhase.OFFLINE_PHASE_PREPARED).toBe(2);
    expect(pb.OfflineBilateralPhase.OFFLINE_PHASE_PENDING_USER_ACTION).toBe(3);
    expect(pb.OfflineBilateralPhase.OFFLINE_PHASE_ACCEPTED).toBe(4);
    expect(pb.OfflineBilateralPhase.OFFLINE_PHASE_REJECTED).toBe(5);
    expect(pb.OfflineBilateralPhase.OFFLINE_PHASE_CONFIRM_PENDING).toBe(6);
    expect(pb.OfflineBilateralPhase.OFFLINE_PHASE_COMMITTED).toBe(7);
    expect(pb.OfflineBilateralPhase.OFFLINE_PHASE_FAILED).toBe(8);
    expect(pb.OfflineBilateralDirection.OFFLINE_DIRECTION_UNSPECIFIED).toBe(0);
    expect(pb.OfflineBilateralDirection.OFFLINE_DIRECTION_INCOMING).toBe(1);
    expect(pb.OfflineBilateralDirection.OFFLINE_DIRECTION_OUTGOING).toBe(2);
  });

  test('Bluetooth binary transport encoding (ISO-8859-1)', () => {
    // Verify BLE transport uses Latin-1 binary strings for Envelope bytes
    const mockEnvelope = new pb.Envelope({
      version: 3,
      headers: new pb.Headers({
        deviceId: ALICE_DEVICE_ID,
        genesisHash: { v: ALICE_GENESIS } as any,
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
    });

    expect(tx.commitmentHash).toHaveLength(32);
  });

  test('fields the SDK leaves unset decode as absent, never as a value', () => {
    // A device that does not know a token's decimals sends no display amount;
    // a contact without an alias sends none. The UI must be able to tell.
    const tx = new pb.OfflineBilateralTransaction({
      id: 'absent-test',
      senderId: ALICE_DEVICE_ID,
      recipientId: BOB_DEVICE_ID,
      commitmentHash: new Uint8Array(32),
      phase: pb.OfflineBilateralPhase.OFFLINE_PHASE_PENDING_USER_ACTION,
      direction: pb.OfflineBilateralDirection.OFFLINE_DIRECTION_INCOMING,
      amount: BigInt(500000000),
      tokenId: 'ROOT',
    });

    const decoded = pb.OfflineBilateralTransaction.fromBinary(tx.toBinary());

    expect(decoded.displayAmount).toBeUndefined();
    expect(decoded.counterpartyAlias).toBeUndefined();
    expect(decoded.senderBleAddress).toBeUndefined();
    expect(decoded.cancellable).toBe(false);
  });
});
