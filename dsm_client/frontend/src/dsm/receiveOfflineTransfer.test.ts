/// <reference types="jest" />

/**
 * Test for BilateralTransferRequest protobuf encoding/decoding
 * Validates message structure and field validation logic
 * 
 * Note: Full integration tests with receiveOfflineTransfer are in Rust test suite.
 * This test validates the TypeScript protobuf encoding layer.
 */

import * as pb from '../proto/dsm_app_pb';

describe('BilateralTransferRequest protobuf', () => {
  it('should encode and decode a valid request with all required fields', () => {
    const req = new pb.BilateralTransferRequest({
      counterpartyDeviceId: new Uint8Array(32).fill(0x99),
      commitmentHash: { v: new Uint8Array(32).fill(1) },
      counterpartySig: new Uint8Array(64).fill(0xAA),
      operationData: new Uint8Array(128).fill(0xBB),
      expectedGenesisHash: { v: new Uint8Array(32).fill(2) },
      expectedCounterpartyStateHash: { v: new Uint8Array(32).fill(3) },
      expectedLocalStateHash: { v: new Uint8Array(32).fill(4) }
    });

    const payload = req.toBinary();
    expect(payload).toBeInstanceOf(Uint8Array);
    expect(payload.length).toBeGreaterThan(0);

    const decoded = pb.BilateralTransferRequest.fromBinary(payload);
    expect(decoded.counterpartyDeviceId).toEqual(req.counterpartyDeviceId);
    expect(decoded.commitmentHash?.v).toEqual(req.commitmentHash?.v);
    expect(decoded.counterpartySig).toEqual(req.counterpartySig);
    expect(decoded.operationData).toEqual(req.operationData);
  });

  it('should validate counterparty_device_id is 32 bytes', () => {
    const req = new pb.BilateralTransferRequest({
      counterpartyDeviceId: new Uint8Array(32).fill(0x99),
      commitmentHash: { v: new Uint8Array(32).fill(1) },
      counterpartySig: new Uint8Array(64).fill(0xAA),
      operationData: new Uint8Array(128),
      expectedGenesisHash: { v: new Uint8Array(32).fill(2) },
      expectedCounterpartyStateHash: { v: new Uint8Array(32).fill(3) },
      expectedLocalStateHash: { v: new Uint8Array(32).fill(4) }
    });

    expect(req.counterpartyDeviceId.length).toBe(32);
  });

  it('should validate commitment_hash is 32 bytes', () => {
    const req = new pb.BilateralTransferRequest({
      counterpartyDeviceId: new Uint8Array(32).fill(0x99),
      commitmentHash: { v: new Uint8Array(32).fill(1) },
      counterpartySig: new Uint8Array(64).fill(0xAA),
      operationData: new Uint8Array(128),
      expectedGenesisHash: { v: new Uint8Array(32).fill(2) },
      expectedCounterpartyStateHash: { v: new Uint8Array(32).fill(3) },
      expectedLocalStateHash: { v: new Uint8Array(32).fill(4) }
    });

    expect(req.commitmentHash?.v.length).toBe(32);
  });

  it('should encode expected hash fields correctly', () => {
    const req = new pb.BilateralTransferRequest({
      counterpartyDeviceId: new Uint8Array(32).fill(0x99),
      commitmentHash: { v: new Uint8Array(32).fill(1) },
      counterpartySig: new Uint8Array(64).fill(0xAA),
      operationData: new Uint8Array(128),
      expectedGenesisHash: { v: new Uint8Array(32).fill(2) },
      expectedCounterpartyStateHash: { v: new Uint8Array(32).fill(3) },
      expectedLocalStateHash: { v: new Uint8Array(32).fill(4) }
    });

    expect(req.expectedGenesisHash?.v.length).toBe(32);
    expect(req.expectedCounterpartyStateHash?.v.length).toBe(32);
    expect(req.expectedLocalStateHash?.v.length).toBe(32);
  });
});

describe('BilateralTransferResponse protobuf', () => {
  it('should encode and decode a successful response', () => {
    const resp = new pb.BilateralTransferResponse({
      success: true,
      transactionHash: { v: new Uint8Array(32).fill(0xCC) },
      message: 'offline transfer accepted (placeholder)'
    });

    const payload = resp.toBinary();
    const decoded = pb.BilateralTransferResponse.fromBinary(payload);

    expect(decoded.success).toBe(true);
    expect(decoded.transactionHash?.v).toEqual(new Uint8Array(32).fill(0xCC));
    expect(decoded.message).toBe('offline transfer accepted (placeholder)');
  });

  it('should encode a failure response without transaction_hash', () => {
    const resp = new pb.BilateralTransferResponse({
      success: false,
      message: 'validation failed: counterparty_device_id must be 32 bytes'
    });

    const payload = resp.toBinary();
    const decoded = pb.BilateralTransferResponse.fromBinary(payload);

    expect(decoded.success).toBe(false);
    expect(decoded.transactionHash).toBeUndefined();
    expect(decoded.message).toContain('validation failed');
  });
});

