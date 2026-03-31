/// <reference types="jest" />
/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// Minimal unit test for BLE error envelope parsing in EventBridge.parseBleEnvelope

import { parseBleEnvelope } from '../dsm/EventBridge';
import * as pb from '../proto/dsm_app_pb';

function buildBleErrorEnvelope(deviceId: string, code: number, message: string): Uint8Array {
  // Construct BleTransactionError
  const bleErr = new pb.BleTransactionError({ deviceId: new TextEncoder().encode(deviceId) as Uint8Array<ArrayBuffer>, errorCode: code, message });
  const bleErrBytes = bleErr.toBinary();

  // Wrap in DsmBtMessage (message_type = BTMSG_TYPE_ERROR)
  const btMsg = new pb.DsmBtMessage({
    messageId: 'test-id',
    messageType: pb.BtMessageType.BTMSG_TYPE_ERROR,
    senderId: new Uint8Array(0) as Uint8Array<ArrayBuffer>,
    recipientId: new Uint8Array(0) as Uint8Array<ArrayBuffer>,
    payload: bleErrBytes as Uint8Array<ArrayBuffer>,
    sequence: BigInt(0),
    requiresAck: false,
    checksum: 0,
    ackFor: '',
    receivedSequence: BigInt(0),
  });

  const env = new pb.Envelope({
    version: 3,
    headers: new pb.Headers({ deviceId: new Uint8Array() }),
    messageId: new Uint8Array([1,2,3]),
    payload: { case: 'dsmBtMessage', value: btMsg },
  });
  const raw = env.toBinary();
  const framed = new Uint8Array(1 + raw.length);
  framed[0] = 0x03;
  framed.set(raw, 1);
  return framed;
}

describe('EventBridge.parseBleEnvelope BLE error parsing', () => {
  it('returns BleErrorResult for BTMSG_TYPE_ERROR envelopes', () => {
    const bytes = buildBleErrorEnvelope('AA:BB:CC:DD:EE:FF', 42, 'gatt_write_failed');
    const result = parseBleEnvelope(bytes);
    expect(result).toBeTruthy();
    if (!result || 'rawEnvelope' in result || 'offlineTransferPayload' in result) {
      throw new Error('Unexpected result shape');
    }
    expect('error' in result).toBe(true);
    if ('error' in result) {
      expect(result.error.code).toBe(42);
      expect(result.error.message).toBe('gatt_write_failed');
    }
  });
});
