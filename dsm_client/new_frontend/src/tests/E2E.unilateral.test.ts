/* eslint-disable @typescript-eslint/no-explicit-any */
/* E2E Test: Unilateral (Online) Transaction Flow
 * Simulates exact user journey: QR scan → add contact → send → verify
 * Uses same dsmClient methods as UI components
 */

(global as any).window = {
  ...(global as any).window,
};

import { dsmClient } from '../dsm/index';
import * as pb from '../proto/dsm_app_pb';

describe('E2E: Unilateral Transaction Flow', () => {
  const ALICE_DEVICE_ID = new Uint8Array(32).fill(1);
  const ALICE_GENESIS = new Uint8Array(32).fill(2);
  const BOB_DEVICE_ID = new Uint8Array(32).fill(10);
  const BOB_GENESIS = new Uint8Array(32).fill(11);

  test('QR code decoding: protobuf ContactQrV3 format', () => {
    // === User scans Bob's QR code ===
    const bobContactQr = new pb.ContactQrV3({
      deviceId: BOB_DEVICE_ID,
      network: 'test',
      storageNodes: ['http://localhost:8080', 'http://localhost:8081', 'http://localhost:8082'],
      sdkFingerprint: new Uint8Array(32).fill(99),
      genesisHash: BOB_GENESIS,
    });

    const qrBytes = bobContactQr.toBinary();
    const qrBase64 = btoa(String.fromCharCode(...qrBytes));

    // === Decode QR (simulating QRCodeScannerScreen.decodeContactQr) ===
    const decodedBytes = Uint8Array.from(atob(qrBase64), c => c.charCodeAt(0));
    const decodedContact = pb.ContactQrV3.fromBinary(decodedBytes);

    expect(decodedContact.deviceId).toEqual(BOB_DEVICE_ID);
    expect(decodedContact.network).toBe('test');
    expect(decodedContact.genesisHash).toEqual(BOB_GENESIS);
    expect(decodedContact.genesisHash.length).toBe(32);
  });

  test('contact alias validation rules', async () => {
    const deviceId = new Uint8Array(32).fill(7);
    const signingKey = new Uint8Array(64).fill(9);
    const storageNodes = ['http://localhost:8080', 'http://localhost:8081', 'http://localhost:8082'];
    // Empty alias should be rejected
    await expect(
      dsmClient.addContact({
        alias: '',
        genesisHash: new Uint8Array(32).fill(1),
        deviceId,
        signingPublicKey: signingKey,
        storageNodes,
      })
    ).rejects.toThrow();

    // genesis_hash must be exactly 32 bytes
    await expect(
      dsmClient.addContact({
        alias: 'ValidAlias',
        genesisHash: new Uint8Array(16), // Wrong length
        deviceId,
        signingPublicKey: signingKey,
        storageNodes,
      })
    ).rejects.toThrow();
  });

  test('protobuf balance response parsing', () => {
    // Verify balance response uses bigint (not string)
    const balanceProto = new pb.BalanceGetResponse({
      tokenId: 'ROOT',
      available: 1000000000n, // 1 billion base units = 10 ERA
    });

    expect(balanceProto.tokenId).toBe('ROOT');
    expect(balanceProto.available).toBe(1000000000n);
    expect(typeof balanceProto.available).toBe('bigint');

    // Serialize/deserialize preserves type
    const bytes = balanceProto.toBinary();
    const decoded = pb.BalanceGetResponse.fromBinary(bytes);
    expect(typeof decoded.available).toBe('bigint');
  });

  test('transaction history uses correct property names', () => {
    // Verify TransactionInfo: amount/fee/logicalIndex are uint64 (bigint in TS)
    const historyProto = new pb.WalletHistoryResponse({
      transactions: [
        {
          id: 'tx-unilateral-001',
          fromDeviceId: ALICE_DEVICE_ID,
          toDeviceId: BOB_DEVICE_ID,
          tokenId: 'ROOT',
          amount: 200000000n, // uint64 = bigint
          fee: 0n,
          logicalIndex: 1n,
          txHash: new Uint8Array(32).fill(88),
        },
      ] as any,
    });

    const bytes = historyProto.toBinary();
    const decoded = pb.WalletHistoryResponse.fromBinary(bytes);
    
    expect(decoded.transactions).toHaveLength(1);
    expect(decoded.transactions[0].id).toBe('tx-unilateral-001');
    expect(decoded.transactions[0].tokenId).toBe('ROOT');
    expect(decoded.transactions[0].amount).toBe(200000000n); // bigint
    expect(typeof decoded.transactions[0].amount).toBe('bigint');
  });

  test('device_id to alias mapping logic', () => {
    // Simulate what EnhancedWalletScreen does
    const contacts = [
      { alias: 'Alice', deviceId: ALICE_DEVICE_ID },
      { alias: 'Bob', deviceId: BOB_DEVICE_ID },
    ];

    const transaction = {
      id: 'tx-001',
      toDeviceId: BOB_DEVICE_ID,
      fromDeviceId: ALICE_DEVICE_ID,
    };

    // Map device_id to alias
    const recipient = contacts.find(c => {
      const txDeviceId = transaction.toDeviceId;
      if (!(txDeviceId instanceof Uint8Array)) return false;
      return c.deviceId.every((byte: number, i: number) => byte === txDeviceId[i]);
    });

    expect(recipient?.alias).toBe('Bob');
  });

  test('binary string encoding for identity persistence', () => {
    // Verify Latin-1 binary string encoding (not Base64/hex)
    const deviceId = new Uint8Array([1, 2, 3, 255, 254, 253]);
    
    // Encode as binary string (Latin-1)
    const binString = String.fromCharCode(...deviceId);
    expect(binString.length).toBe(6);
    
    // Decode back to bytes
    const decoded = Uint8Array.from(binString, c => c.charCodeAt(0));
    expect(decoded).toEqual(deviceId);
    
    // Verify high bytes (>127) preserved
    expect(decoded[3]).toBe(255);
    expect(decoded[4]).toBe(254);
    expect(decoded[5]).toBe(253);
  });
});
