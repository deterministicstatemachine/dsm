// SPDX-License-Identifier: Apache-2.0
import { encodeBase32Crockford, decodeBase32Crockford } from '../../../utils/textId';

const mockFromBinary = jest.fn();
const mockToBinary = jest.fn();

jest.mock('../../../proto/dsm_app_pb', () => ({
  BilateralEventType: {
    BILATERAL_EVENT_PREPARE_RECEIVED: 0,
    BILATERAL_EVENT_ACCEPT_SENT: 1,
    BILATERAL_EVENT_COMMIT_RECEIVED: 2,
    BILATERAL_EVENT_TRANSFER_COMPLETE: 3,
    BILATERAL_EVENT_REJECTED: 4,
    BILATERAL_EVENT_FAILED: 5,
  },
  BilateralEventNotification: Object.assign(
    jest.fn().mockImplementation((data: Record<string, unknown>) => ({
      ...data,
      toBinary: mockToBinary,
    })),
    { fromBinary: mockFromBinary },
  ),
}));

jest.mock('../../../dsm/index', () => ({
  acceptOfflineTransfer: jest.fn().mockResolvedValue({ success: true }),
  rejectOfflineTransfer: jest.fn().mockResolvedValue({ success: true }),
}));

import {
  BilateralEventType,
  decodeBilateralEvent,
  encodeBilateralEventNotification,
  acceptIncomingTransfer,
  rejectIncomingTransfer,
  BilateralTransferEvent,
} from '../bilateralEventService';
import { acceptOfflineTransfer, rejectOfflineTransfer } from '../../../dsm/index';

describe('BilateralEventType', () => {
  it('exports expected event type constants', () => {
    expect(BilateralEventType.PREPARE_RECEIVED).toBe(0);
    expect(BilateralEventType.ACCEPT_SENT).toBe(1);
    expect(BilateralEventType.COMMIT_RECEIVED).toBe(2);
    expect(BilateralEventType.TRANSFER_COMPLETE).toBe(3);
    expect(BilateralEventType.REJECTED).toBe(4);
    expect(BilateralEventType.FAILED).toBe(5);
  });
});

describe('decodeBilateralEvent', () => {
  beforeEach(() => {
    mockFromBinary.mockReset();
  });

  it('decodes a valid notification with Uint8Array fields', () => {
    const devId = new Uint8Array(32).fill(0xaa);
    const commitHash = new Uint8Array(32).fill(0xbb);
    const txHash = new Uint8Array(32).fill(0xcc);

    mockFromBinary.mockReturnValue({
      eventType: 3,
      counterpartyDeviceId: devId,
      commitmentHash: commitHash,
      transactionHash: txHash,
      amount: 100n,
      tokenId: 'ERA',
      status: 'complete',
      message: 'Transfer done',
      senderBleAddress: 'AA:BB:CC:DD:EE:FF',
    });

    const result = decodeBilateralEvent(new Uint8Array([1, 2, 3]));
    expect(result).not.toBeNull();
    expect(result!.eventType).toBe(3);
    expect(result!.counterpartyDeviceId).toBe(encodeBase32Crockford(devId));
    expect(result!.commitmentHash).toBe(encodeBase32Crockford(commitHash));
    expect(result!.transactionHash).toBe(encodeBase32Crockford(txHash));
    expect(result!.amount).toBe(100n);
    expect(result!.tokenId).toBe('ERA');
    expect(result!.status).toBe('complete');
    expect(result!.message).toBe('Transfer done');
    expect(result!.senderBleAddress).toBe('AA:BB:CC:DD:EE:FF');
  });

  it('returns empty base32 strings for null/empty byte fields', () => {
    mockFromBinary.mockReturnValue({
      eventType: 0,
      counterpartyDeviceId: null,
      commitmentHash: new Uint8Array(0),
      transactionHash: undefined,
      amount: 0n,
      tokenId: '',
      status: 'pending',
      message: '',
      senderBleAddress: '',
    });

    const result = decodeBilateralEvent(new Uint8Array([0]));
    expect(result).not.toBeNull();
    expect(result!.counterpartyDeviceId).toBe('');
    expect(result!.commitmentHash).toBe('');
    expect(result!.transactionHash).toBe('');
  });

  it('returns null on protobuf decode failure', () => {
    mockFromBinary.mockImplementation(() => {
      throw new Error('bad proto');
    });
    expect(decodeBilateralEvent(new Uint8Array([0xff]))).toBeNull();
  });
});

describe('encodeBilateralEventNotification', () => {
  beforeEach(() => {
    mockToBinary.mockReset();
  });

  it('constructs a notification and calls toBinary', () => {
    const expected = new Uint8Array([10, 20, 30]);
    mockToBinary.mockReturnValue(expected);

    const result = encodeBilateralEventNotification({
      eventType: BilateralEventType.ACCEPT_SENT,
      status: 'ok',
      message: 'accepted',
      amount: 42n,
      tokenId: 'ERA',
    });

    expect(result).toBe(expected);
    expect(mockToBinary).toHaveBeenCalledTimes(1);
  });

  it('defaults empty status and message', () => {
    mockToBinary.mockReturnValue(new Uint8Array(0));
    encodeBilateralEventNotification({ eventType: BilateralEventType.FAILED });
    expect(mockToBinary).toHaveBeenCalled();
  });
});

describe('acceptIncomingTransfer', () => {
  it('decodes base32 hashes and calls acceptOfflineTransfer', async () => {
    const commitBytes = new Uint8Array(32).fill(0x11);
    const devBytes = new Uint8Array(32).fill(0x22);
    const event: BilateralTransferEvent = {
      eventType: BilateralEventType.PREPARE_RECEIVED,
      counterpartyDeviceId: encodeBase32Crockford(devBytes),
      commitmentHash: encodeBase32Crockford(commitBytes),
      status: 'pending',
      message: '',
    };

    const result = await acceptIncomingTransfer(event);
    expect(result).toEqual({ success: true });
    expect(acceptOfflineTransfer).toHaveBeenCalledWith({
      commitmentHash: expect.any(Uint8Array),
      counterpartyDeviceId: expect.any(Uint8Array),
    });
  });

  it('throws when commitmentHash does not decode to 32 bytes', async () => {
    const event: BilateralTransferEvent = {
      eventType: BilateralEventType.PREPARE_RECEIVED,
      counterpartyDeviceId: encodeBase32Crockford(new Uint8Array(32).fill(0x33)),
      commitmentHash: encodeBase32Crockford(new Uint8Array(5)),
      status: '',
      message: '',
    };
    await expect(acceptIncomingTransfer(event)).rejects.toThrow(/commitmentHash must decode to 32 bytes/);
  });
});

describe('rejectIncomingTransfer', () => {
  it('decodes base32 hashes and calls rejectOfflineTransfer', async () => {
    const commitBytes = new Uint8Array(32).fill(0x44);
    const devBytes = new Uint8Array(32).fill(0x55);
    const event: BilateralTransferEvent = {
      eventType: BilateralEventType.PREPARE_RECEIVED,
      counterpartyDeviceId: encodeBase32Crockford(devBytes),
      commitmentHash: encodeBase32Crockford(commitBytes),
      status: 'pending',
      message: '',
    };

    await rejectIncomingTransfer(event, 'user declined');
    expect(rejectOfflineTransfer).toHaveBeenCalledWith({
      commitmentHash: expect.any(Uint8Array),
      counterpartyDeviceId: expect.any(Uint8Array),
      reason: 'user declined',
    });
  });

  it('throws when counterpartyDeviceId does not decode to 32 bytes', async () => {
    const event: BilateralTransferEvent = {
      eventType: BilateralEventType.PREPARE_RECEIVED,
      counterpartyDeviceId: encodeBase32Crockford(new Uint8Array(10)),
      commitmentHash: encodeBase32Crockford(new Uint8Array(32).fill(0x66)),
      status: '',
      message: '',
    };
    await expect(rejectIncomingTransfer(event)).rejects.toThrow(/counterpartyDeviceId must decode to 32 bytes/);
  });
});
