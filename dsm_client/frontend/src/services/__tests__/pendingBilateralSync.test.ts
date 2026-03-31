import * as pb from '../../proto/dsm_app_pb';
import { encodeBase32Crockford as base32CrockfordEncode } from '../../utils/textId';
import { initializeEventBridge } from '../../dsm/EventBridge';
import { installPendingBilateralSync } from '../pendingBilateralSync';
import {
  clearPendingBilateral,
  loadPendingBilateral,
  makePendingId,
} from '../pendingBilateralStore';

import { bridgeEvents } from '../../bridge/bridgeEvents';

jest.mock('../../dsm/index', () => ({
  getPendingBilateralListStrict: jest.fn(),
}));

const getPendingBilateralListStrict = jest.requireMock('../../dsm/index').getPendingBilateralListStrict as jest.Mock;

function emitBilateralEvent(note: pb.BilateralEventNotification) {
  const bytes = note.toBinary();
  bridgeEvents.emit('bilateral.event', bytes);
}

describe('pendingBilateralSync', () => {
  beforeEach(() => {
    clearPendingBilateral();
    delete (window as any).__DSM_PENDING_BILATERAL_SYNC_INSTALLED__;
    delete (window as any).__DSM_PENDING_BILATERAL_STORE_SYNC__;
    // Ensure bridge is installed for this test environment.
    initializeEventBridge();
    getPendingBilateralListStrict.mockReset();
    getPendingBilateralListStrict.mockResolvedValue({ transactions: [] });
  });

  // Updated reflection of architecture:
  // pendingBilateralSync no longer updates the background store on events.
  // Instead, the UI components (PendingBilateralPanel) subscribe directly and fetch fresh state.
  test('ignores events (leaving store empty) as panel handles sync', async () => {
    const commitmentHash = new Uint8Array(32);
    commitmentHash[0] = 1;
    const counterpartyDeviceId = new Uint8Array(32);
    counterpartyDeviceId[0] = 2;

    const id = makePendingId(base32CrockfordEncode(commitmentHash), base32CrockfordEncode(counterpartyDeviceId));

    getPendingBilateralListStrict
      .mockResolvedValueOnce({ transactions: [] }) // Initial load
      .mockResolvedValueOnce({
        transactions: [
          new pb.OfflineBilateralTransaction({
            id: base32CrockfordEncode(commitmentHash),
            senderId: counterpartyDeviceId as any,
            recipientId: new Uint8Array(32) as any,
            commitmentHash: commitmentHash as any,
            senderStateHash: new Uint8Array(32) as any,
            recipientStateHash: new Uint8Array(32) as any,
            status: pb.OfflineBilateralTransactionStatus.OFFLINE_TX_PENDING,
            metadata: {
              direction: 'incoming',
              phase: 'pending_user_action',
              amount: '2',
              token_id: 'ERA',
              created_at_step: '1',
            },
          }),
        ],
      });

    installPendingBilateralSync();

    const note = new pb.BilateralEventNotification({
      eventType: pb.BilateralEventType.BILATERAL_EVENT_PREPARE_RECEIVED,
      commitmentHash,
      counterpartyDeviceId,
      status: 'pending_user_action',
      message: 'incoming',
    });

    emitBilateralEvent(note);

    // Allow async event processing
    await new Promise(resolve => setTimeout(resolve, 10));

    const after = loadPendingBilateral();
    // Expect FALSE because the background sync is disabled in favor of direct UI polling
    expect(after.some((x) => x.id === id)).toBe(false);
  });
});
