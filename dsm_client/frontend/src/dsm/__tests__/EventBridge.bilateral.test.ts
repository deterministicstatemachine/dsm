/* eslint-disable @typescript-eslint/no-explicit-any */
import { initializeEventBridge } from '../EventBridge';
import * as pb from '../../proto/dsm_app_pb';
import { bridgeEvents } from '../../bridge/bridgeEvents';

describe('EventBridge bilateral.event handling', () => {
  beforeEach(() => {
    initializeEventBridge();
  });

  test('TRANSFER_COMPLETE bilateral.event triggers dsm-wallet-refresh', async () => {
    const refreshSpy = jest.fn();

    const unsubscribe = bridgeEvents.on('wallet.refresh', refreshSpy as any);

    // Build a TRANSFER_COMPLETE payload
    const n = new pb.BilateralEventNotification({
      eventType: pb.BilateralEventType.BILATERAL_EVENT_TRANSFER_COMPLETE,
      message: 'test',
    } as any);
    const bytes = n.toBinary();

    // Dispatch the binary event, EventBridge will parse and emit underlying topic
    window.dispatchEvent(new CustomEvent('dsm-event-bin', { detail: { topic: 'bilateral.event', payload: bytes } }));

    // Allow queued microtasks to run
    await Promise.resolve();
    await Promise.resolve();

    expect(refreshSpy).toHaveBeenCalled();
    unsubscribe();
  });
});
