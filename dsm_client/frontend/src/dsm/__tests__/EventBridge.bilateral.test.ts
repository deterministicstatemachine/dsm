// SPDX-License-Identifier: MIT OR Apache-2.0

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

  // A status string is free text; only the event type says a transfer completed.
  // "Transfer sealed" and the completion refresh hang off this.
  test('a rejection whose status reads "completed" completes no transfer', async () => {
    const complete = jest.fn();
    const off = bridgeEvents.on('bilateral.transferComplete', complete as any);

    const reject = new pb.BilateralEventNotification({
      eventType: pb.BilateralEventType.BILATERAL_EVENT_REJECTED,
      status: 'completed',
      message: 'test',
    } as any).toBinary();
    window.dispatchEvent(new CustomEvent('dsm-event-bin', { detail: { topic: 'bilateral.event', payload: reject } }));
    await Promise.resolve();
    expect(complete).not.toHaveBeenCalled();

    const done = new pb.BilateralEventNotification({
      eventType: pb.BilateralEventType.BILATERAL_EVENT_TRANSFER_COMPLETE,
      status: 'completed',
    } as any).toBinary();
    window.dispatchEvent(new CustomEvent('dsm-event-bin', { detail: { topic: 'bilateral.event', payload: done } }));
    await Promise.resolve();
    expect(complete).toHaveBeenCalledTimes(1);
    off();
  });
});

describe('EventBridge announces only what the native payload states', () => {
  beforeEach(() => {
    initializeEventBridge();
  });

  // The poller's counts, or no announcement: a payload that does not decode
  // used to announce zero new items.
  test('an inbox update that does not decode announces nothing', async () => {
    const updated = jest.fn();
    const off = bridgeEvents.on('inbox.updated', updated as any);

    window.dispatchEvent(new CustomEvent('dsm-event-bin', {
      detail: { topic: 'inbox.updated', payload: new Uint8Array([0xff, 0xff, 0xff]) },
    }));
    await Promise.resolve();
    expect(updated).not.toHaveBeenCalled();

    const sync = new pb.StorageSyncResponse({ success: true, pulled: 3, processed: 2 }).toBinary();
    window.dispatchEvent(new CustomEvent('dsm-event-bin', { detail: { topic: 'inbox.updated', payload: sync } }));
    await Promise.resolve();
    expect(updated).toHaveBeenCalledWith({ newItems: 2, source: 'rust_poller' });
    off();
  });

  // A prepare response is not a wallet change; the wallet changes at
  // TRANSFER_COMPLETE, which `bilateral.event` announces. This used to emit a
  // `wallet.refresh` claiming `bilateral.transfer_complete` on one prepare
  // response in eight.
  test('a BLE prepare response announces no wallet change', async () => {
    const refresh = jest.fn();
    const off = bridgeEvents.on('wallet.refresh', refresh as any);

    const env = new pb.Envelope({
      version: 3,
      payload: { case: 'bilateralPrepareResponse', value: new pb.BilateralPrepareResponse({}) },
    });
    const bytes = env.toBinary();
    const framed = new Uint8Array(1 + bytes.length);
    framed[0] = 0x03;
    framed.set(bytes, 1);
    for (let i = 0; i < 9; i++) {
      window.dispatchEvent(new CustomEvent('dsm-event-bin', { detail: { topic: 'ble.envelope.bin', payload: framed } }));
    }
    await Promise.resolve();
    await Promise.resolve();

    expect(refresh).not.toHaveBeenCalled();
    off();
  });

  test('a BLE contact update that names no device is not announced', async () => {
    const updated = jest.fn();
    const off = bridgeEvents.on('contact.bleUpdated', updated as any);

    window.dispatchEvent(new CustomEvent('dsm-event-bin', {
      detail: { topic: 'dsm-contact-ble-updated', payload: new Uint8Array(5) },
    }));
    await Promise.resolve();
    expect(updated).not.toHaveBeenCalled();

    window.dispatchEvent(new CustomEvent('dsm-event-bin', {
      detail: { topic: 'dsm-contact-ble-updated', payload: new Uint8Array(32).fill(1) },
    }));
    await Promise.resolve();
    expect(updated).toHaveBeenCalledTimes(1);
    off();
  });
});
