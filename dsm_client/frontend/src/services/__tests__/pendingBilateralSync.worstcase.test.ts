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

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe('pendingBilateralSync worst-case', () => {
  beforeEach(() => {
    clearPendingBilateral();
    delete (window as any).__DSM_PENDING_BILATERAL_SYNC_INSTALLED__;
    delete (window as any).__DSM_PENDING_BILATERAL_STORE_SYNC__;
    initializeEventBridge();
    getPendingBilateralListStrict.mockReset();
  });

  // Updated: this behavior is retired. We verify that events do NOT queue refreshes anymore.
  test('ignores events (scheduler disabled) even if loaded concurrently', async () => {
    const commitmentHash = new Uint8Array(32);
    commitmentHash[0] = 1;
    const counterpartyDeviceId = new Uint8Array(32);
    counterpartyDeviceId[0] = 2;

    const id = makePendingId(
      base32CrockfordEncode(commitmentHash),
      base32CrockfordEncode(counterpartyDeviceId)
    );

    const first = deferred<{ transactions: pb.OfflineBilateralTransaction[] }>();

    // It is called once on install
    getPendingBilateralListStrict
      .mockImplementationOnce(() => first.promise);

    installPendingBilateralSync();

    const note = new pb.BilateralEventNotification({
      eventType: pb.BilateralEventType.BILATERAL_EVENT_PREPARE_RECEIVED,
      commitmentHash,
      counterpartyDeviceId,
      status: 'pending_user_action',
      message: 'incoming',
    });

    // Fire event (should be ignored)
    emitBilateralEvent(note);

    first.resolve({ transactions: [] });

    await new Promise((resolve) => setTimeout(resolve, 20));

    const after = loadPendingBilateral();
    // No update in store
    expect(after.some((x) => x.id === id)).toBe(false);
    // Only called once (initial install), event did not trigger a second call
    expect(getPendingBilateralListStrict).toHaveBeenCalledTimes(1);
  });
});
