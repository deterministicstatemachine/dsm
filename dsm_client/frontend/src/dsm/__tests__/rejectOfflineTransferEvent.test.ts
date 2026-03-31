import * as dsm from '../index';
import * as bridge from '../WebViewBridge';

describe('rejectOfflineTransfer event emission', () => {
  test('calls native reject and returns success (event emission handled by native)', async () => {
    const commitment = new Uint8Array(32); commitment.fill(0xA5);
    const counterparty = new Uint8Array(32); counterparty.fill(0x5A);

    // Mock the native bridge call
    const okEnv = new (await import('../../proto/dsm_app_pb')).Envelope({
      version: 3,
      payload: { case: 'appStateResponse', value: new (await import('../../proto/dsm_app_pb')).AppStateResponse({ key: 'ok' }) },
    } as any).toBinary();
    const framed = new Uint8Array(1 + okEnv.length);
    framed[0] = 0x03;
    framed.set(okEnv, 1);
    const mockReject = jest.spyOn(bridge, 'rejectBilateralByCommitmentBridge').mockResolvedValue(framed); // Success envelope

    const res = await dsm.rejectOfflineTransfer({ commitmentHash: commitment, counterpartyDeviceId: counterparty, reason: 'test reject' });
    expect(res.success).toBe(true);
    expect(mockReject).toHaveBeenCalledWith(commitment, 'test reject');
  });
});
