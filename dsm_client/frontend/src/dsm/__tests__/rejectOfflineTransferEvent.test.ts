// SPDX-License-Identifier: MIT OR Apache-2.0

import * as dsm from '../index';
import * as bridge from '../WebViewBridge';
import * as pb from '../../proto/dsm_app_pb';

function framed(payload: pb.Envelope['payload']): Uint8Array {
  const env = new pb.Envelope({ version: 3, payload }).toBinary();
  const out = new Uint8Array(1 + env.length);
  out[0] = 0x03;
  out.set(env, 1);
  return out;
}

describe('rejectOfflineTransfer', () => {
  const commitment = new Uint8Array(32).fill(0xA5);
  const counterparty = new Uint8Array(32).fill(0x5A);

  afterEach(() => jest.restoreAllMocks());

  test('is done when the SDK answers with the rejection it sends the proposer', async () => {
    const mockReject = jest.spyOn(bridge, 'rejectBilateralByCommitmentBridge').mockResolvedValue(
      framed({ case: 'bilateralPrepareReject', value: new pb.BilateralPrepareReject({ reason: 'test reject' }) }),
    );

    const res = await dsm.rejectOfflineTransfer({ commitmentHash: commitment, counterpartyDeviceId: counterparty, reason: 'test reject' });
    expect(res.success).toBe(true);
    expect(mockReject).toHaveBeenCalledWith(commitment, 'test reject');
  });

  test("carries the SDK's reason when it refuses", async () => {
    jest.spyOn(bridge, 'rejectBilateralByCommitmentBridge').mockResolvedValue(
      framed({ case: 'error', value: new pb.Error({ code: 1, message: 'no proposal with that commitment' }) }),
    );

    const res = await dsm.rejectOfflineTransfer({ commitmentHash: commitment, counterpartyDeviceId: counterparty });
    expect(res).toEqual({ success: false, error: 'no proposal with that commitment' });
  });

  test('an answer that is not a rejection is not reported as done', async () => {
    jest.spyOn(bridge, 'rejectBilateralByCommitmentBridge').mockResolvedValue(
      framed({ case: 'appStateResponse', value: new pb.AppStateResponse({ key: 'ok' }) }),
    );

    const res = await dsm.rejectOfflineTransfer({ commitmentHash: commitment, counterpartyDeviceId: counterparty });
    expect(res.success).toBe(false);
  });
});
