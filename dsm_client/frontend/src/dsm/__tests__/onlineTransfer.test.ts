// SPDX-License-Identifier: Apache-2.0
// The online send the send screen makes: wallet.sendSmart. The file used to
// test a wallet.send wrapper no screen called, and two of its tests compared an
// object the test built with itself.

import * as pb from '../../proto/dsm_app_pb';
import * as dsm from '../index';
import * as bridge from '../WebViewBridge';

function framed(payload: pb.Envelope['payload']): Uint8Array {
  const env = new pb.Envelope({ version: 3, payload }).toBinary();
  const out = new Uint8Array(1 + env.length);
  out[0] = 0x03;
  out.set(env, 1);
  return out;
}

describe('sendOnlineTransferSmart', () => {
  afterEach(() => jest.restoreAllMocks());

  it('invokes wallet.sendSmart with the request the user made and returns what Rust answered', async () => {
    const invoke = jest.spyOn(bridge, 'routerInvokeBin').mockResolvedValue(
      framed({
        case: 'onlineTransferResponse',
        value: new pb.OnlineTransferResponse({ success: true, message: 'sent', newBalance: 90n }),
      }),
    );

    const res = await dsm.sendOnlineTransferSmart('alice', '10', 'lunch', 'RIGB');

    expect(res).toEqual({ success: true, message: 'sent', newBalance: 90n });
    expect(invoke).toHaveBeenCalledTimes(1);
    const [method, args] = invoke.mock.calls[0];
    expect(method).toBe('wallet.sendSmart');
    const req = pb.OnlineTransferSmartRequest.fromBinary(pb.ArgPack.fromBinary(args as Uint8Array).body);
    expect({ recipient: req.recipient, amount: req.amount, tokenId: req.tokenId, memo: req.memo }).toEqual({
      recipient: 'alice',
      amount: '10',
      tokenId: 'RIGB',
      memo: 'lunch',
    });
  });

  it("carries Rust's refusal of a send that names no token", async () => {
    const invoke = jest.spyOn(bridge, 'routerInvokeBin').mockResolvedValue(
      framed({ case: 'error', value: new pb.Error({ code: 1, message: 'wallet.sendSmart: the request names no token' }) }),
    );

    const res = await dsm.sendOnlineTransferSmart('alice', '10', undefined, '');

    const req = pb.OnlineTransferSmartRequest.fromBinary(
      pb.ArgPack.fromBinary(invoke.mock.calls[0][1] as Uint8Array).body,
    );
    expect(req.tokenId).toBe('');
    expect(res.success).toBe(false);
    expect(res.message).toContain('names no token');
  });
});
