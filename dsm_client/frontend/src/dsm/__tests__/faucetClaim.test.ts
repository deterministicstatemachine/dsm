// SPDX-License-Identifier: MIT OR Apache-2.0
//! faucet.claim reports what Rust released, in its words, or why not.
//!
//! The client used to answer "Faucet claim ok" in place of Rust's message,
//! a constant `humanScaled: true`, a received count of 0 on every failure,
//! and debug bytes invented on an exception.

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

describe('claimFaucet', () => {
  beforeEach(() => {
    jest.spyOn(bridge, 'getDeviceIdBinBridgeAsync').mockResolvedValue(new Uint8Array(32).fill(0x11));
  });
  afterEach(() => jest.restoreAllMocks());

  it('claims for this device and reports what Rust released, in its words', async () => {
    const invoke = jest.spyOn(bridge, 'routerInvokeBin').mockResolvedValue(
      framed({
        case: 'faucetClaimResponse',
        value: new pb.FaucetClaimResponse({
          success: true,
          tokensReceived: 100n,
          message: 'claimed 100 ERA (economic position 3)',
        }),
      }),
    );

    const res = await dsm.claimFaucet();

    expect(res).toEqual({ success: true, tokensReceived: 100n, message: 'claimed 100 ERA (economic position 3)' });
    const [method, args] = invoke.mock.calls[0];
    expect(method).toBe('faucet.claim');
    const req = pb.FaucetClaimRequest.fromBinary(pb.ArgPack.fromBinary(args as Uint8Array).body);
    expect(Array.from(req.deviceId)).toEqual(Array.from(new Uint8Array(32).fill(0x11)));
  });

  it("carries Rust's refusal and counts nothing", async () => {
    jest.spyOn(bridge, 'routerInvokeBin').mockResolvedValue(
      framed({ case: 'error', value: new pb.Error({ code: 1, message: 'faucet.claim: the reserve is spent' }) }),
    );

    expect(await dsm.claimFaucet()).toEqual({ success: false, message: 'faucet.claim: the reserve is spent' });
  });

  it('an answer that is not a claim is not a success', async () => {
    jest.spyOn(bridge, 'routerInvokeBin').mockResolvedValue(
      framed({ case: 'appStateResponse', value: new pb.AppStateResponse({ key: 'ok' }) }),
    );

    const res = await dsm.claimFaucet();
    expect(res.success).toBe(false);
  });
});
