// SPDX-License-Identifier: MIT OR Apache-2.0
//! Loading and unloading offline cash carries the user's text to Rust and
//! Rust's rendered balances back; anything but Rust's answer is an error.

jest.mock('../WebViewBridge', () => ({ routerInvokeBin: jest.fn() }));

import * as pb from '../../proto/dsm_app_pb';
import { loadOfflineCash, unloadOfflineCash } from '../offlineCash';
import { routerInvokeBin } from '../WebViewBridge';

function framed(payload: any): Uint8Array {
  const bytes = new pb.Envelope({ version: 3, payload }).toBinary();
  const out = new Uint8Array(1 + bytes.length);
  out[0] = 0x03;
  out.set(bytes, 1);
  return out;
}

const moved = (message: string, online: string, allocation: string) =>
  framed({
    case: 'offlineCashResponse',
    value: new pb.OfflineCashResponse({
      success: true,
      onlineBalance: 8500n,
      allocationBalance: 1500n,
      onlineDisplay: online,
      allocationDisplay: allocation,
      message,
    }),
  });

describe('offline cash', () => {
  beforeEach(() => jest.clearAllMocks());

  it('sends the token and the amount as typed, and returns what Rust rendered', async () => {
    (routerInvokeBin as jest.Mock).mockResolvedValue(moved('loaded 5.00 ERA — offline allocation now 15.00, online 85.00', '85.00', '15.00'));
    const res = await loadOfflineCash('ERA', ' 5 ');
    expect(res).toEqual({ onlineDisplay: '85.00', allocationDisplay: '15.00', message: expect.stringContaining('loaded 5.00 ERA') });
    const [method, args] = (routerInvokeBin as jest.Mock).mock.calls[0];
    expect(method).toBe('wallet.loadOffline');
    const pack = pb.ArgPack.fromBinary(args);
    expect(pack.codec).toBe(pb.Codec.PROTO);
    const req = pb.OfflineCashRequest.fromBinary(pack.body);
    expect([req.tokenId, req.amount]).toEqual(['ERA', '5']);
  });

  it('unload goes to wallet.unloadOffline', async () => {
    (routerInvokeBin as jest.Mock).mockResolvedValue(moved('unloaded 5.00 ERA — offline allocation now 5.00, online 95.00', '95.00', '5.00'));
    await unloadOfflineCash('ERA', '5');
    expect((routerInvokeBin as jest.Mock).mock.calls[0][0]).toBe('wallet.unloadOffline');
  });

  it("throws Rust's refusal in Rust's words", async () => {
    (routerInvokeBin as jest.Mock).mockResolvedValue(
      framed({ case: 'error', value: new pb.Error({ code: 7, message: 'wallet.loadOffline: connect your anchor device to manage offline cash' }) }),
    );
    await expect(loadOfflineCash('ERA', '5')).rejects.toThrow(/connect your anchor device/);
  });

  it('refuses an answer that is not the move', async () => {
    (routerInvokeBin as jest.Mock).mockResolvedValue(
      framed({ case: 'bilateralPrepareResponse', value: new pb.BilateralPrepareResponse({}) }),
    );
    await expect(loadOfflineCash('ERA', '5')).rejects.toThrow(/not offlineCashResponse/);
  });

  it('refuses an answer without its rendered balances', async () => {
    (routerInvokeBin as jest.Mock).mockResolvedValue(moved('moved', '', ''));
    await expect(loadOfflineCash('ERA', '5')).rejects.toThrow(/STRICT/);
  });
});
