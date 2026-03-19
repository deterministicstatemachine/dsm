import * as dsm from '../dsm/index';
import * as pb from '../proto/dsm_app_pb';

// Helper to wrap response in DSM_BRIDGE format
function wrapSuccessEnvelope(data: Uint8Array): Uint8Array {
  // Create framed envelope: 0x03 + data
  const framingByte = new Uint8Array([0x03]);
  const framed = new Uint8Array(framingByte.length + data.length);
  framed.set(framingByte, 0);
  framed.set(data, framingByte.length);

  // Return BridgeRpcResponse with framed envelope as data
  const br = new pb.BridgeRpcResponse({
    result: { case: 'success', value: { data: framed } }
  });
  return br.toBinary();
}

function wrapSuccessRaw(data: Uint8Array): Uint8Array {
  // Return BridgeRpcResponse with raw data (for direct bridge methods)
  const br = new pb.BridgeRpcResponse({
    result: { case: 'success', value: { data } }
  });
  return br.toBinary();
}

/** Build a framed Envelope with onlineTransferResponse payload (matches new appRouter path) */
function makeOnlineResponseFramed(success: boolean, message: string, newBalance: bigint = 1n): Uint8Array {
  const txHash = new pb.Hash32({ v: new Uint8Array(32) });
  const resp = new pb.OnlineTransferResponse({
    success,
    transactionHash: txHash,
    message,
    newBalance: newBalance as any,
  } as any);
  const envelope = new pb.Envelope({
    version: 3,
    payload: { case: 'onlineTransferResponse', value: resp },
  } as any);
  const envBytes = envelope.toBinary();
  const framed = new Uint8Array(1 + envBytes.length);
  framed[0] = 0x03;
  framed.set(envBytes, 1);
  return framed;
}

describe('E2E: sendOnlineTransfer (unit-level, mocked storage)', () => {
  beforeEach(() => {
    jest.restoreAllMocks();
    // Provide a simple bridge with device identity getters and minimal hooks
    (global as any).window = (global as any).window || {};
    (global as any).window.DsmBridge = (global as any).window.DsmBridge || {};

    // Bytes-only MessagePort bridge contract (required by WebViewBridge.callBin)
    (global as any).window.DsmBridge.__binary = true;
    (global as any).window.DsmBridge.sendMessageBin = (global as any).window.DsmBridge.sendMessageBin || (async () => new Uint8Array(0));

    // Mock the bytes-only router calls
    (global as any).window.DsmBridge.__callBin = async (reqBytes: Uint8Array) => {
      const req = pb.BridgeRpcRequest.fromBinary(reqBytes);
      const method = req.method || '';

      if (method === 'getTransportHeadersV3Bin') {
        const headers = new pb.Headers({
          deviceId: new Uint8Array(32).fill(0x11),
          chainTip: new Uint8Array(32).fill(0xff),
          genesisHash: new Uint8Array(32).fill(0x11),
          seq: 1n as any
        } as any);
        return wrapSuccessRaw(headers.toBinary());
      }

      if (method === 'appRouterInvoke') {
        // For these tests, we'll mock appRouterInvokeBin directly
        return wrapSuccessEnvelope(new Uint8Array(0));
      }

      return wrapSuccessEnvelope(new Uint8Array(0));
    };
  });

  it('sendOnlineTransfer succeeds via appRouterInvoke wallet.send (bytes-only)', async () => {
    const devB = new Uint8Array(32).fill(0x22);

    // Mock appRouterInvokeBin to return framed Envelope with onlineTransferResponse
    const mockAppRouterInvoke = jest.fn().mockResolvedValue(makeOnlineResponseFramed(true, 'ok', 1n));
    jest.spyOn(require('../dsm/WebViewBridge'), 'appRouterInvokeBin').mockImplementation(mockAppRouterInvoke);

    // Run sendOnlineTransfer
    const res = await dsm.sendOnlineTransfer({ to: devB, amount: 1n, tokenId: 'ERA' });
    expect(res.accepted).toBe(true);
    expect(res.newBalance).toBe(1n);
    // Verify it called appRouterInvokeBin with 'wallet.send'
    expect(mockAppRouterInvoke).toHaveBeenCalledWith('wallet.send', expect.any(Uint8Array));
  });

  // Quorum/fan-out is handled by native persistence.

  it('error response: native reports failure and sendOnlineTransfer returns accepted=false', async () => {
    const devB = new Uint8Array(32).fill(0x22);

    // Mock appRouterInvokeBin to return framed Envelope with failed OnlineTransferResponse
    const mockAppRouterInvoke = jest.fn().mockResolvedValue(makeOnlineResponseFramed(false, 'insufficient funds', 0n));
    jest.spyOn(require('../dsm/WebViewBridge'), 'appRouterInvokeBin').mockImplementation(mockAppRouterInvoke);

    const res = await (dsm as any).sendOnlineTransfer({ to: devB, amount: 2n, tokenId: 'ERA' });
    expect(res.accepted).toBe(false);
    expect(String(res.result || '')).toContain('insufficient funds');
  });
});
