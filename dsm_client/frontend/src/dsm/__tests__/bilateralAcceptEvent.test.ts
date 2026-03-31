/* eslint-disable @typescript-eslint/no-explicit-any */
import { acceptOfflineTransfer } from '../index';
import { acceptBilateralByCommitmentBridge } from '../WebViewBridge';
import * as pb from '../../proto/dsm_app_pb';

// Helper to wrap responses in DSM_BRIDGE format
function wrapSuccessEnvelope(data: Uint8Array): Uint8Array {
  return (global as any).createDsmBridgeSuccessResponse(data);
}

function frameEnvelope(envelope: pb.Envelope): Uint8Array {
  const bytes = envelope.toBinary();
  const framed = new Uint8Array(1 + bytes.length);
  framed[0] = 0x03;
  framed.set(bytes, 1);
  return framed;
}

describe('bilateral accept event dispatch', () => {
  beforeEach(() => {
    // Ensure no global DsmBridge left over
    (window as any).DsmBridge = {};
    jest.restoreAllMocks();
  });

  test('acceptOfflineTransfer dispatches dsm-bilateral-committed', async () => {
    const commitmentHash = new Uint8Array(32).fill(2);
    const counterpartyDeviceId = new Uint8Array(32).fill(3);
    const env = new pb.Envelope({
      version: 3,
      payload: { case: 'appStateResponse', value: new pb.AppStateResponse({ key: 'ok' }) },
    } as any);
    const framed = frameEnvelope(env);
    (window as any).DsmBridge = {
      __callBin: async (reqBytes: Uint8Array) => {
        const req = pb.BridgeRpcRequest.fromBinary(reqBytes);
        const method = req.method || '';
        const payload = req.payload?.case === 'bytes' ? req.payload.value.data : new Uint8Array(0);
        if (method === 'acceptBilateralByCommitment') {
          expect(payload).toBeInstanceOf(Uint8Array);
          expect(payload.length).toBe(32);
          return wrapSuccessEnvelope(framed);
        }
        throw new Error(`unhandled __callBin method: ${method}`);
      },
    };

    const handler = jest.fn();
    window.addEventListener('dsm-bilateral-committed', handler as EventListener, { once: true });

    await acceptOfflineTransfer({ commitmentHash, counterpartyDeviceId });

    expect(handler).toHaveBeenCalledTimes(1);
    const event = handler.mock.calls[0]?.[0] as CustomEvent | undefined;
    expect(event?.detail).toEqual(expect.objectContaining({
      accepted: true,
      committed: true,
      commitmentHash,
      counterpartyDeviceId,
    }));
  });

  test('acceptBilateralByCommitmentBridge rejects invalid payload size', async () => {
    (window as any).DsmBridge = {
      __callBin: async (_reqBytes: Uint8Array) => new Uint8Array([1]),
    };
    await expect(acceptBilateralByCommitmentBridge(new Uint8Array([1, 2, 3]))).rejects.toThrow(/must be 32 bytes/i);
  });
});
