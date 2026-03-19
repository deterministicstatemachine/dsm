import { getAllBalancesStrictBridge } from '../WebViewBridge';

function createSuccessResponse(data: Uint8Array): Uint8Array {
  // Build BridgeRpcResponse.success payload
  const pb = require('../../proto/dsm_app_pb');
  const br = new pb.BridgeRpcResponse({ result: { case: 'success', value: { data } } });
  return br.toBinary();
}

describe('getAllBalancesStrictBridge', () => {
  it('returns FramedEnvelopeV3 (0x03 + Envelope) from native getAllBalancesStrict()', async () => {
    // Check if global helper is available
    if (typeof (global as any).createDsmBridgeSuccessResponse !== 'function') {
      throw new Error('createDsmBridgeSuccessResponse not available');
    }

    const pb = require('../../proto/dsm_app_pb');

    // Create a real envelope payload (BalancesListResponse)
    const balancesList = new pb.BalancesListResponse({
      balances: [new pb.BalanceGetResponse({ tokenId: 'TEST', available: 100n, locked: 0n })]
    });
    
    // Wrap in Envelope v3
    const envelope = new pb.Envelope({
      version: 3, 
      payload: { case: 'balancesListResponse', value: balancesList }
    });
    const envelopeBytes = envelope.toBinary();

    // Create FramedEnvelopeV3 (0x03 + envelopeBytes)
    const framedData = new Uint8Array(1 + envelopeBytes.length);
    framedData[0] = 0x03;
    framedData.set(envelopeBytes, 1);

    // Mock the native bridge to return the framed data wrapped in BridgeRpcResponse
    (globalThis as any).window = (globalThis as any).window || {};
    (globalThis as any).window.DsmBridge = {
      // presence of __callBin signals BridgeGate to not block in tests
      __callBin: async (reqBytes: Uint8Array) => {
        const pb = require('../../proto/dsm_app_pb');
        const req = pb.BridgeRpcRequest.fromBinary(reqBytes);
        // Expect direct method call, NOT appRouterQuery
        if (req.method === 'getAllBalancesStrict') {
          return createSuccessResponse(framedData);
        }
        return createSuccessResponse(new Uint8Array(0));
      },
    };

    const res = await getAllBalancesStrictBridge();
    expect(res).toBeInstanceOf(Uint8Array);
    
    // The returned body should equal the framed data exactly (no stripping)
    expect(Array.from(res)).toEqual(Array.from(framedData));

    // cleanup
    delete (globalThis as any).window.DsmBridge;
  });
});
