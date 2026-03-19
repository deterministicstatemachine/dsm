import { sendOnlineTransfer } from '../index';
import { encodeBase32Crockford as base32CrockfordEncode } from '../../utils/textId';

function bytes32(fill = 0x11): Uint8Array {
  return new Uint8Array(32).fill(fill);
}

// Helper to wrap response in DSM_BRIDGE format
function wrapSuccessEnvelope(data: Uint8Array): Uint8Array {
  return (global as any).createDsmBridgeSuccessResponse(data);
}

const headersBytes = () =>
  new (require('../../proto/dsm_app_pb').Headers)({
    deviceId: bytes32(0x01) as any,
    genesisHash: bytes32(0x02) as any,
    chainTip: bytes32(0x03) as any,
    seq: BigInt(1) as any,
  }).toBinary();

describe('sendOnlineTransfer input validation', () => {
  let logSpy: jest.SpyInstance;

  beforeEach(() => {
    logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    // Minimal deterministic bridge stubs
    (global as any).window = (global as any).window ?? ({} as any);
    // Also attach to globalThis.window for code paths that reference it.
    (globalThis as any).window = (global as any).window;
    const win: any = (global as any).window;
    win.DsmBridge = {
      hasIdentityDirect: jest.fn().mockReturnValue(true),
      // Identity/header sources used by getHeaders()/getTransportHeadersV3Bin.
      getDeviceIdBin: jest.fn().mockReturnValue(base32CrockfordEncode(bytes32(0x01))),
      getGenesisHashBin: jest.fn().mockReturnValue(base32CrockfordEncode(bytes32(0x02))),
      getTransportHeadersV3Bin: jest.fn().mockReturnValue(headersBytes()),
      // bytes-only router hook used by WebViewBridge.callBin in tests.
      __callBin: jest.fn(async (reqBytes: Uint8Array) => {
        const pb = require('../../proto/dsm_app_pb');
        const req = pb.BridgeRpcRequest.fromBinary(reqBytes);
        if (req.method === 'getTransportHeadersV3Bin') return wrapSuccessEnvelope(headersBytes());
        return wrapSuccessEnvelope(new Uint8Array(0));
      }),
    };
  });

  afterEach(() => {
    logSpy.mockRestore();
  });

  test('rejects toDeviceId when not Uint8Array', async () => {
    const res = await sendOnlineTransfer({
      // @ts-expect-error intentional
      to: 'BASE32_OR_HEX_STRING',
      amount: 1n,
      tokenId: 'ERA',
      memo: '',
    });

    expect(res.accepted).toBe(false);
    expect(String(res.result)).toMatch(/32 bytes|Invalid|decode/i);
    expect((window as any).DsmBridge.__callBin).not.toHaveBeenCalled();
  });

  test('rejects toDeviceId when not 32 bytes', async () => {
    const res = await sendOnlineTransfer({
      to: new Uint8Array(31),
      amount: 1n,
      tokenId: 'ERA',
      memo: '',
    });

    expect(res.accepted).toBe(false);
    expect(String(res.result)).toMatch(/32 bytes/i);
    expect((window as any).DsmBridge.__callBin).not.toHaveBeenCalled();
  });

  test('accepts 32-byte Uint8Array (validation passes)', async () => {
    const res = await sendOnlineTransfer({
      to: bytes32(0x22),
      amount: 1n,
      tokenId: 'ERA',
      memo: '',
    });

    // Validation passed. Bridge is stubbed, so acceptance is not asserted here;
    // we only assert we did not fail 32-byte validation.
    expect(String(res.result ?? '')).not.toMatch(/device_id must be 32 bytes/i);
    expect((window as any).DsmBridge.__callBin).toHaveBeenCalled();
  });
});
