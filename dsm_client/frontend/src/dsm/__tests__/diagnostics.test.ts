// SPDX-License-Identifier: MIT OR Apache-2.0

/* eslint-disable @typescript-eslint/no-explicit-any */
import { ArchitectureInfoProto, BridgeRpcRequest, BridgeRpcResponse, ErrorResponse, Headers } from '../../proto/dsm_app_pb';
import { getArchitectureInfo, getDeviceIdBinBridgeAsync } from '../WebViewBridge/diagnostics';

function success(data: Uint8Array): Uint8Array {
  return new BridgeRpcResponse({ result: { case: 'success', value: { data: new Uint8Array(data) } } }).toBinary();
}

function failure(message: string): Uint8Array {
  return new BridgeRpcResponse({
    result: { case: 'error', value: new ErrorResponse({ errorCode: 1, message }) },
  }).toBinary();
}

/** The native bridge answering `answers[method]` (bytes) over the real transport. */
function installBridge(answers: Record<string, () => Uint8Array>): void {
  (global as any).window.DsmBridge = {
    __callBin: async (reqBytes: Uint8Array) => {
      const method = BridgeRpcRequest.fromBinary(reqBytes).method;
      const answer = answers[method];
      if (!answer) throw new Error(`unexpected bridge method ${method}`);
      return answer();
    },
  };
}

describe('getArchitectureInfo', () => {
  test('answers the measurement the native checker made', async () => {
    installBridge({
      getArchitectureInfo: () => success(new ArchitectureInfoProto({
        status: 'UNSUPPORTED_ABI', deviceArch: 'x86', supportedAbis: 'x86', message: 'unsupported', recommendation: 'use arm64',
      }).toBinary()),
    });
    await expect(getArchitectureInfo()).resolves.toEqual({
      status: 'UNSUPPORTED_ABI', deviceArch: 'x86', supportedAbis: 'x86', message: 'unsupported', recommendation: 'use arm64',
    });
  });

  // "UNKNOWN" / "unavailable" was the answer both layers invented on failure.
  test('an answer that is not a measured status is refused, never shown as a status', async () => {
    installBridge({
      getArchitectureInfo: () => success(new ArchitectureInfoProto({
        status: 'UNKNOWN', deviceArch: 'unavailable', message: 'Architecture check error',
      }).toBinary()),
    });
    await expect(getArchitectureInfo()).rejects.toThrow('STRICT');

    installBridge({ getArchitectureInfo: () => success(new Uint8Array(0)) });
    await expect(getArchitectureInfo()).rejects.toThrow('no bytes');
  });

  test('a bridge failure is the failure, not a status', async () => {
    installBridge({ getArchitectureInfo: () => failure('Architecture check threw') });
    await expect(getArchitectureInfo()).rejects.toThrow(/Architecture check threw/);
  });
});

describe('getDeviceIdBinBridgeAsync', () => {
  test('answers the 32-byte device id Rust’s headers carry, and refuses any other length', async () => {
    const deviceId = new Uint8Array(32).fill(7);
    installBridge({ getTransportHeadersV3Bin: () => success(new Headers({ deviceId }).toBinary()) });
    await expect(getDeviceIdBinBridgeAsync()).resolves.toEqual(deviceId);

    installBridge({ getTransportHeadersV3Bin: () => success(new Headers({}).toBinary()) });
    await expect(getDeviceIdBinBridgeAsync()).rejects.toThrow('0-byte device id');
  });
});
