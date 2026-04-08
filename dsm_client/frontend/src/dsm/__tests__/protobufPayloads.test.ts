import { createGenesisBin, setBleIdentityForAdvertising, rejectBilateralByCommitmentBridge } from '../WebViewBridge';
import {
  AppRouterPayload,
  ArgPack,
  BilateralPayload,
  BleIdentityPayload,
  BridgeRpcRequest,
  BridgeRpcResponse,
  Codec,
  DeviceBindingCapturePayload,
  DeviceBindingCaptureResult,
  Envelope,
  GenesisCreated,
  Hash32,
  IngressRequest,
  IngressResponse,
  NativeHostRequest,
  NativeHostRequestKind,
  NativeHostResponse,
  SystemGenesisRequest,
} from '../../proto/dsm_app_pb';

function wrapSuccessEnvelope(data: Uint8Array): Uint8Array {
  const br = new BridgeRpcResponse({ result: { case: 'success', value: { data } } });
  return br.toBinary();
}

function setupBridge(onRequest: (req: BridgeRpcRequest) => void): void {
  (global as any).window = (global as any).window ?? {};
  (global as any).window.DsmBridge = {
    __callBin: async (reqBytes: Uint8Array) => {
      const req = BridgeRpcRequest.fromBinary(reqBytes);
      onRequest(req);
      return wrapSuccessEnvelope(new Uint8Array([1]));
    },
  };
}

describe('protobuf-only bridge payloads', () => {
  test('createGenesisBin sends system.genesis query and native host device-binding capture', async () => {
    const seenRequests: BridgeRpcRequest[] = [];
    const deviceId = new Uint8Array(32).fill(0x11);
    const genesisHash = new Uint8Array(32).fill(0x22);
    const entropy = new Uint8Array(32).fill(7);
    const genesisEnvelope = new Envelope({
      version: 3,
      payload: {
        case: 'genesisCreatedResponse',
        value: new GenesisCreated({
          deviceId,
          genesisHash: new Hash32({ v: genesisHash }),
          deviceEntropy: entropy,
          networkId: 'testnet',
          locale: 'en-US',
        }),
      },
    });
    const framedGenesisEnvelope = new Uint8Array([0x03, ...genesisEnvelope.toBinary()]);
    (global as any).window = (global as any).window ?? {};
    (global as any).window.DsmBridge = {
      __callBin: async (reqBytes: Uint8Array) => {
        const req = BridgeRpcRequest.fromBinary(reqBytes);
        seenRequests.push(req);
        if (req.method === 'nativeBoundaryIngress') {
          return wrapSuccessEnvelope(
            new IngressResponse({
              result: {
                case: 'okBytes',
                value: framedGenesisEnvelope,
              },
            }).toBinary(),
          );
        }
        if (req.method === 'nativeHostRequest') {
          const result = new DeviceBindingCaptureResult({
            installed: true,
            deviceId,
            genesisHash,
          });
          return wrapSuccessEnvelope(
            new NativeHostResponse({
              result: {
                case: 'okBytes',
                value: result.toBinary(),
              },
            }).toBinary(),
          );
        }
        return wrapSuccessEnvelope(new Uint8Array([1]));
      },
    };

    await createGenesisBin('en-US', 'testnet', entropy);

    expect(seenRequests).toHaveLength(2);
    expect(seenRequests[0].method).toBe('nativeBoundaryIngress');
    expect(seenRequests[0].payload.case).toBe('bytes');
    const ingressRequest = IngressRequest.fromBinary(seenRequests[0].payload.value.data);
    expect(ingressRequest.operation.case).toBe('routerQuery');
    const seenRouterPayload = ingressRequest.operation.value;
    expect(seenRouterPayload.method).toBe('system.genesis');

    const argPack = ArgPack.fromBinary(seenRouterPayload.args);
    expect(argPack.codec).toBe(Codec.PROTO);
    const decoded = SystemGenesisRequest.fromBinary(argPack.body);
    expect(decoded.locale).toBe('en-US');
    expect(decoded.networkId).toBe('testnet');
    expect(decoded.deviceEntropy).toEqual(entropy);

    expect(seenRequests[1].method).toBe('nativeHostRequest');
    expect(seenRequests[1].payload.case).toBe('bytes');
    const hostRequest = NativeHostRequest.fromBinary(seenRequests[1].payload.value.data);
    expect(hostRequest.kind).toBe(
      NativeHostRequestKind.PLATFORM_PRIMITIVE_DEVICE_BINDING_CAPTURE,
    );
    const deviceBindingPayload = DeviceBindingCapturePayload.fromBinary(hostRequest.payload);
    expect(deviceBindingPayload.genesisEnvelope).toEqual(framedGenesisEnvelope);
  });

  test('setBleIdentityForAdvertising sends BleIdentityPayload', async () => {
    let seenMethod = '';
    let seenPayload: Uint8Array | undefined;

    setupBridge((req) => {
      seenMethod = req.method;
      seenPayload = req.payload.case === 'bytes' ? req.payload.value.data : new Uint8Array(0);
    });

    const genesis = new Uint8Array(32).fill(0xaa);
    const deviceId = new Uint8Array(32).fill(0xbb);
    await setBleIdentityForAdvertising(genesis, deviceId);

    expect(seenMethod).toBe('setBleIdentityForAdvertising');
    expect(seenPayload).toBeInstanceOf(Uint8Array);

    const decoded = BleIdentityPayload.fromBinary(seenPayload as Uint8Array);
    expect(decoded.genesisHash).toEqual(genesis);
    expect(decoded.deviceId).toEqual(deviceId);
  });

  test('rejectBilateralByCommitmentBridge sends BilateralPayload', async () => {
    let seenMethod = '';
    let seenPayload: BilateralPayload | undefined;

    setupBridge((req) => {
      seenMethod = req.method;
      seenPayload = req.payload.case === 'bilateral' ? req.payload.value : undefined;
    });

    const commitment = new Uint8Array(32).fill(0x11);
    const reason = 'nope';
    await rejectBilateralByCommitmentBridge(commitment, reason);

    expect(seenMethod).toBe('rejectBilateralByCommitment');
    expect(seenPayload).toBeInstanceOf(BilateralPayload);
    expect(seenPayload?.commitment).toEqual(commitment);
    expect(seenPayload?.reason).toBe(reason);
  });
});
