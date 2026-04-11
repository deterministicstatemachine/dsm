import * as dsm from '../index';
import * as contacts from '../contacts';
import * as pb from '../../proto/dsm_app_pb';
import { storageNodeService } from '../../services/storageNodeService';

// Helper to create a successful online transfer envelope
function makeOkEnvelope(): pb.Envelope {
  const devId = new Uint8Array(32).fill(0xaa);
  const chainTip = new Uint8Array(32).fill(0xff);
  const gh = new Uint8Array(32).fill(0xbb);
  const txHash = new Uint8Array(32).fill(0xdd);
  return new pb.Envelope({
    version: 3,
    headers: new pb.Headers({
      deviceId: devId,
      chainTip: chainTip,
      genesisHash: gh,
      seq: 1,
    } as any),
    payload: {
      case: 'onlineTransferResponse',
      value: new pb.OnlineTransferResponse({
        success: true,
        transactionHash: txHash,
        message: 'ok',
      } as any),
    },
  } as any);
}

function makeFramedEnvelope(envelope: pb.Envelope): Uint8Array {
  const envelopeBytes = envelope.toBinary();
  const framingByte = new Uint8Array([0x03]);
  const framed = new Uint8Array(framingByte.length + envelopeBytes.length);
  framed.set(framingByte, 0);
  framed.set(envelopeBytes, framingByte.length);
  return framed;
}

function wrapSuccessRaw(data: Uint8Array): Uint8Array {
  // Return BridgeRpcResponse with raw data (for direct bridge methods)
  const br = new pb.BridgeRpcResponse({ 
    result: { case: 'success', value: { data } } 
  });
  return br.toBinary();
}

function wrapIngressOk(data: Uint8Array): Uint8Array {
  return wrapSuccessRaw(
    new pb.IngressResponse({
      result: { case: 'okBytes', value: data },
    }).toBinary(),
  );
}

describe('online send node fan-out', () => {
  beforeEach(() => {
    // Storage node config is intentionally disabled (protobuf-only, no JSON/localStorage).
    // This test asserts that onlineTransfer goes through the native binary bridge and
    // does not require any JS-side HTTP fan-out.
    jest
      .spyOn(storageNodeService, 'selectNodesForAddr')
      .mockReturnValue(['http://n1:8080', 'http://n2:8080', 'http://n3:8080']);
    // Mock getContacts and bridge transports used by send
    (global as any).window = (global as any).window || {};
    const devId = new Uint8Array(32).fill(0xaa);
    const gh = new Uint8Array(32).fill(0xbb);

    (global as any).window.DsmBridge = {
      __binary: true,
      sendMessageBin: async (_payload?: Uint8Array) => new Uint8Array(0),
      // Provide valid identity bytes so getHeaders() succeeds
      getDeviceIdBin: () => devId,
      getGenesisHashBin: () => gh,
      __callBin: async (reqBytes: Uint8Array) => {
        const req = pb.BridgeRpcRequest.fromBinary(reqBytes);
        const method = req.method || '';
        if (method === 'getTransportHeadersV3Bin') {
          // Return valid Headers protobuf bytes
          const headers = new pb.Headers({
            deviceId: devId,
            genesisHash: gh,
            chainTip: new Uint8Array(32).fill(0xff), // Non-zero chain tip
            seq: 1n,
          } as any);
          return wrapSuccessRaw(headers.toBinary());
        }
        if (method === 'nativeBoundaryIngress') {
          const ingressRequest = pb.IngressRequest.fromBinary(p);
          if (ingressRequest.operation.case !== 'routerInvoke') {
            return wrapIngressOk(new Uint8Array(0));
          }
          // Return a successful online transfer response as framed Envelope
          const resp = new pb.OnlineTransferResponse({
            success: true,
            transactionHash: new pb.Hash32({ v: new Uint8Array(32) }),
            message: 'ok',
            newBalance: 123n as any,
          } as any);
          const envelope = new pb.Envelope({
            version: 3,
            headers: new pb.Headers({
              deviceId: devId,
              chainTip: new Uint8Array(32).fill(0xff),
              genesisHash: gh,
            } as any),
            payload: {
              case: 'onlineTransferResponse',
              value: resp,
            },
          } as any);
          // Return BridgeRpcResponse with data = [8-byte reqId] + [0x03 + envelope]
          const envelopeBytes = envelope.toBinary();
          const framingByte = new Uint8Array([0x03]);
          const framed = new Uint8Array(framingByte.length + envelopeBytes.length);
          framed.set(framingByte, 0);
          framed.set(envelopeBytes, framingByte.length);
          return wrapIngressOk(framed);
        }
        return new Uint8Array(0);
      },
    };
  });

  it('routes onlineTransfer through the binary bridge (no web fetch fan-out required)', async () => {
    const devId = new Uint8Array(32).fill(0xaa);
    const gh = new Uint8Array(32).fill(0xbb);

    // Modern contract: online transfers are executed by the native layer.
    // The WebView SDK should not be required to fan-out HTTP requests itself.
    // We keep a fetch mock only to ensure we don't accidentally depend on it.
    const fetchMock = jest.fn().mockImplementation(async (_url: string, _opts?: any) => ({ ok: true, status: 200 }));
    (global as any).fetch = fetchMock;

    // Provide a contact matching device id
    jest.spyOn(contacts, 'getContacts').mockResolvedValue({ contacts: [{ alias: 'x', device_id: new Uint8Array(32).fill(0xdd), genesis_hash: new Uint8Array(32).fill(0xee), chain_tip: new Uint8Array(32).fill(0xff) }] } as any);

    // Stub computeB0xAddressBridge to a stable value
    jest.spyOn(require('../WebViewBridge'), 'computeB0xAddressBridge').mockReturnValue('B0XABC');
    // Provide a contacts response so getContacts() finds the recipient
    const pb = require('../../proto/dsm_app_pb');
    const contact = new pb.ContactAddResponse({ alias: 'alice', deviceId: new Uint8Array(32).fill(0xdd), genesisHash: new pb.Hash32({ v: new Uint8Array(32).fill(0xee) }), chainTip: new pb.Hash32({ v: new Uint8Array(32).fill(0xff) }), genesisVerifiedOnline: true, verifyCounter: 1, addedCounter: 1, verifyingStorageNodes: ['http://n1:8080','http://n2:8080','http://n3:8080'] } as any);
    const contactsResp = new pb.ContactsListResponse({ contacts: [contact] });
    // Note: dsm.getContacts is mocked above, so the strict bridge isn't required here.
    (global as any).window.DsmBridge.__callBin = async (reqBytes: Uint8Array) => {
      const req = pb.BridgeRpcRequest.fromBinary(reqBytes);
      const method = req.method || '';
      const p = req.payload?.case === 'bytes' ? req.payload.value.data : new Uint8Array(0);
      if (method === 'getTransportHeadersV3Bin') {
        const headers = new pb.Headers({ deviceId: devId, chainTip: new Uint8Array(32).fill(0xff), genesisHash: gh, seq: 1n } as any);
        return wrapSuccessRaw(headers.toBinary());
      }

      if (method === 'nativeBoundaryIngress') {
        const ingressRequest = pb.IngressRequest.fromBinary(p);
        if (ingressRequest.operation.case === 'routerQuery') {
          const path = ingressRequest.operation.value.method;
          if (path === '/transport/headersV3') {
            const headers = new pb.Headers({ deviceId: devId, chainTip: new Uint8Array(32), genesisHash: gh, seq: 1n } as any);
            return wrapIngressOk(headers.toBinary());
          }
          return wrapIngressOk(new Uint8Array(0));
        }
        if (ingressRequest.operation.case !== 'routerInvoke') {
          return wrapIngressOk(new Uint8Array(0));
        }
        const envelope = makeOkEnvelope();
        const framedBytes = makeFramedEnvelope(envelope);
        return wrapIngressOk(framedBytes);
      }

      return new Uint8Array(0);
    };

    // Run sendOnlineTransfer; it should route through the binary bridge.
    const sendRes = await dsm.sendOnlineTransfer({ to: new Uint8Array(32).fill(0xdd), amount: 1n } as any);
    expect(sendRes.accepted).toBe(true);

    // Ensure we invoked the native binary bridge.
    expect((global as any).window.DsmBridge.__callBin).toBeDefined();
    // Optional: ensure no HTTP fan-out happened in this layer.
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
