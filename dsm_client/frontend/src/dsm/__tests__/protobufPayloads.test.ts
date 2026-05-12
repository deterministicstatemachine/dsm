import { setBleIdentityForAdvertising, rejectBilateralByCommitmentBridge } from "../WebViewBridge";
import {
  BilateralPayload,
  BleIdentityPayload,
  BridgeRpcRequest,
  BridgeRpcResponse,
} from "../../proto/dsm_app_pb";

function wrapSuccessEnvelope(data: Uint8Array): Uint8Array {
  const br = new BridgeRpcResponse({ result: { case: "success", value: { data } } });
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

describe("protobuf-only bridge payloads", () => {
  test("setBleIdentityForAdvertising sends BleIdentityPayload", async () => {
    let seenMethod = "";
    let seenPayload: Uint8Array | undefined;

    setupBridge((req) => {
      seenMethod = req.method;
      seenPayload = req.payload.case === "bytes" ? req.payload.value.data : new Uint8Array(0);
    });

    const genesis = new Uint8Array(32).fill(0xaa);
    const deviceId = new Uint8Array(32).fill(0xbb);
    await setBleIdentityForAdvertising(genesis, deviceId);

    expect(seenMethod).toBe("setBleIdentityForAdvertising");
    expect(seenPayload).toBeInstanceOf(Uint8Array);

    const decoded = BleIdentityPayload.fromBinary(seenPayload as Uint8Array);
    expect(decoded.genesisHash).toEqual(genesis);
    expect(decoded.deviceId).toEqual(deviceId);
  });

  test("rejectBilateralByCommitmentBridge sends BilateralPayload", async () => {
    let seenMethod = "";
    let seenPayload: BilateralPayload | undefined;

    setupBridge((req) => {
      seenMethod = req.method;
      seenPayload = req.payload.case === "bilateral" ? req.payload.value : undefined;
    });

    const commitment = new Uint8Array(32).fill(0x11);
    const reason = "nope";
    await rejectBilateralByCommitmentBridge(commitment, reason);

    expect(seenMethod).toBe("rejectBilateralByCommitment");
    expect(seenPayload).toBeInstanceOf(BilateralPayload);
    expect(seenPayload?.commitment).toEqual(commitment);
    expect(seenPayload?.reason).toBe(reason);
  });
});
