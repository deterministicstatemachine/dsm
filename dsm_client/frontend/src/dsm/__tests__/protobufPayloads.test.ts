// SPDX-License-Identifier: MIT OR Apache-2.0

import {
  createGenesisViaRouter,
  rejectBilateralByCommitmentBridge,
} from "../WebViewBridge";
import {
  BilateralPayload,
  BridgeRpcRequest,
  BridgeRpcResponse,
  Envelope,
  GenesisCreated,
  Hash32,
  WalletCreateGenesisV2Request,
} from "../../proto/dsm_app_pb";

function wrapSuccessEnvelope(data: Uint8Array): Uint8Array {
  const br = new BridgeRpcResponse({ result: { case: "success", value: { data: new Uint8Array(data) } } });
  return br.toBinary();
}

function setupBridge(onRequest: (req: BridgeRpcRequest) => void): void {
  (global as any).window = (global as any).window ?? {};
  (global as any).window.DsmBridge = {
    sendMessageBin: async (reqBytes: Uint8Array) => {
      const req = BridgeRpcRequest.fromBinary(reqBytes);
      onRequest(req);
      return wrapSuccessEnvelope(new Uint8Array([1]));
    },
  };
}

describe("protobuf-only bridge payloads", () => {
  test("createGenesisViaRouter sends one mnemonic-rooted Genesis v2 request", async () => {
    const seenRequests: BridgeRpcRequest[] = [];
    const deviceId = new Uint8Array(32).fill(0x11);
    const genesisHash = new Uint8Array(32).fill(0x22);
    const mnemonic =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const genesisEnvelope = new Envelope({
      version: 3,
      payload: {
        case: "genesisCreatedResponse",
        value: new GenesisCreated({
          deviceId,
          genesisHash: new Hash32({ v: genesisHash }),
          genesisNonce: new Uint8Array(32).fill(0x33),
          networkId: "testnet",
        }),
      },
    });
    const framedGenesisEnvelope = new Uint8Array([0x03, ...genesisEnvelope.toBinary()]);
    (global as any).window = (global as any).window ?? {};
    (global as any).window.DsmBridge = {
      sendMessageBin: async (reqBytes: Uint8Array) => {
        const req = BridgeRpcRequest.fromBinary(reqBytes);
        seenRequests.push(req);
        if (req.method === "createGenesisV2") {
          return wrapSuccessEnvelope(framedGenesisEnvelope);
        }
        return wrapSuccessEnvelope(new Uint8Array([1]));
      },
    };

    await createGenesisViaRouter(mnemonic);

    expect(seenRequests).toHaveLength(1);
    expect(seenRequests[0].method).toBe("createGenesisV2");
    const payload = seenRequests[0].payload;
    expect(payload.case).toBe("bytes");
    if (payload.case !== "bytes") throw new Error("expected a bytes payload");
    const decoded = WalletCreateGenesisV2Request.fromBinary(payload.value.data);
    expect(decoded.mnemonic).toBe(mnemonic);
    // The network is the SDK's to choose; the request names none.
    expect(WalletCreateGenesisV2Request.fields.findJsonName("networkId")).toBeUndefined();
    // No silicon / no random entropy: the mnemonic is the sole genesis root.
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
