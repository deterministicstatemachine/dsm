// SPDX-License-Identifier: MIT OR Apache-2.0

import {
  createGenesisViaRouter,
  rejectBilateralByCommitmentBridge,
  setBleIdentityForAdvertising,
} from "../WebViewBridge";
import {
  BilateralPayload,
  BleIdentityPayload,
  BridgeRpcRequest,
  BridgeRpcResponse,
  Envelope,
  GenesisCreated,
  Hash32,
  WalletCreateGenesisV2Request,
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
          deviceEntropy: new Uint8Array(32).fill(0x33), // v2: carries the PUBLIC genesis_nonce
          networkId: "testnet",
          locale: "en-US",
        }),
      },
    });
    const framedGenesisEnvelope = new Uint8Array([0x03, ...genesisEnvelope.toBinary()]);
    (global as any).window = (global as any).window ?? {};
    (global as any).window.DsmBridge = {
      __callBin: async (reqBytes: Uint8Array) => {
        const req = BridgeRpcRequest.fromBinary(reqBytes);
        seenRequests.push(req);
        if (req.method === "createGenesisV2") {
          return wrapSuccessEnvelope(framedGenesisEnvelope);
        }
        return wrapSuccessEnvelope(new Uint8Array([1]));
      },
    };

    await createGenesisViaRouter(mnemonic, "en-US", "testnet");

    expect(seenRequests).toHaveLength(1);
    expect(seenRequests[0].method).toBe("createGenesisV2");
    expect(seenRequests[0].payload.case).toBe("bytes");
    const decoded = WalletCreateGenesisV2Request.fromBinary(seenRequests[0].payload.value.data);
    expect(decoded.mnemonic).toBe(mnemonic);
    expect(decoded.locale).toBe("en-US");
    expect(decoded.networkId).toBe("testnet");
    // No silicon / no random entropy: the mnemonic is the sole genesis root.
  });

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
