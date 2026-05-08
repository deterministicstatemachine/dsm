/// <reference types="jest" />
/// <reference types="node" />

import "../../setupTests";

import * as pb from "../../proto/dsm_app_pb";
import { encodeBase32Crockford } from "../../utils/textId";

// Import the function under test
import { sendOnlineTransfer } from "../index";

const zeroHash = () => new pb.Hash32({ v: new Uint8Array(32) });

function bytes(len: number, fill: number): Uint8Array {
  const b = new Uint8Array(len);
  b.fill(fill & 0xff);
  return b;
}

/** Build a framed Envelope with onlineTransferResponse payload */
function makeOnlineResponseFramed(
  success: boolean,
  message: string,
  newBalance: bigint = 123n
): Uint8Array {
  const resp = new pb.OnlineTransferResponse({
    success,
    transactionHash: zeroHash(),
    message,
    newBalance: newBalance as any,
  } as any);
  const envelope = new pb.Envelope({
    version: 3,
    payload: { case: "onlineTransferResponse", value: resp },
  } as any);
  const envBytes = envelope.toBinary();
  const framed = new Uint8Array(1 + envBytes.length);
  framed[0] = 0x03;
  framed.set(envBytes, 1);
  return framed;
}

describe("sendOnlineTransfer uses modern bridge contract", () => {
  test("uses transport headers bytes and succeeds via wallet.send", async () => {
    // Mock queryTransportHeadersV3
    const headers = new pb.Headers({
      deviceId: bytes(32, 0x11),
      chainTip: bytes(32, 0x22),
      genesisHash: bytes(32, 0x33),
      seq: 1,
    } as any);
    jest
      .spyOn(require("../WebViewBridge"), "queryTransportHeadersV3")
      .mockResolvedValue(headers.toBinary());

    // Mock routerInvokeBin to return framed Envelope with onlineTransferResponse
    const mockAppRouter = jest.fn().mockResolvedValue(makeOnlineResponseFramed(true, "ok", 123n));
    jest.spyOn(require("../WebViewBridge"), "routerInvokeBin").mockImplementation(mockAppRouter);

    const recipient = bytes(32, 0x44);
    const res = await sendOnlineTransfer({
      to: encodeBase32Crockford(recipient),
      amount: 1n,
      tokenId: "ERA",
      memo: "",
    });
    expect(res.accepted).toBe(true);

    // Verify routerInvokeBin was called with 'wallet.send'
    expect(mockAppRouter).toHaveBeenCalledWith("wallet.send", expect.any(Uint8Array));
  });
});
