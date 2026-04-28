// SPDX-License-Identifier: Apache-2.0
// Manual bilateral accept/reject (bytes-only).

import { BilateralPayload, BridgeRpcRequest } from "../../proto/dsm_app_pb";
import { callBin, maybeThrowOnEmpty, sendBridgeRequestBytes } from "./transportCore";

export async function acceptBilateralByCommitmentBridge(
  commitmentHash: Uint8Array
): Promise<Uint8Array> {
  if (!(commitmentHash instanceof Uint8Array) || commitmentHash.length !== 32) {
    throw new Error("acceptBilateralByCommitmentBridge: commitmentHash must be 32 bytes");
  }
  const res = await callBin("acceptBilateralByCommitment", commitmentHash);
  return maybeThrowOnEmpty(res);
}

export async function rejectBilateralByCommitmentBridge(
  commitmentHash: Uint8Array,
  reason: string
): Promise<Uint8Array> {
  if (!(commitmentHash instanceof Uint8Array) || commitmentHash.length !== 32) {
    throw new Error("rejectBilateralByCommitmentBridge: commitmentHash must be 32 bytes");
  }

  const req = new BridgeRpcRequest({
    method: "rejectBilateralByCommitment",
    payload: {
      case: "bilateral",
      value: new BilateralPayload({
        commitment: new Uint8Array(commitmentHash),
        reason: String(reason ?? ""),
      }),
    },
  });
  const res = await sendBridgeRequestBytes("rejectBilateralByCommitment", req.toBinary());
  return maybeThrowOnEmpty(res);
}
