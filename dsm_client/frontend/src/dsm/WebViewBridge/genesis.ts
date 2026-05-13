// SPDX-License-Identifier: Apache-2.0
// Genesis creation + secondary device + persisted genesis envelope routes.

import { SystemGenesisRequest } from "../../proto/dsm_app_pb";
import { bridgeGate } from "../BridgeGate";
import { decodeFramedEnvelopeV3 } from "../decoding";
import {
  callBin,
  invokeRouterEnvelope,
  maybeThrowOnEmpty,
  toBytes,
} from "./transportCore";

export async function createGenesisViaRouter(
  locale: string,
  networkId: string,
  entropy: Uint8Array
): Promise<Uint8Array> {
  if (entropy.length !== 32) throw new Error("entropy must be 32 bytes");
  const req = new SystemGenesisRequest({
    locale: String(locale ?? ""),
    networkId: String(networkId ?? ""),
    deviceEntropy: new Uint8Array(entropy),
  });
  const res = await maybeThrowOnEmpty(
    await bridgeGate.enqueue(() => callBin("createGenesis", req.toBinary())),
  );
  const env = decodeFramedEnvelopeV3(res);
  if (env.payload.case === "error") {
    return res;
  }
  if (env.payload.case !== "genesisCreatedResponse") {
    throw new Error(`system.genesis returned unexpected payload: ${env.payload.case}`);
  }
  return res;
}

/**
 * Add a secondary device to an existing genesis. Returns the inner
 * SecondaryDeviceResponse proto bytes (already decoded out of the framed
 * Envelope) so callers do not have to repeat the decode.
 */
export async function addSecondaryDeviceBin(
  genesisHash: Uint8Array,
  deviceEntropy: Uint8Array
): Promise<Uint8Array> {
  const pb = await import("../../proto/dsm_app_pb");
  const req = new pb.SecondaryDeviceRequest({
    genesisHash: new Uint8Array(genesisHash),
    deviceEntropy: new Uint8Array(deviceEntropy),
  });
  const arg = new pb.ArgPack({
    codec: pb.Codec.PROTO,
    body: toBytes(req.toBinary()),
  });
  const { envelope: env } = await invokeRouterEnvelope("system.secondary_device", arg.toBinary());
  if (env.payload.case === "error") {
    const errMsg = env.payload.value.message || `Error code ${env.payload.value.code}`;
    throw new Error(`initializeSecondaryDevice failed: ${errMsg}`);
  }
  if (env.payload.case === "secondaryDeviceResponse") {
    return env.payload.value.toBinary();
  }
  throw new Error(`initializeSecondaryDevice failed: unexpected payload case ${env.payload.case}`);
}
