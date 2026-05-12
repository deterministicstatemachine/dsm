// SPDX-License-Identifier: Apache-2.0
// Genesis creation + secondary device + persisted genesis envelope routes.

import {
  ArgPack,
  BootstrapFinalizeResponse_Result,
  Codec,
  SystemGenesisRequest,
} from "../../proto/dsm_app_pb";
import { decodeFramedEnvelopeV3 } from "../decoding";
import { captureDeviceBindingForGenesisEnvelope } from "../NativeHostBridge";
import { invokeRouterEnvelope, queryRouterEnvelope, toBytes } from "./transportCore";

const ENVELOPE_V3 = 3 as const;

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
  const argPack = new ArgPack({
    codec: Codec.PROTO,
    body: new Uint8Array(req.toBinary()),
  });
  const { bytes: res, envelope: env } = await queryRouterEnvelope(
    "system.genesis",
    argPack.toBinary()
  );
  if (env.payload.case === "error") {
    return res;
  }
  if (env.payload.case !== "genesisCreatedResponse") {
    throw new Error(`system.genesis returned unexpected payload: ${env.payload.case}`);
  }
  // Internal state-binding capture is not part of the public router contract,
  // so we keep using the host bridge directly here.
  void ENVELOPE_V3;
  const finalizeEnvelopeBytes = await captureDeviceBindingForGenesisEnvelope(res);
  const finalizeEnvelope = decodeFramedEnvelopeV3(finalizeEnvelopeBytes);
  if (finalizeEnvelope.payload.case !== "bootstrapFinalizeResponse") {
    throw new Error(
      `device binding capture returned unexpected payload: ${finalizeEnvelope.payload.case}`
    );
  }
  const finalize = finalizeEnvelope.payload.value;
  if (finalize.result !== BootstrapFinalizeResponse_Result.BOOTSTRAP_RESULT_READY) {
    throw new Error(finalize.message || `bootstrap finalize failed with result ${finalize.result}`);
  }
  if (finalize.deviceId.length !== 32 || finalize.genesisHash.length !== 32) {
    throw new Error("bootstrap finalize returned incomplete identity");
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
