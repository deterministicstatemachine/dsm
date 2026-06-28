// SPDX-License-Identifier: Apache-2.0
// Canonical mnemonic-rooted Genesis v2 (whitepaper §2.5) + secondary device + persisted envelope.

import { WalletCreateGenesisV2Request } from "../../proto/dsm_app_pb";
import { bridgeGate } from "../BridgeGate";
import { decodeFramedEnvelopeV3 } from "../decoding";
import {
  callBin,
  invokeRouterEnvelope,
  maybeThrowOnEmpty,
  toBytes,
} from "./transportCore";

/**
 * Generate a fresh BIP39 mnemonic for the new wallet (the sole Genesis v2 root). The caller MUST
 * present it to the user for backup BEFORE calling {@link createGenesisViaRouter}. No silicon, no
 * random genesis entropy — the mnemonic IS the root.
 */
export async function generateMnemonic(): Promise<string> {
  const res = await maybeThrowOnEmpty(
    await bridgeGate.enqueue(() => callBin("generateMnemonic", new Uint8Array(0))),
  );
  return new TextDecoder().decode(res).trim();
}

/**
 * Canonical mnemonic-rooted wallet creation. The (backed-up) `mnemonic` is the sole root: the
 * native side derives `wallet_seed`, caches it in the unlocked session, and runs `create_genesis_v2`
 * (install + persist v2 record + identity + SDK context). Returns the framed genesis envelope.
 */
export async function createGenesisViaRouter(
  mnemonic: string,
  locale: string,
  networkId: string
): Promise<Uint8Array> {
  if (!mnemonic || mnemonic.trim().length === 0) {
    throw new Error("createGenesisViaRouter: mnemonic is required (Genesis v2)");
  }
  const req = new WalletCreateGenesisV2Request({
    mnemonic: String(mnemonic),
    locale: String(locale ?? ""),
    networkId: String(networkId ?? ""),
  });
  const res = await maybeThrowOnEmpty(
    await bridgeGate.enqueue(() => callBin("createGenesisV2", req.toBinary())),
  );
  const env = decodeFramedEnvelopeV3(res);
  if (env.payload.case === "error") {
    return res;
  }
  if (env.payload.case !== "genesisCreatedResponse") {
    throw new Error(`createGenesisV2 returned unexpected payload: ${env.payload.case}`);
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
