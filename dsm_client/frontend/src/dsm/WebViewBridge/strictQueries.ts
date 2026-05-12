// SPDX-License-Identifier: Apache-2.0
// Strict query helpers: contacts, balances, history, inbox, pending bilateral
// list, storage sync. All return raw framed Envelope v3 bytes; callers decode.

import { ArgPack, Codec, InboxRequest, StorageSyncRequest } from "../../proto/dsm_app_pb";
import { callBin, maybeThrowOnEmpty, routerQueryBin, toBytes } from "./transportCore";

export async function getContactsStrictBridge(): Promise<Uint8Array> {
  const res = await routerQueryBin("contacts.list");
  return maybeThrowOnEmpty(res);
}

/**
 * Calls the strict JNI endpoint directly to get a FramedEnvelopeV3 (no 8-byte
 * router prefix). Capability is enforced inside sendBridgeRequestBytes, so no
 * pre-check is needed here.
 */
export async function getAllBalancesStrictBridge(): Promise<Uint8Array> {
  const res = await callBin("getAllBalancesStrict");
  return maybeThrowOnEmpty(res);
}

export async function getWalletHistoryStrictBridge(): Promise<Uint8Array> {
  // limit=0, offset=0 (little-endian u64 each)
  const limitOffset = new Uint8Array(16);
  const arg = new ArgPack({
    codec: Codec.PROTO,
    body: toBytes(limitOffset),
  });
  const res = await routerQueryBin("wallet.history", arg.toBinary());
  return maybeThrowOnEmpty(res);
}

export async function getInboxStrictBridge(args?: { limit?: number }): Promise<Uint8Array> {
  const limit = typeof args?.limit === "number" ? args.limit : 50;
  const req = new InboxRequest({ limit });
  const arg = new ArgPack({
    codec: Codec.PROTO,
    body: toBytes(req.toBinary()),
  });
  const res = await routerQueryBin("inbox.pull", arg.toBinary());
  return maybeThrowOnEmpty(res);
}

export async function getPendingBilateralListStrictBridge(): Promise<Uint8Array> {
  const arg = new ArgPack({
    codec: Codec.PROTO,
    body: new Uint8Array(0),
  });
  const res = await routerQueryBin("bilateral.pending_list", arg.toBinary());
  return maybeThrowOnEmpty(res);
}

export async function syncWithStorageStrictBridge(args?: {
  pullInbox?: boolean;
  pushPending?: boolean;
  limit?: number;
}): Promise<Uint8Array> {
  const req = new StorageSyncRequest({
    pullInbox: args?.pullInbox !== false,
    pushPending: args?.pushPending === true,
    limit: typeof args?.limit === "number" ? args.limit : 50,
  });
  const arg = new ArgPack({
    codec: Codec.PROTO,
    body: toBytes(req.toBinary()),
  });
  const res = await routerQueryBin("storage.sync", arg.toBinary());
  return maybeThrowOnEmpty(res);
}
