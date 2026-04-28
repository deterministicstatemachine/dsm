// SPDX-License-Identifier: Apache-2.0
// Token policy publish/get/list-cached. Router paths verified against the
// Rust dispatch table in dsm_sdk/src/handlers/token_routes.rs and
// app_router_impl.rs (issue #226 item 7).

import { routerInvokeBin, routerQueryBin } from "./transportCore";

export async function publishTokenPolicyBytes(policyBytes: Uint8Array): Promise<Uint8Array> {
  return routerInvokeBin("tokens.publishPolicy", policyBytes);
}

export async function getTokenPolicyBytes(policyId: Uint8Array): Promise<Uint8Array> {
  return routerQueryBin("tokens.getPolicy", policyId);
}

export async function listCachedTokenPolicies(): Promise<Uint8Array> {
  return routerQueryBin("tokens.listCachedPolicies", new Uint8Array(0));
}
