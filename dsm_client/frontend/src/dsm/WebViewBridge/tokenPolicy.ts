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

/// Adopt a token created on another device, by its CPTA anchor.
///
/// A device cannot hold a token whose policy it does not have — balances are
/// keyed by policy commitment. Creating registers the token on the creator's
/// device only; every other device has to add it before it can receive any.
export async function addTokenByAnchor(anchor: Uint8Array): Promise<Uint8Array> {
  return routerQueryBin("tokens.addByAnchor", anchor);
}

export async function listCachedTokenPolicies(): Promise<Uint8Array> {
  return routerQueryBin("tokens.listCachedPolicies", new Uint8Array(0));
}
