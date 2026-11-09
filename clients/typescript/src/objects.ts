// SPDX-License-Identifier: MIT OR Apache-2.0

// Objects and amounts, as an application names them.
//
// An object is a kind of thing an account can hold: ERA, an item, a ticket, a
// currency a game issued. On the wire it is a 32-byte policy commit; here it
// is named by its symbol ("ERA", "SWORD") or by that id. An amount is written
// in the object's own units ("0.10", "1"); Rust converts it to and from the
// object's smallest unit, so no client carries the unit rule.

import type { BalanceGetResponse } from "./generated/dsm_app_pb.js";
import { BalanceHolding } from "./generated/dsm_app_pb.js";
import { decodeB32, encodeB32 } from "./b32.js";

/** An object, by its symbol ("ERA"), its id (Base32 Crockford), its raw 32-byte id, or its description. */
export type ObjectRef = string | Uint8Array | ObjectInfo;

/** An amount: a string in the object's own units ("1.50"), or a bigint in its smallest unit. */
export type Amount = string | bigint;

/** An object as this account knows it. */
export interface ObjectInfo {
  /** Its id (Base32 Crockford of the 32-byte policy commit). */
  id: string;
  /** The raw id. */
  raw: Uint8Array;
  /** Its symbol: ERA, SWORD. Not unique on its own; two issuers may pick the same one. */
  symbol: string;
  name: string;
  decimals: number;
  /** "unique": exactly one exists (an item). "currency": counted in units. */
  kind: "unique" | "currency";
  /** The whole supply that will ever exist, in its own units; empty when unknown here. */
  supply: string;
  /** An asset the protocol defines (ERA), rather than one an account issued. */
  protocol: boolean;
  icon: string;
}

/** What an account holds of one object. */
export interface Owned {
  object: ObjectInfo;
  /** In the object's smallest unit. */
  amount: bigint;
  /** The same, in the object's own units, as Rust renders it. */
  display: string;
  /** Held in vaults or stakes, in the smallest unit. */
  locked: bigint;
}

export function objectOf(b: BalanceGetResponse): ObjectInfo {
  const raw = decodeB32(b.policyAnchorB32);
  return {
    id: b.policyAnchorB32,
    raw,
    symbol: b.symbol.length > 0 ? b.symbol : b.tokenId,
    name: b.tokenName,
    decimals: b.decimals,
    kind: b.holding === BalanceHolding.STATE_OBJECT ? "unique" : "currency",
    supply: b.genesisSupplyDisplay,
    protocol: b.protocolDefined,
    icon: b.iconUrl,
  };
}

export function ownedOf(b: BalanceGetResponse): Owned {
  return { object: objectOf(b), amount: b.available, display: b.displayAmount, locked: b.locked };
}

/** The raw id a reference names directly, or undefined when it is a symbol to look up. */
export function directId(ref: ObjectRef): Uint8Array | undefined {
  if (typeof ref !== "string") {
    return ref instanceof Uint8Array ? ref : ref.raw;
  }
  if (ref.length === 52) {
    try {
      const raw = decodeB32(ref);
      if (raw.length === 32) return raw;
    } catch {
      return undefined;
    }
  }
  return undefined;
}

export function sameObject(a: Uint8Array, b: Uint8Array): boolean {
  return encodeB32(a) === encodeB32(b);
}

/** How a reference reads in a message about it. */
export function describe(ref: ObjectRef): string {
  if (typeof ref === "string") return ref;
  return ref instanceof Uint8Array ? encodeB32(ref) : ref.symbol;
}
