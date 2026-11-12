// SPDX-License-Identifier: MIT OR Apache-2.0

// What an application asks a wallet to grant (`grant`), and what it asks a
// connected wallet to do (`ask`). Each builder returns a plain description;
// the account turns it into the wire's message when it sends it, resolving
// object symbols and amounts through Rust.

import type { Amount, ObjectRef } from "./objects.js";
import type { HoldingsProofV1 } from "./generated/dsm_app_pb.js";

/** A limit on what a grant lets the application take of one object. */
export interface Cap {
  object: ObjectRef;
  /** The most any one request may take. */
  perRequest: Amount;
  /** The most all requests may take together. */
  total: Amount;
}

export type Grant =
  | { kind: "send"; caps: Cap[] }
  | { kind: "owns"; objects: ObjectRef[] }
  | { kind: "accept" }
  | { kind: "contacts" }
  | { kind: "trade"; pair: [ObjectRef, ObjectRef]; caps: Cap[] }
  | { kind: "match"; caps: Cap[] }
  | { kind: "contribute"; caps: Cap[] }
  | { kind: "duel"; programs: Uint8Array[]; caps: Cap[] };

/** What an offer asks a wallet to let the application do without asking again. */
export const grant = {
  /** Send this application `object`, up to `perRequest` each time and `total` in all. */
  send(object: ObjectRef, perRequest: Amount, total: Amount): Grant {
    return { kind: "send", caps: [{ object, perRequest, total }] };
  },
  /** Prove what it owns of these objects. Objects this application issued are always included. */
  owns(objects: ObjectRef[]): Grant {
    return { kind: "owns", objects };
  },
  /** Accept objects this application issues. */
  accept(): Grant {
    return { kind: "accept" };
  },
  /** Tell this application who its contacts are (their DSM identities), and nothing more. */
  contacts(): Grant {
    return { kind: "contacts" };
  },
  /** Trade between these two objects through this application's vaults, within `caps`. */
  trade(a: ObjectRef, b: ObjectRef, caps: Cap[]): Grant {
    return { kind: "trade", pair: [a, b], caps };
  },
  /** Stake in matches this application referees, within `caps`. */
  match(caps: Cap[]): Grant {
    return { kind: "match", caps };
  },
  /** Commit amounts to what this application names, the wallet's to take back, within `caps`. */
  contribute(caps: Cap[]): Grant {
    return { kind: "contribute", caps };
  },
  /** Stake in matches these programs decide (each by the hash it is pinned by), within `caps`. */
  duel(programs: Uint8Array[], caps: Cap[]): Grant {
    return { kind: "duel", programs, caps };
  },
};

/** The identity of the other player, as this application's connection to it names it. */
export interface Opponent {
  genesis: Uint8Array;
  deviceId: Uint8Array;
  signingKey: Uint8Array;
}

export type Side = "A" | "B";

export type Ask =
  | { kind: "send"; object: ObjectRef; amount: Amount; memo: string }
  | { kind: "owns"; objects: ObjectRef[] }
  | { kind: "accept"; object: ObjectRef }
  | { kind: "contacts" }
  | { kind: "sign"; statement: string }
  | { kind: "price"; from: ObjectRef; to: ObjectRef; amount: Amount }
  | { kind: "trade"; from: ObjectRef; to: ObjectRef; amount: Amount; atLeast: Amount }
  | {
      kind: "stake";
      match: Uint8Array;
      object: ObjectRef;
      amount: Amount;
      side: Side;
      opponent: Opponent;
      against?: Uint8Array;
      memo: string;
    }
  | { kind: "collect"; stakes: Uint8Array[] }
  | { kind: "contribute"; to: Uint8Array; object: ObjectRef; amount: Amount; memo: string }
  | { kind: "takeBack"; contributions: Uint8Array[] }
  | { kind: "duelSessionKey"; nonce: Uint8Array }
  | {
      kind: "duelStake";
      setup: Uint8Array;
      side: Side;
      object: ObjectRef;
      amount: Amount;
      opponent: Opponent;
      opponentOwns: HoldingsProofV1;
      against?: Uint8Array;
      memo: string;
    }
  | { kind: "duelReady"; cell: Uint8Array; opponentReady?: Uint8Array; opponentReveal?: Uint8Array }
  | { kind: "duelWithdraw"; cell: Uint8Array }
  | { kind: "duelSign"; cell: Uint8Array; preceding: SignedEntry[]; entry: Uint8Array }
  | { kind: "duelSettle"; cell: Uint8Array; entries: SignedEntry[] }
  | { kind: "duelCollect"; stakes: Uint8Array[] };

/** The words a sign-in asks the player to approve. Compare the signed statement with this. */
export function loginStatement(app: string, nonce: string): string {
  return `Sign in to ${app} (${nonce})`;
}

/** One signed entry of a duel's transcript. */
export interface SignedEntry {
  entry: Uint8Array;
  signature: Uint8Array;
}

/** What an application asks a connected wallet to do. */
export const ask = {
  /** Send this application `amount` of `object`. */
  send(object: ObjectRef, amount: Amount, memo = ""): Ask {
    return { kind: "send", object, amount, memo };
  },
  /** Prove what the wallet owns of these objects. */
  owns(objects: ObjectRef[]): Ask {
    return { kind: "owns", objects };
  },
  /** Accept an object this application issued, so the wallet can hold it. */
  accept(object: ObjectRef): Ask {
    return { kind: "accept", object };
  },
  /** The DSM identities of the wallet's contacts. */
  contacts(): Ask {
    return { kind: "contacts" };
  },
  /** Sign a statement. Never in a grant: the player reads it and approves it on the device. */
  sign(statement: string): Ask {
    return { kind: "sign", statement };
  },
  /**
   * Sign in: the player approves `loginStatement(app, nonce)` on the device,
   * and the wallet's identity signs it. Keep the nonce, and accept the
   * sign-in only when the result's fact is "signed" and its statement is the
   * one you asked for. This is a password, an authenticator code and a
   * security key in one request, with nothing for you to store but the nonce.
   */
  login(app: string, nonce: string = crypto.randomUUID()): Ask {
    return { kind: "sign", statement: loginStatement(app, nonce) };
  },
  /** What `amount` of `from` would get in `to`, through this application's vaults. Information, never a fact. */
  price(from: ObjectRef, to: ObjectRef, amount: Amount): Ask {
    return { kind: "price", from, to, amount };
  },
  /** Trade `amount` of `from` for at least `atLeast` of `to`, through this application's vaults. */
  trade(from: ObjectRef, to: ObjectRef, amount: Amount, atLeast: Amount): Ask {
    return { kind: "trade", from, to, amount, atLeast };
  },
  /** Matches this application referees. */
  match: {
    /**
     * Stake `amount` of `object` on the match `match` describes (its agreed
     * bytes, 1 to 256), on `side`, against `opponent`. Side B passes side
     * A's stake id as `against`, so both stakes share one verdict.
     */
    stake(options: {
      match: Uint8Array | string;
      object: ObjectRef;
      amount: Amount;
      side: Side;
      opponent: Opponent;
      against?: Uint8Array;
      memo?: string;
    }): Ask {
      const match = typeof options.match === "string" ? new TextEncoder().encode(options.match) : options.match;
      return {
        kind: "stake",
        match,
        object: options.object,
        amount: options.amount,
        side: options.side,
        opponent: options.opponent,
        against: options.against,
        memo: options.memo ?? "",
      };
    },
    /** Collect the stakes a decided match pays this wallet (one or two stake ids). */
    collect(stakes: Uint8Array[]): Ask {
      return { kind: "collect", stakes };
    },
  },
  /**
   * Contributions (DSM Amendment A35): an amount the wallet commits to what
   * this application names. Both outcomes return it to the wallet; the
   * application decides when, never to whom.
   */
  contribution: {
    /** Commit `amount` of `object` to what `to` describes (its agreed bytes, 1 to 256). */
    commit(to: Uint8Array | string, object: ObjectRef, amount: Amount, memo = ""): Ask {
      return { kind: "contribute", to: typeof to === "string" ? new TextEncoder().encode(to) : to, object, amount, memo };
    },
    /** Take contributions back into this wallet (one to eight contribution ids). */
    takeBack(contributions: Uint8Array[]): Ask {
      return { kind: "takeBack", contributions };
    },
  },
  /** Matches a pinned program decides from both players' signed moves (SoFi Amendment S22). */
  duel: {
    /** The wallet's session key for the match whose setup carries `nonce`. */
    sessionKey(nonce: Uint8Array): Ask {
      return { kind: "duelSessionKey", nonce };
    },
    /** Stake in the match `setup` describes. The wallet checks the opponent's proof of what it owns itself. */
    stake(options: {
      setup: Uint8Array;
      side: Side;
      object: ObjectRef;
      amount: Amount;
      opponent: Opponent;
      opponentOwns: HoldingsProofV1;
      against?: Uint8Array;
      memo?: string;
    }): Ask {
      return {
        kind: "duelStake",
        setup: options.setup,
        side: options.side,
        object: options.object,
        amount: options.amount,
        opponent: options.opponent,
        opponentOwns: options.opponentOwns,
        against: options.against,
        memo: options.memo ?? "",
      };
    },
    /** Ready the wallet for the match; with the other side's ready and reveal, it readies second and starts it. */
    ready(cell: Uint8Array, opponentReady?: Uint8Array, opponentReveal?: Uint8Array): Ask {
      return { kind: "duelReady", cell, opponentReady, opponentReveal };
    },
    /** Withdraw while the match has not started: void, both refunded. */
    withdraw(cell: Uint8Array): Ask {
      return { kind: "duelWithdraw", cell };
    },
    /** Sign the wallet's next move, after the other side's moves since its last. */
    sign(cell: Uint8Array, preceding: SignedEntry[], entry: Uint8Array): Ask {
      return { kind: "duelSign", cell, preceding, entry };
    },
    /** Settle the match from the other side's last signed moves. */
    settle(cell: Uint8Array, entries: SignedEntry[]): Ask {
      return { kind: "duelSettle", cell, entries };
    },
    /** Collect the stakes a settled match pays this wallet. */
    collect(stakes: Uint8Array[]): Ask {
      return { kind: "duelCollect", stakes };
    },
  },
};
