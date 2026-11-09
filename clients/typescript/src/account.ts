// SPDX-License-Identifier: MIT OR Apache-2.0

// An account a dsm-app-host runs, reached through its ingress. Your
// application's account is an AppAccount; the terminal dev wallet is a
// WalletAccount. Both are the same SDK on the same production path a phone
// runs; these classes name its routes and nothing more.

import {
  BalanceGetResponse,
  ConnectAcceptIssuedV1,
  ConnectAppOfferRequestV1,
  ConnectAppRequestIntentV1,
  ConnectAppStatusV1,
  ConnectApproveRequestV1,
  ConnectCapV1,
  ConnectDecision,
  ConnectHoldingsV1,
  ConnectOfferRefV1,
  ConnectPayV1,
  ConnectPreviewRequestV1,
  ConnectRequestRefV1,
  ConnectRespondRequestV1,
  ConnectScopeKind,
  ConnectScopeV1,
  ConnectSessionRefV1,
  FaucetClaimRequest,
} from "./generated/dsm_app_pb.js";
import type {
  ConnectAppOfferV1,
  ConnectDecidedV1,
  ConnectLogV1,
  ConnectPendingV1,
  ConnectPreviewV1,
  ConnectSessionV1,
  FaucetClaimResponse,
} from "./generated/dsm_app_pb.js";
import { decodeId, encodeB32 } from "./b32.js";
import { Ingress } from "./ingress.js";
import { connectReply, payload } from "./replies.js";

/** What every account can do: name itself, read its balances, claim the faucet. */
export class Account {
  constructor(readonly ingress: Ingress) {}

  /** This account's device id (32 bytes). */
  async deviceId(): Promise<Uint8Array> {
    const activity = await this.ingress.activity(0n);
    if (activity.deviceId.length !== 32) {
      throw new Error("the host named no account: is it still starting?");
    }
    return activity.deviceId;
  }

  /** This account's device id as people read it (Base32 Crockford). */
  async id(): Promise<string> {
    return encodeB32(await this.deviceId());
  }

  /** Every token this account holds, in base units. */
  async balances(): Promise<BalanceGetResponse[]> {
    const route = "balance.list";
    const envelope = await this.ingress.call("query", route, undefined, { quiet: true });
    return payload(route, envelope, "balancesListResponse").balances;
  }

  /** The policy commit (32 bytes) of a token this account holds, by its ticker. */
  async policyCommitOf(ticker: string): Promise<Uint8Array> {
    const held = (await this.balances()).find((b) => b.tokenId === ticker || b.symbol === ticker);
    if (held === undefined) {
      throw new Error(`this account holds no ${ticker}`);
    }
    return decodeId(held.policyAnchorB32, `${ticker}'s policy anchor`);
  }

  /** One claim from the network's faucet, for this account. */
  async claimFaucet(): Promise<FaucetClaimResponse> {
    const route = "faucet.claim";
    const deviceId = await this.deviceId();
    const envelope = await this.ingress.call("invoke", route, new FaucetClaimRequest({ deviceId }));
    return payload(route, envelope, "faucetClaimResponse");
  }
}

/** A scope an application asks a wallet to grant. */
export const scope = {
  /** Pay this application's account in `token`, at most `perRequest` each time and `total` in all (base units). */
  pay(token: Uint8Array, perRequest: bigint, total: bigint): ConnectScopeV1 {
    return new ConnectScopeV1({
      kind: ConnectScopeKind.PAY,
      caps: [new ConnectCapV1({ policyCommit: token, perRequest, total })],
    });
  },
  /** Prove holdings of these tokens (objects this application issued are always included). */
  holdings(tokens: Uint8Array[]): ConnectScopeV1 {
    return new ConnectScopeV1({ kind: ConnectScopeKind.HOLDINGS, policyCommits: tokens });
  },
  /** Take objects this application's account issued. */
  acceptIssued(): ConnectScopeV1 {
    return new ConnectScopeV1({ kind: ConnectScopeKind.ACCEPT_ISSUED });
  },
  /** Read the DSM identities of the wallet's contacts, and nothing more. */
  contacts(): ConnectScopeV1 {
    return new ConnectScopeV1({ kind: ConnectScopeKind.CONTACTS });
  },
};

export interface OfferOptions {
  /** The name the wallet shows the user. */
  displayName: string;
  /** What the application may ask for without the user. */
  scopes: ConnectScopeV1[];
  /** Tokens the wallet adopts when it connects (policy anchors, 32 bytes each). */
  tokenAnchors?: Uint8Array[];
  /** Requests the wallet answers before the application pays for more. */
  freeRequests: number;
}

/** A request the application makes of a connected wallet. */
export type Intent = ConnectAppRequestIntentV1["kind"];

export const intent = {
  /** Pay this application's account `amount` base units of `token`. */
  pay(token: Uint8Array, amount: bigint, memo: string): Intent {
    return { case: "pay", value: new ConnectPayV1({ policyCommit: token, amount, memo }) };
  },
  /** Prove what the wallet holds of these tokens. */
  holdings(tokens: Uint8Array[]): Intent {
    return { case: "holdings", value: new ConnectHoldingsV1({ policyCommits: tokens }) };
  },
  /** Take an object this application's account issued, by its anchor. */
  acceptIssued(anchor: Uint8Array): Intent {
    return { case: "acceptIssued", value: new ConnectAcceptIssuedV1({ anchor }) };
  },
};

/** A request this application made, by session and sequence number. */
export interface RequestRef {
  sessionId: Uint8Array;
  seq: bigint;
}

/** Your application's own account. */
export class AppAccount extends Account {
  /**
   * Make an offer: the `dsm:connect/v1:` code a wallet scans to connect. The
   * host names its own relay endpoint and certificate pin in it.
   */
  async offer(options: OfferOptions): Promise<ConnectAppOfferV1> {
    const route = "connect.app.offer";
    const request = new ConnectAppOfferRequestV1({
      displayName: options.displayName,
      scopes: options.scopes,
      tokenAnchors: options.tokenAnchors ?? [],
      freeRequests: options.freeRequests,
    });
    return connectReply(route, await this.ingress.call("invoke", route, request), "offer");
  }

  /** An offer this account made, by its digest. */
  async offerOf(offerDigest: Uint8Array): Promise<ConnectAppOfferV1> {
    const route = "connect.app.offerOf";
    const request = new ConnectOfferRefV1({ offerDigest });
    return connectReply(route, await this.ingress.call("query", route, request, { quiet: true }), "offer");
  }

  /** Every wallet connected to this application, and every one that disconnected. */
  async sessions(): Promise<ConnectSessionV1[]> {
    const route = "connect.app.sessions";
    const envelope = await this.ingress.call("query", route, undefined, { quiet: true });
    return connectReply(route, envelope, "sessions").sessions;
  }

  /** Ask a connected wallet for something. The wallet answers on its own time; read the answer with `status`. */
  async request(sessionId: Uint8Array, kind: Intent): Promise<RequestRef> {
    const route = "connect.app.request";
    const request = new ConnectAppRequestIntentV1({ sessionId, kind });
    const ref = connectReply(route, await this.ingress.call("invoke", route, request), "request");
    return { sessionId: ref.sessionId, seq: ref.seq };
  }

  /**
   * What became of a request: the wallet's answer (a notification) and the
   * fact this account established itself (a payment accepted onto its own
   * relationship, a holdings proof it verified). Only the fact is evidence.
   */
  async status(ref: RequestRef): Promise<ConnectAppStatusV1> {
    const route = "connect.app.status";
    const request = new ConnectRequestRefV1({ sessionId: ref.sessionId, seq: ref.seq });
    return connectReply(route, await this.ingress.call("invoke", route, request, { quiet: true }), "status");
  }
}

/** A wallet's side of Connect: the terminal dev wallet, or any wallet you script. */
export class WalletAccount extends Account {
  /** What a connect code asks for, before the user approves it. */
  async preview(code: string): Promise<ConnectPreviewV1> {
    const route = "connect.preview";
    const request = new ConnectPreviewRequestV1({ code });
    return connectReply(route, await this.ingress.call("query", route, request), "preview");
  }

  /** Approve an offer. With no scopes given it grants exactly what the offer asked. */
  async approve(offerDigest: Uint8Array, granted: ConnectScopeV1[] = []): Promise<ConnectSessionV1> {
    const route = "connect.approve";
    const request = new ConnectApproveRequestV1({ offerDigest, granted });
    return connectReply(route, await this.ingress.call("invoke", route, request), "session");
  }

  /** Every application this wallet is connected to. */
  async sessions(): Promise<ConnectSessionV1[]> {
    const route = "connect.list";
    return connectReply(route, await this.ingress.call("query", route, undefined, { quiet: true }), "sessions").sessions;
  }

  /** Fetch and carry out what connected applications asked, now. */
  async sync(): Promise<ConnectSessionV1[]> {
    const route = "connect.sync";
    return connectReply(route, await this.ingress.call("invoke", route, undefined), "sessions").sessions;
  }

  /** Requests outside a grant, waiting for the user. */
  async pending(): Promise<ConnectPendingV1[]> {
    const route = "connect.pending";
    return connectReply(route, await this.ingress.call("query", route, undefined, { quiet: true }), "pending").pending;
  }

  /** Approve or decline a waiting request. */
  async respond(sessionId: Uint8Array, seq: bigint, approve: "approve" | "decline"): Promise<ConnectDecidedV1> {
    const route = "connect.respond";
    const decision = approve === "approve" ? ConnectDecision.APPROVE : ConnectDecision.DECLINE;
    const request = new ConnectRespondRequestV1({ sessionId, seq, decision });
    return connectReply(route, await this.ingress.call("invoke", route, request), "decided");
  }

  /** Everything a connected application asked, and what came of it. */
  async log(sessionId: Uint8Array): Promise<ConnectLogV1> {
    const route = "connect.log";
    const request = new ConnectSessionRefV1({ sessionId });
    return connectReply(route, await this.ingress.call("query", route, request, { quiet: true }), "log");
  }

  /** End a connection. The application can ask nothing more of this wallet. */
  async disconnect(sessionId: Uint8Array): Promise<ConnectSessionV1> {
    const route = "connect.disconnect";
    const request = new ConnectSessionRefV1({ sessionId });
    return connectReply(route, await this.ingress.call("invoke", route, request), "session");
  }
}
