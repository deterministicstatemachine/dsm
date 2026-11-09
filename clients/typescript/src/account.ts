// SPDX-License-Identifier: MIT OR Apache-2.0

// An account a dsm-app-host runs, reached through its ingress. Your
// application's account is an AppAccount; a wallet you script (the terminal
// dev wallet) is a WalletAccount. Both are the same SDK on the same path a
// phone runs: these classes name its routes, resolve the names you use into
// the wire's bytes, and read its answers back into plain values.

import {
  ConnectAcceptIssuedV1,
  ConnectAppOfferRequestV1,
  ConnectAppRequestIntentV1,
  ConnectApproveRequestV1,
  ConnectCapV1,
  ConnectContactsV1,
  ConnectDecision,
  ConnectDuelCollectV1,
  ConnectDuelLockV1,
  ConnectDuelReadyV1,
  ConnectDuelSessionKeyV1,
  ConnectDuelSettleV1,
  ConnectDuelSignV1,
  ConnectDuelSignedEntryV1,
  ConnectDuelWithdrawV1,
  ConnectEscrowLockV1,
  ConnectEscrowReleaseV1,
  ConnectHoldingsV1,
  ConnectOfferRefV1,
  ConnectPayV1,
  ConnectPreviewRequestV1,
  ConnectQuoteV1,
  ConnectRequestRefV1,
  ConnectRespondRequestV1,
  ConnectScopeKind,
  ConnectScopeV1,
  ConnectSessionRefV1,
  ConnectSignV1,
  ConnectSwapV1,
  EscrowOutcomeRequest,
  FaucetClaimRequest,
  OnlineTransferSmartRequest,
  SofiCloseRequest,
  SofiCreateVaultRequest,
  TokenCreateRequest,
  WalletAmountRequest,
} from "./generated/dsm_app_pb.js";
import type {
  ConnectAppOfferV1,
  ConnectDecidedV1,
  ConnectLogV1,
  EscrowVerdictResponse,
  SofiOwnedVaultV1,
} from "./generated/dsm_app_pb.js";
import { decodeId, encodeB32 } from "./b32.js";
import { Ingress } from "./ingress.js";
import {
  describe,
  directId,
  objectOf,
  ownedOf,
  sameObject,
  type Amount,
  type ObjectInfo,
  type ObjectRef,
  type Owned,
} from "./objects.js";
import { connectReply, payload } from "./replies.js";
import type { Ask, Cap, Grant } from "./requests.js";
import {
  connectionOf,
  pendingOf,
  previewOf,
  resultOf,
  type Connection,
  type Pending,
  type Preview,
  type RequestRef,
  type Result,
} from "./results.js";

/** An account's DSM identity. */
export interface Identity {
  /** As people read it (Base32 Crockford). */
  id: string;
  raw: Uint8Array;
}

/** A connection or a wallet, by its id (Base32 Crockford), its raw id, or the connection itself. */
export type ConnectionRef = string | Uint8Array | Connection;

function rawOf(ref: ConnectionRef, what: string): Uint8Array {
  if (typeof ref === "string") return decodeId(ref, what);
  return ref instanceof Uint8Array ? ref : ref.rawId;
}

/** What every account can do: name itself, say what it owns, be funded on a development set. */
export class Account {
  #objects: ObjectInfo[] | undefined;

  constructor(readonly ingress: Ingress) {}

  /** This account's DSM identity. */
  async identity(): Promise<Identity> {
    const activity = await this.ingress.activity(0n);
    if (activity.deviceId.length !== 32) {
      throw new Error("the host named no account: is it still starting?");
    }
    return { id: encodeB32(activity.deviceId), raw: activity.deviceId };
  }

  /** This account's identity, as people read it. */
  async id(): Promise<string> {
    return (await this.identity()).id;
  }

  /** Everything this account owns. */
  async owned(): Promise<Owned[]> {
    const route = "balance.list";
    const envelope = await this.ingress.call("query", route, undefined, { quiet: true });
    const owned = payload(route, envelope, "balancesListResponse").balances.map(ownedOf);
    this.#objects = owned.map((o) => o.object);
    return owned;
  }

  /** What this account owns of one object, or undefined when it owns none. */
  async owns(object: ObjectRef): Promise<Owned | undefined> {
    const raw = await this.objectId(object);
    return (await this.owned()).find((o) => sameObject(o.object.raw, raw));
  }

  /** An object this account knows, by symbol or id. */
  async object(ref: ObjectRef): Promise<ObjectInfo> {
    if (typeof ref === "object" && !(ref instanceof Uint8Array)) return ref;
    const direct = directId(ref);
    const known = async (): Promise<ObjectInfo | undefined> => {
      const objects = this.#objects ?? (await this.owned()).map((o) => o.object);
      return objects.find((o) => (direct !== undefined ? sameObject(o.raw, direct) : o.symbol === ref));
    };
    const found = (await known()) ?? ((this.#objects = undefined), await known());
    if (found === undefined) {
      throw new Error(`this account knows no object ${describe(ref)}: it holds none, and issued none by that name`);
    }
    return found;
  }

  /** The raw id of an object: given directly, or looked up by symbol among what this account knows. */
  async objectId(ref: ObjectRef): Promise<Uint8Array> {
    return directId(ref) ?? (await this.object(ref)).raw;
  }

  /** `amount` of `object` in the object's smallest unit. Rust parses what people write. */
  async units(object: ObjectRef, amount: Amount): Promise<bigint> {
    if (typeof amount === "bigint") return amount;
    const info = await this.object(object);
    const route = "wallet.amount";
    const request = new WalletAmountRequest({
      unit: { case: "tokenId", value: info.symbol },
      amount: { case: "entered", value: amount },
    });
    const envelope = await this.ingress.call("query", route, request, { quiet: true });
    return payload(route, envelope, "walletAmountResponse").baseUnits;
  }

  /** `amount` of `object` in the object's own units, as Rust renders it. */
  async display(object: ObjectRef, amount: Amount): Promise<string> {
    if (typeof amount === "string") return amount;
    const info = await this.object(object);
    const route = "wallet.amount";
    const request = new WalletAmountRequest({
      unit: { case: "tokenId", value: info.symbol },
      amount: { case: "baseUnits", value: amount },
    });
    const envelope = await this.ingress.call("query", route, request, { quiet: true });
    return payload(route, envelope, "walletAmountResponse").displayAmount;
  }

  /**
   * Ask the development set's faucet for ERA, once. Returns what it said; a
   * faucet that is not ready yet says so and funds nothing, so call it again.
   */
  async fund(): Promise<{ funded: boolean; message: string }> {
    const route = "faucet.claim";
    const identity = await this.identity();
    const envelope = await this.ingress.call("invoke", route, new FaucetClaimRequest({ deviceId: identity.raw }));
    const claim = payload(route, envelope, "faucetClaimResponse");
    return { funded: claim.success, message: claim.message };
  }

  protected async cap(c: Cap): Promise<ConnectCapV1> {
    return new ConnectCapV1({
      policyCommit: await this.objectId(c.object),
      perRequest: await this.units(c.object, c.perRequest),
      total: await this.units(c.object, c.total),
    });
  }

  protected async caps(caps: Cap[]): Promise<ConnectCapV1[]> {
    return Promise.all(caps.map((c) => this.cap(c)));
  }

  protected async ids(objects: ObjectRef[]): Promise<Uint8Array[]> {
    return Promise.all(objects.map((o) => this.objectId(o)));
  }

  /** A grant, on the wire. */
  async scope(g: Grant): Promise<ConnectScopeV1> {
    switch (g.kind) {
      case "send":
        return new ConnectScopeV1({ kind: ConnectScopeKind.PAY, caps: await this.caps(g.caps) });
      case "owns":
        return new ConnectScopeV1({ kind: ConnectScopeKind.HOLDINGS, policyCommits: await this.ids(g.objects) });
      case "accept":
        return new ConnectScopeV1({ kind: ConnectScopeKind.ACCEPT_ISSUED });
      case "contacts":
        return new ConnectScopeV1({ kind: ConnectScopeKind.CONTACTS });
      case "trade":
        return new ConnectScopeV1({
          kind: ConnectScopeKind.SWAP,
          policyCommits: await this.ids(g.pair),
          caps: await this.caps(g.caps),
        });
      case "match":
        return new ConnectScopeV1({ kind: ConnectScopeKind.ESCROW, caps: await this.caps(g.caps) });
      case "duel":
        return new ConnectScopeV1({ kind: ConnectScopeKind.DUEL, programs: g.programs, caps: await this.caps(g.caps) });
    }
  }

  /** A request, on the wire. */
  async intent(a: Ask): Promise<ConnectAppRequestIntentV1["kind"]> {
    switch (a.kind) {
      case "send":
        return {
          case: "pay",
          value: new ConnectPayV1({
            policyCommit: await this.objectId(a.object),
            amount: await this.units(a.object, a.amount),
            memo: a.memo,
          }),
        };
      case "owns":
        return { case: "holdings", value: new ConnectHoldingsV1({ policyCommits: await this.ids(a.objects) }) };
      case "accept":
        return { case: "acceptIssued", value: new ConnectAcceptIssuedV1({ anchor: await this.objectId(a.object) }) };
      case "contacts":
        return { case: "contacts", value: new ConnectContactsV1() };
      case "sign":
        return { case: "sign", value: new ConnectSignV1({ statement: a.statement }) };
      case "price":
        return {
          case: "quote",
          value: new ConnectQuoteV1({
            tokenIn: await this.objectId(a.from),
            tokenOut: await this.objectId(a.to),
            amountIn: await this.units(a.from, a.amount),
          }),
        };
      case "trade":
        return {
          case: "swap",
          value: new ConnectSwapV1({
            tokenIn: await this.objectId(a.from),
            tokenOut: await this.objectId(a.to),
            amountIn: await this.units(a.from, a.amount),
            minAmountOut: await this.units(a.to, a.atLeast),
          }),
        };
      case "stake":
        return {
          case: "escrowLock",
          value: new ConnectEscrowLockV1({
            external: a.match,
            policyCommit: await this.objectId(a.object),
            amount: await this.units(a.object, a.amount),
            side: a.side === "A" ? 1 : 2,
            opponentGenesis: a.opponent.genesis,
            opponentDeviceId: a.opponent.deviceId,
            opponentSigningKey: a.opponent.signingKey,
            counterpartVaultId: a.against ?? new Uint8Array(0),
            memo: a.memo,
          }),
        };
      case "collect":
        return { case: "escrowRelease", value: new ConnectEscrowReleaseV1({ vaultIds: a.stakes }) };
      case "duelSessionKey":
        return { case: "duelSessionKey", value: new ConnectDuelSessionKeyV1({ matchNonce: a.nonce }) };
      case "duelStake":
        return {
          case: "duelLock",
          value: new ConnectDuelLockV1({
            setup: a.setup,
            side: a.side === "A" ? 1 : 2,
            policyCommit: await this.objectId(a.object),
            amount: await this.units(a.object, a.amount),
            opponentGenesis: a.opponent.genesis,
            opponentDeviceId: a.opponent.deviceId,
            counterpartVaultId: a.against ?? new Uint8Array(0),
            memo: a.memo,
            opponentHoldings: a.opponentOwns,
          }),
        };
      case "duelReady":
        return {
          case: "duelReady",
          value: new ConnectDuelReadyV1({
            matchCell: a.cell,
            opponentReady: a.opponentReady ?? new Uint8Array(0),
            opponentReveal: a.opponentReveal ?? new Uint8Array(0),
          }),
        };
      case "duelWithdraw":
        return { case: "duelWithdraw", value: new ConnectDuelWithdrawV1({ matchCell: a.cell }) };
      case "duelSign":
        return {
          case: "duelSign",
          value: new ConnectDuelSignV1({
            matchCell: a.cell,
            preceding: a.preceding.map((e) => new ConnectDuelSignedEntryV1(e)),
            entry: a.entry,
          }),
        };
      case "duelSettle":
        return {
          case: "duelSettle",
          value: new ConnectDuelSettleV1({
            matchCell: a.cell,
            entries: a.entries.map((e) => new ConnectDuelSignedEntryV1(e)),
          }),
        };
      case "duelCollect":
        return { case: "duelCollect", value: new ConnectDuelCollectV1({ vaultIds: a.stakes }) };
    }
  }
}

export interface OfferOptions {
  /** The name the wallet shows the player. */
  name: string;
  /** What the application may ask for without asking the player again. */
  grants: Grant[];
  /** Objects the wallet takes up when it connects, so it can hold them. */
  adopt?: ObjectRef[];
  /** Requests the wallet answers before the application pays for more. Default 64. */
  freeRequests?: number;
}

/** A connect code, ready to show. */
export interface Offer {
  /** The `dsm:connect/v1:` text: show it as a QR code, or as a link on the same device. */
  code: string;
  digest: Uint8Array;
  raw: ConnectAppOfferV1;
}

export interface IssueOptions {
  /** 2 to 8 uppercase letters or digits: SWORD, GOLD. */
  symbol: string;
  name: string;
  /** The whole supply that will ever exist, in the object's own units: "1" for a unique item. */
  supply: string;
  /** Decimal places. Default 0. */
  decimals?: number;
  /** Holders can send it on. Default true. */
  transferable?: boolean;
  /** Holders can destroy it. Default false. */
  burnable?: boolean;
  description?: string;
  icon?: string;
}

/** A vault of this application's: two objects it trades between, at a fee. */
export interface Vault {
  id: Uint8Array;
  a: { object: string; symbol: string; reserve: bigint; display: string };
  b: { object: string; symbol: string; reserve: bigint; display: string };
  feeBps: number;
  /** Trades and closes it has taken. */
  generation: bigint;
  active: boolean;
  label: string;
  raw: SofiOwnedVaultV1;
}

function vaultOf(v: SofiOwnedVaultV1): Vault {
  return {
    id: v.vaultId,
    a: { object: encodeB32(v.tokenAPolicyCommit), symbol: v.tokenASymbol, reserve: v.reserveA, display: v.reserveADisplay },
    b: { object: encodeB32(v.tokenBPolicyCommit), symbol: v.tokenBSymbol, reserve: v.reserveB, display: v.reserveBDisplay },
    feeBps: v.feeBps,
    generation: v.generation,
    active: v.status === 1,
    label: v.label,
    raw: v,
  };
}

/** Who a match pays: side A, side B, or nobody (each stake back to its owner). */
export type Decision = "A" | "B" | "void";

const DECISIONS: Record<Decision, string> = { A: "a-wins", B: "b-wins", void: "void" };

/** Your application's own account. */
export class AppAccount extends Account {
  /** A connect code for a wallet to scan. The host names its own relay and certificate in it. */
  async offer(options: OfferOptions): Promise<Offer> {
    const route = "connect.app.offer";
    const request = new ConnectAppOfferRequestV1({
      displayName: options.name,
      scopes: await Promise.all(options.grants.map((g) => this.scope(g))),
      tokenAnchors: await this.ids(options.adopt ?? []),
      freeRequests: options.freeRequests ?? 64,
    });
    const offer = connectReply(route, await this.ingress.call("invoke", route, request), "offer");
    return { code: offer.code, digest: offer.offerDigest, raw: offer };
  }

  /** An offer this account made, by its digest. */
  async offerOf(digest: Uint8Array): Promise<Offer> {
    const route = "connect.app.offerOf";
    const request = new ConnectOfferRefV1({ offerDigest: digest });
    const offer = connectReply(route, await this.ingress.call("query", route, request, { quiet: true }), "offer");
    return { code: offer.code, digest: offer.offerDigest, raw: offer };
  }

  /** Every wallet connected to this application, and every one that disconnected. */
  async connections(): Promise<Connection[]> {
    const route = "connect.app.sessions";
    const envelope = await this.ingress.call("query", route, undefined, { quiet: true });
    return connectReply(route, envelope, "sessions").sessions.map(connectionOf);
  }

  /** One connection, by id. */
  async connection(ref: ConnectionRef): Promise<Connection> {
    const id = encodeB32(rawOf(ref, "the connection id"));
    const found = (await this.connections()).find((c) => c.id === id);
    if (found === undefined) throw new Error(`no connection ${id}`);
    return found;
  }

  /** Ask a connected wallet for something. The wallet answers on its own time: read it with `result` or `wait`. */
  async request(connection: ConnectionRef, what: Ask): Promise<RequestRef> {
    const route = "connect.app.request";
    const sessionId = rawOf(connection, "the connection id");
    const request = new ConnectAppRequestIntentV1({ sessionId, kind: await this.intent(what) });
    const ref = connectReply(route, await this.ingress.call("invoke", route, request), "request");
    return { connection: ref.sessionId, seq: ref.seq };
  }

  /**
   * What became of a request: the wallet's answer (a notification) and the
   * fact this account established itself (the evidence). Decide on the fact.
   */
  async result(ref: RequestRef): Promise<Result> {
    const route = "connect.app.status";
    const request = new ConnectRequestRefV1({ sessionId: ref.connection, seq: ref.seq });
    return resultOf(ref, connectReply(route, await this.ingress.call("invoke", route, request, { quiet: true }), "status"));
  }

  /**
   * Wait for a request to settle: a fact established, a declined or failed
   * answer, or (with `until: "answered"`) any answer, a held request included.
   * Throws after `timeoutMs` (default four minutes).
   */
  async wait(ref: RequestRef, options: { until?: "fact" | "answered"; timeoutMs?: number } = {}): Promise<Result> {
    const deadline = Date.now() + (options.timeoutMs ?? 240_000);
    for (;;) {
      const r = await this.result(ref);
      const done =
        options.until === "answered"
          ? r.answered || r.outcome === "awaiting_approval"
          : r.fact !== "none" || r.outcome === "declined" || r.outcome === "failed" || (r.answered && r.price !== undefined);
      if (done) return r;
      if (Date.now() > deadline) {
        throw new Error(`request ${ref.seq} did not settle: ${r.outcome}, ${r.reason || r.detail}`);
      }
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
  }

  /** Issue a new object. This account holds its whole supply, and can give it out. */
  async issue(options: IssueOptions): Promise<ObjectInfo> {
    const route = "token.create";
    const request = new TokenCreateRequest({
      ticker: options.symbol,
      alias: options.name,
      decimals: options.decimals ?? 0,
      genesisSupplyEntered: options.supply,
      burnEnabled: options.burnable ?? false,
      transferable: options.transferable ?? true,
      threshold: 1,
      description: options.description ?? "",
      iconUrl: options.icon ?? "",
    });
    const created = payload(route, await this.ingress.call("invoke", route, request), "tokenCreateResponse");
    if (!created.success) throw new Error(`issuing ${options.symbol}: ${created.message}`);
    const issued = (await this.owned()).find((o) => sameObject(o.object.raw, created.policyAnchor));
    if (issued === undefined) throw new Error(`issued ${options.symbol}, but this account does not list it yet`);
    return issued.object;
  }

  /**
   * Give a wallet `amount` of `object`, from what this account owns. The
   * wallet must have accepted the object first (`ask.accept`), unless it
   * already holds some. Returns once the transfer is sent.
   */
  async give(to: string | Uint8Array | Connection, object: ObjectRef, amount: Amount, memo = ""): Promise<void> {
    const route = "wallet.sendSmart";
    const recipient =
      typeof to === "string" ? decodeId(to, "the wallet's identity") : to instanceof Uint8Array ? to : to.raw.peerDeviceId;
    const info = await this.object(object);
    const request = new OnlineTransferSmartRequest({
      recipientDeviceId: recipient,
      amount: await this.display(info, amount),
      tokenId: info.symbol,
      memo,
    });
    const sent = payload(route, await this.ingress.call("invoke", route, request), "onlineTransferResponse");
    if (!sent.success) throw new Error(`giving ${describe(object)}: ${sent.message}`);
  }

  /** Open a vault that trades between `a` and `b`, funded from what this account owns. */
  async openVault(options: {
    a: ObjectRef;
    reserveA: Amount;
    b: ObjectRef;
    reserveB: Amount;
    /** The fee on each trade, in hundredths of a percent. Default 30 (0.30%). */
    feeBps?: number;
    label?: string;
  }): Promise<Vault> {
    const route = "sofi.createVault";
    const a = await this.object(options.a);
    const b = await this.object(options.b);
    const [first, second] = encodeB32(a.raw) < encodeB32(b.raw) ? [a, b] : [b, a];
    const reserves = { [a.id]: options.reserveA, [b.id]: options.reserveB };
    const request = new SofiCreateVaultRequest({
      tokenAPolicyCommit: first.raw,
      tokenBPolicyCommit: second.raw,
      reserveAEntered: await this.display(first, reserves[first.id] as Amount),
      reserveBEntered: await this.display(second, reserves[second.id] as Amount),
      feeBps: options.feeBps ?? 30,
      label: options.label ?? "",
    });
    const created = payload(route, await this.ingress.call("invoke", route, request), "sofiVaultCreatedResponse");
    const vault = (await this.vaults()).find((v) => encodeB32(v.id) === encodeB32(created.vaultId));
    if (vault === undefined) throw new Error("opened a vault, but this account does not list it yet");
    return vault;
  }

  /** Every vault this account owns. */
  async vaults(): Promise<Vault[]> {
    const route = "sofi.vaults";
    const envelope = await this.ingress.call("invoke", route, undefined, { quiet: true });
    return payload(route, envelope, "sofiVaultsResponse").vaults.map(vaultOf);
  }

  /** Close a vault: its reserves come back to this account. */
  async closeVault(id: Uint8Array): Promise<void> {
    const route = "sofi.close";
    await this.ingress.call("invoke", route, new SofiCloseRequest({ vaultId: id }));
  }

  /**
   * Decide a match this application referees: who the stake `stake` pays.
   * Both players' stakes share one verdict, so deciding either decides both.
   */
  async decide(stake: Uint8Array, decision: Decision): Promise<EscrowVerdictResponse> {
    const route = "escrow.adjudicate";
    const request = new EscrowOutcomeRequest({ vaultId: stake, outcome: new TextEncoder().encode(DECISIONS[decision]) });
    return payload(route, await this.ingress.call("invoke", route, request), "escrowVerdictResponse");
  }
}

/** A wallet's side: the terminal dev wallet, or any wallet you script. */
export class WalletAccount extends Account {
  /** What a connect code asks for, before anyone approves it. */
  async preview(code: string): Promise<Preview> {
    const route = "connect.preview";
    const request = new ConnectPreviewRequestV1({ code });
    return previewOf(connectReply(route, await this.ingress.call("query", route, request), "preview"));
  }

  /** Approve an offer. With no grants given it grants exactly what the offer asked. */
  async approve(offer: Preview | Uint8Array, granted: Grant[] = []): Promise<Connection> {
    const route = "connect.approve";
    const offerDigest = offer instanceof Uint8Array ? offer : offer.digest;
    const request = new ConnectApproveRequestV1({
      offerDigest,
      granted: await Promise.all(granted.map((g) => this.scope(g))),
    });
    return connectionOf(connectReply(route, await this.ingress.call("invoke", route, request), "session"));
  }

  /** Every application this wallet is connected to, and every one it left. */
  async connections(): Promise<Connection[]> {
    const route = "connect.list";
    const envelope = await this.ingress.call("query", route, undefined, { quiet: true });
    return connectReply(route, envelope, "sessions").sessions.map(connectionOf);
  }

  /** Fetch and carry out what connected applications asked, now. */
  async sync(): Promise<Connection[]> {
    const route = "connect.sync";
    return connectReply(route, await this.ingress.call("invoke", route, undefined), "sessions").sessions.map(connectionOf);
  }

  /** Requests outside a grant, waiting for the player. */
  async pending(): Promise<Pending[]> {
    const route = "connect.pending";
    const envelope = await this.ingress.call("query", route, undefined, { quiet: true });
    return connectReply(route, envelope, "pending").pending.map(pendingOf);
  }

  /** Approve or decline a waiting request. */
  async respond(connection: ConnectionRef, seq: bigint, decision: "approve" | "decline"): Promise<ConnectDecidedV1> {
    const route = "connect.respond";
    const request = new ConnectRespondRequestV1({
      sessionId: rawOf(connection, "the connection id"),
      seq,
      decision: decision === "approve" ? ConnectDecision.APPROVE : ConnectDecision.DECLINE,
    });
    return connectReply(route, await this.ingress.call("invoke", route, request), "decided");
  }

  /** Everything an application asked over a connection, and what came of it. */
  async log(connection: ConnectionRef): Promise<ConnectLogV1> {
    const route = "connect.log";
    const request = new ConnectSessionRefV1({ sessionId: rawOf(connection, "the connection id") });
    return connectReply(route, await this.ingress.call("query", route, request, { quiet: true }), "log");
  }

  /** End a connection. The application can ask nothing more of this wallet. */
  async disconnect(connection: ConnectionRef): Promise<Connection> {
    const route = "connect.disconnect";
    const request = new ConnectSessionRefV1({ sessionId: rawOf(connection, "the connection id") });
    return connectionOf(connectReply(route, await this.ingress.call("invoke", route, request), "session"));
  }
}
