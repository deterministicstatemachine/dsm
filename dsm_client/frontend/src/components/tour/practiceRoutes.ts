// SPDX-License-Identifier: Apache-2.0
//
// The guided tour's practice answers to router routes: the trade, liquidity,
// escrow, app-connection and token-creation routes the tour walks through.
// While the tour runs, the bridge hands every router call here first
// (bridge/practiceGate.ts). A route answered here never reaches Rust; its
// answer is framed as Rust frames one, so the real screens show what the real
// route does, on the practice wallet. Every amount is parsed and rendered by
// Rust (`wallet.amount`), as the practice wallet's balances are. A route this
// file does not answer goes on to the gate, which lets reads through to Rust
// and refuses everything else.

import * as pb from '../../proto/dsm_app_pb';
import { walletAmount, type AmountForms } from '../../dsm/amount';
import { decodeBase32Crockford, encodeBase32Crockford } from '../../utils/textId';
import type { TokenBalanceView } from '../../dsm/types';

/** What the tour waits for: the practice wallet reports each action it carries out. */
export type PracticeRouteEvent =
  | 'quoted'
  | 'traded'
  | 'vaultCreated'
  | 'vaultClosed'
  | 'escrowLocked'
  | 'escrowSigned'
  | 'escrowDecided'
  | 'escrowReleased'
  | 'appPreviewed'
  | 'appApproved'
  | 'appRequestDecided'
  | 'appDisconnected'
  | 'tokenCreated';

// Practice ids use only Base32 Crockford characters, so any code that decodes
// an id keeps working.
const PAD = '0'.repeat(52);
export const practiceId = (stem: string): string => (stem + PAD).slice(0, 52);

/** Bytes this module owns (a plain ArrayBuffer), as protobuf fields take them. */
type Bytes = Uint8Array<ArrayBuffer>;
const own = (bytes: Uint8Array): Bytes => new Uint8Array(bytes);
const fromB32 = (text: string): Bytes => own(decodeBase32Crockford(text));
const practiceBytes = (stem: string): Bytes => fromB32(practiceId(stem));

/** The connect code the tour hands the user: the practice wallet answers it, Rust never sees it. */
export const PRACTICE_CONNECT_CODE = 'dsm:connect/v1:PRACT1CEARCADE';
/** The id of the first liquidity vault the user creates in practice, which the tour hands to Close. */
export const PRACTICE_FIRST_VAULT_ID = practiceId('PRACT1CEVA1');
const PRACTICE_APP_NAME = 'Practice Arcade';
/** What the practice app may ask without the user: pay up to this much PLAY a time, and three times that in all. */
const PRACTICE_APP_PER_REQUEST = '5';
/** The request the practice app sends once connected, above what the grant covers, so it waits for the user. */
const PRACTICE_APP_ASK = '8';

/** What every practice token creation burns, as people count ERA (the real fee is Core's). */
const PRACTICE_CREATION_FEE = '10';

/** The practice market every practice swap prices against: PLAY against ERA, at this fee. */
const PRACTICE_MARKET_FEE_BPS = 30;
const PRACTICE_MARKET_PLAY = '1000';
const PRACTICE_MARKET_ERA = '500';

type Vault = {
  vaultId: Bytes;
  root: Bytes;
  tokenA: string; // anchor, Base32
  tokenB: string;
  reserveA: bigint;
  reserveB: bigint;
  feeBps: number;
  generation: bigint;
  status: pb.SofiVaultStatus;
  owned: 'mine' | 'market';
};

type EscrowOutcome = { outcome: Bytes; decidedBy: Bytes[]; pays: Bytes };

type Escrow = {
  vaultId: Bytes;
  verdictCell: Bytes;
  externalCommitment: Bytes;
  token: string; // anchor, Base32
  amount: AmountForms;
  outcomes: EscrowOutcome[];
  decided: Bytes | undefined;
  status: pb.SofiVaultStatus;
};

type AppSession = {
  sessionId: Bytes;
  status: pb.ConnectSessionStatus;
  spent: bigint;
  pending: { seq: bigint; amount: AmountForms }[];
  log: pb.ConnectLogEntryV1[];
  lastSeq: bigint;
};

/** The practice wallet's side of the routes: its balances and identity, and how it changes them. */
export interface PracticeBook {
  balances: TokenBalanceView[];
  identity: { genesisHash: string; deviceId: string };
  /** One change to the practice wallet at a time. */
  inTurn<T>(change: () => Promise<T>): Promise<T>;
  /** Practice ERA is counted before anything reads it. */
  ready(): Promise<void>;
  emit(event: PracticeRouteEvent): void;
}

const same = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((v, i) => v === b[i]);

function framed(payload: pb.Envelope['payload']): Uint8Array {
  const body = new pb.Envelope({ version: 3, payload }).toBinary();
  const out = new Uint8Array(body.length + 1);
  out[0] = 0x03;
  out.set(body, 1);
  return out;
}

const refused = (message: string): Uint8Array => framed({ case: 'error', value: new pb.Error({ message }) });

const connectReply = (reply: pb.ConnectReplyV1['reply']): Uint8Array =>
  framed({ case: 'connectReply', value: new pb.ConnectReplyV1({ reply }) });

/** The argument body a router call carries: its ArgPack's body. */
function bodyOf(args: Uint8Array): Uint8Array {
  return args.length === 0 ? args : pb.ArgPack.fromBinary(args).body;
}

const whyNot = (e: unknown): string => (e instanceof Error ? e.message : String(e));

/**
 * The router routes the practice wallet answers, by name. `answer` gives the
 * framed envelope for a route it carries out, or undefined for one it leaves to
 * the gate.
 */
export function practiceRoutes(book: PracticeBook): (method: string, args: Uint8Array) => Promise<Uint8Array | undefined> {
  const vaults: Vault[] = [];
  const escrows: Escrow[] = [];
  const sessions: AppSession[] = [];
  let position = BigInt(0);
  // One count per kind, so each practice id is known in advance: the tour hands the first vault's id to Close.
  const made = { vaults: 0, escrows: 0, sessions: 0, tokens: 0 };

  const holding = (anchor: string): TokenBalanceView | undefined =>
    book.balances.find((b) => b.policyAnchorB32 === anchor);
  const anchorOf = (commit: Uint8Array): string => encodeBase32Crockford(commit);
  const symbolOf = (anchor: string): string => {
    const held = holding(anchor);
    if (!held) throw new Error('You hold no such token in practice.');
    return held.symbol;
  };
  const decimalsOf = (anchor: string): number => {
    const held = holding(anchor);
    if (!held) throw new Error('You hold no such token in practice.');
    return held.decimals;
  };
  const shown = async (anchor: string, baseUnits: bigint): Promise<string> =>
    (await walletAmount({ decimals: decimalsOf(anchor) }, { baseUnits })).displayAmount;
  const entered = (anchor: string, text: string): Promise<AmountForms> =>
    walletAmount({ decimals: decimalsOf(anchor) }, { entered: text });
  const nextPosition = (): bigint => {
    position += BigInt(1);
    return position;
  };

  /** Moves `delta` base units into (positive) or out of (negative) a practice holding; Rust renders the balance. */
  async function adjust(anchor: string, delta: bigint): Promise<void> {
    const held = holding(anchor);
    if (!held) throw new Error('You hold no such token in practice.');
    const next = held.baseUnits + delta;
    if (next < BigInt(0)) throw new Error(`Not enough ${held.symbol}: you have ${held.displayAmount}.`);
    const forms = await walletAmount({ decimals: held.decimals }, { baseUnits: next });
    held.baseUnits = forms.baseUnits;
    held.displayAmount = forms.displayAmount;
  }

  /** The practice market, opened the first time a route needs it. */
  async function market(): Promise<void> {
    if (vaults.some((v) => v.owned === 'market')) return;
    await book.ready();
    const play = book.balances.find((b) => b.tokenId === 'PLAY');
    const era = book.balances.find((b) => b.tokenId === 'ERA');
    if (!play?.policyAnchorB32 || !era?.policyAnchorB32) return;
    vaults.push({
      vaultId: practiceBytes('PRACT1CEMARKET'),
      root: practiceBytes('PRACT1CEMARKETR00T'),
      tokenA: play.policyAnchorB32,
      tokenB: era.policyAnchorB32,
      reserveA: (await entered(play.policyAnchorB32, PRACTICE_MARKET_PLAY)).baseUnits,
      reserveB: (await entered(era.policyAnchorB32, PRACTICE_MARKET_ERA)).baseUnits,
      feeBps: PRACTICE_MARKET_FEE_BPS,
      generation: BigInt(1),
      status: pb.SofiVaultStatus.ACTIVE,
      owned: 'market',
    });
  }

  /** What `amountIn` of `tokenIn` buys from a vault: the constant product, after the vault's fee. */
  function quote(v: Vault, tokenIn: string, amountIn: bigint): bigint {
    const forward = v.tokenA === tokenIn;
    const reserveIn = forward ? v.reserveA : v.reserveB;
    const reserveOut = forward ? v.reserveB : v.reserveA;
    const afterFee = (amountIn * BigInt(10_000 - v.feeBps)) / BigInt(10_000);
    return (reserveOut * afterFee) / (reserveIn + afterFee);
  }

  const vaultFor = (tokenIn: string, tokenOut: string): Vault | undefined =>
    vaults.find((v) => v.status === pb.SofiVaultStatus.ACTIVE
      && ((v.tokenA === tokenIn && v.tokenB === tokenOut) || (v.tokenA === tokenOut && v.tokenB === tokenIn)));

  async function findRoute(body: Uint8Array): Promise<Uint8Array | undefined> {
    await market();
    const req = pb.SofiFindRouteRequest.fromBinary(body);
    const tokenIn = anchorOf(req.tokenInPolicyCommit);
    const tokenOut = anchorOf(req.tokenOutPolicyCommit);
    const v = vaultFor(tokenIn, tokenOut);
    // Not a practice pair: the route is a read, and Rust answers it.
    if (!v || !holding(tokenIn) || !holding(tokenOut)) return undefined;
    const amountIn = await entered(tokenIn, req.amountInEntered);
    const amountOut = quote(v, tokenIn, amountIn.baseUnits);
    const amountOutDisplay = await shown(tokenOut, amountOut);
    book.emit('quoted');
    return framed({
      case: 'sofiFindRouteResponse',
      value: new pb.SofiFindRouteResponse({
        hops: [new pb.SofiHopV1({
          vaultId: v.vaultId,
          parentRoot: v.root,
          tokenInPolicyCommit: req.tokenInPolicyCommit,
          tokenOutPolicyCommit: req.tokenOutPolicyCommit,
          amountIn: amountIn.baseUnits,
          amountOut,
          amountInDisplay: amountIn.displayAmount,
          amountOutDisplay,
        })],
        search: pb.SofiSearch.COMPLETE,
        shape: pb.SofiRouteShape.CHAIN,
        amountIn: amountIn.baseUnits,
        amountOut,
        amountInDisplay: amountIn.displayAmount,
        amountOutDisplay,
      }),
    });
  }

  const positionAnswer = (state: pb.SofiPositionState, at: bigint): Uint8Array =>
    framed({ case: 'sofiPositionResponse', value: new pb.SofiPositionResponse({ position: at, state }) });

  /** One hop against one practice vault: realized, or void when it gives less than the least accepted. */
  async function trade(vaultId: Uint8Array, tokenIn: string, tokenOut: string, amountText: string, minText: string): Promise<Uint8Array> {
    const v = vaults.find((x) => same(x.vaultId, vaultId) && x.status === pb.SofiVaultStatus.ACTIVE);
    if (!v) return refused('sofi.trade: no such vault in practice');
    return book.inTurn(async () => {
      const amountIn = await entered(tokenIn, amountText);
      const least = await entered(tokenOut, minText.trim() === '' ? '0' : minText);
      const amountOut = quote(v, tokenIn, amountIn.baseUnits);
      // Another trade won the race, or the price moved: void, and nothing moved.
      if (amountOut < least.baseUnits) return positionAnswer(pb.SofiPositionState.VOID, nextPosition());
      await adjust(tokenIn, -amountIn.baseUnits);
      await adjust(tokenOut, amountOut);
      const forward = v.tokenA === tokenIn;
      v.reserveA += forward ? amountIn.baseUnits : -amountOut;
      v.reserveB += forward ? -amountOut : amountIn.baseUnits;
      v.generation += BigInt(1);
      book.emit('traded');
      return positionAnswer(pb.SofiPositionState.REALIZED, nextPosition());
    });
  }

  async function createVault(body: Uint8Array): Promise<Uint8Array> {
    const req = pb.SofiCreateVaultRequest.fromBinary(body);
    const tokenA = anchorOf(req.tokenAPolicyCommit);
    const tokenB = anchorOf(req.tokenBPolicyCommit);
    if (tokenA === tokenB) return refused('sofi.createVault: a vault holds two different tokens');
    return book.inTurn(async () => {
      const reserveA = await entered(tokenA, req.reserveAEntered);
      const reserveB = await entered(tokenB, req.reserveBEntered);
      await adjust(tokenA, -reserveA.baseUnits);
      await adjust(tokenB, -reserveB.baseUnits).catch(async (e: unknown) => {
        await adjust(tokenA, reserveA.baseUnits);
        throw e;
      });
      made.vaults += 1;
      const vaultId = practiceBytes(`PRACT1CEVA${made.vaults}`);
      vaults.push({
        vaultId,
        root: practiceBytes(`PRACT1CEVAR00T${made.vaults}`),
        tokenA,
        tokenB,
        reserveA: reserveA.baseUnits,
        reserveB: reserveB.baseUnits,
        feeBps: req.feeBps,
        generation: BigInt(1),
        status: pb.SofiVaultStatus.ACTIVE,
        owned: 'mine',
      });
      book.emit('vaultCreated');
      return framed({
        case: 'sofiVaultCreatedResponse',
        value: new pb.SofiVaultCreatedResponse({ vaultId, position: nextPosition() }),
      });
    });
  }

  async function ownedVaults(): Promise<Uint8Array> {
    const rows = await Promise.all(vaults.filter((v) => v.owned === 'mine').map(async (v) => new pb.SofiOwnedVaultV1({
      vaultId: v.vaultId,
      tokenAPolicyCommit: fromB32(v.tokenA),
      tokenBPolicyCommit: fromB32(v.tokenB),
      tokenASymbol: symbolOf(v.tokenA),
      tokenBSymbol: symbolOf(v.tokenB),
      reserveA: v.reserveA,
      reserveB: v.reserveB,
      reserveADisplay: await shown(v.tokenA, v.reserveA),
      reserveBDisplay: await shown(v.tokenB, v.reserveB),
      feeBps: v.feeBps,
      generation: v.generation,
      status: v.status,
    })));
    return framed({ case: 'sofiVaultsResponse', value: new pb.SofiVaultsResponse({ vaults: rows }) });
  }

  async function close(body: Uint8Array): Promise<Uint8Array> {
    const req = pb.SofiCloseRequest.fromBinary(body);
    const v = vaults.find((x) => same(x.vaultId, req.vaultId) && x.owned === 'mine' && x.status === pb.SofiVaultStatus.ACTIVE);
    if (!v) return refused('sofi.close: Close is for a vault of your own, still open');
    return book.inTurn(async () => {
      await adjust(v.tokenA, v.reserveA);
      await adjust(v.tokenB, v.reserveB);
      v.reserveA = BigInt(0);
      v.reserveB = BigInt(0);
      v.status = pb.SofiVaultStatus.RETIRED;
      v.generation += BigInt(1);
      book.emit('vaultClosed');
      return positionAnswer(pb.SofiPositionState.REALIZED, nextPosition());
    });
  }

  // ── Escrow ────────────────────────────────────────────────────────────────
  const me = (): Bytes => fromB32(book.identity.deviceId);
  const myGenesis = (): Bytes => fromB32(book.identity.genesisHash);

  async function escrowLock(body: Uint8Array): Promise<Uint8Array> {
    const req = pb.EscrowLockRequest.fromBinary(body);
    const token = anchorOf(req.tokenPolicyCommit);
    if (req.outcomes.length === 0) return refused('escrow.lock: the terms list no outcome');
    return book.inTurn(async () => {
      const amount = await entered(token, req.amountEntered);
      if (amount.baseUnits <= BigInt(0)) return refused('escrow.lock: stake an amount above zero');
      await adjust(token, -amount.baseUnits);
      made.escrows += 1;
      const escrow: Escrow = {
        vaultId: practiceBytes(`PRACT1CEESCR0W${made.escrows}`),
        verdictCell: practiceBytes(`PRACT1CEVERD1CT${made.escrows}`),
        externalCommitment: practiceBytes(`PRACT1CEAGREE${made.escrows}`),
        token,
        amount,
        outcomes: req.outcomes.map((o) => ({ outcome: own(o.outcome), decidedBy: o.decidedBy.map(own), pays: own(o.pays) })),
        decided: undefined,
        status: pb.SofiVaultStatus.ACTIVE,
      };
      escrows.push(escrow);
      book.emit('escrowLocked');
      return framed({
        case: 'escrowCreatedResponse',
        value: new pb.EscrowCreatedResponse({
          vaultId: escrow.vaultId,
          verdictCell: escrow.verdictCell,
          externalCommitment: escrow.externalCommitment,
          position: nextPosition(),
        }),
      });
    });
  }

  const escrowRows = (list: Escrow[]): Uint8Array => framed({
    case: 'escrowVaultsResponse',
    value: new pb.EscrowVaultsResponse({
      search: pb.SofiSearch.COMPLETE,
      vaults: list.map((e) => new pb.EscrowVaultV1({
        vaultId: e.vaultId,
        ownerGenesis: myGenesis(),
        ownerDeviceId: me(),
        verdictCell: e.verdictCell,
        externalCommitment: e.externalCommitment,
        tokenPolicyCommit: fromB32(e.token),
        tokenSymbol: symbolOf(e.token),
        amount: e.amount.baseUnits,
        amountDisplay: e.amount.displayAmount,
        generation: BigInt(1),
        status: e.status,
        outcomes: e.outcomes.map((o) => new pb.EscrowVaultOutcomeV1({
          outcome: o.outcome,
          recipientDeviceId: o.pays,
          decidedByThisDevice: o.decidedBy.some((d) => same(d, me())),
          paysThisDevice: same(o.pays, me()),
        })),
      })),
    }),
  });

  const escrowOf = (vaultId: Uint8Array): Escrow | undefined => escrows.find((e) => same(e.vaultId, vaultId));

  const verdictAnswer = (e: Escrow): Uint8Array => framed({
    case: 'escrowVerdictResponse',
    value: new pb.EscrowVerdictResponse({
      verdictCell: e.verdictCell,
      state: e.decided === undefined ? pb.EscrowVerdictState.NONE : pb.EscrowVerdictState.FINAL,
      outcome: e.decided ?? own(new Uint8Array(0)),
    }),
  });

  async function escrowDecide(body: Uint8Array, signOnly: 'sign' | 'decide'): Promise<Uint8Array> {
    const req = pb.EscrowOutcomeRequest.fromBinary(body);
    const e = escrowOf(req.vaultId);
    if (!e) return refused('escrow: no such escrow vault in practice');
    const named = e.outcomes.find((o) => same(o.outcome, req.outcome));
    if (!named) return refused('escrow: the terms list no such outcome');
    if (!named.decidedBy.some((d) => same(d, me()))) return refused('escrow: this device does not decide that outcome');
    if (signOnly === 'sign') {
      book.emit('escrowSigned');
      return framed({
        case: 'escrowSignedResponse',
        value: new pb.EscrowSignedResponse({ verdictCell: e.verdictCell, gathered: practiceBytes('PRACT1CES1GNED') }),
      });
    }
    if (e.decided === undefined) e.decided = named.outcome;
    book.emit('escrowDecided');
    return verdictAnswer(e);
  }

  async function escrowRelease(body: Uint8Array): Promise<Uint8Array> {
    const req = pb.EscrowReleaseRequest.fromBinary(body);
    const e = escrowOf(req.vaultId);
    if (!e || e.status !== pb.SofiVaultStatus.ACTIVE) return refused('escrow.release: no open escrow vault by that id');
    const decided = e.decided;
    if (decided === undefined) return refused('escrow.release: no outcome is decided yet');
    const outcome = e.outcomes.find((o) => same(o.outcome, decided));
    if (!outcome || !same(outcome.pays, me())) return refused('escrow.release: only the party the decided outcome pays releases the stake');
    return book.inTurn(async () => {
      await adjust(e.token, e.amount.baseUnits);
      e.status = pb.SofiVaultStatus.RETIRED;
      book.emit('escrowReleased');
      return positionAnswer(pb.SofiPositionState.REALIZED, nextPosition());
    });
  }

  // ── Apps (DSM Connect) ───────────────────────────────────────────────────
  const playAnchor = (): string | undefined => book.balances.find((b) => b.tokenId === 'PLAY')?.policyAnchorB32;

  async function scopeLines(): Promise<string[]> {
    const play = playAnchor();
    if (!play) return [];
    const each = await entered(play, PRACTICE_APP_PER_REQUEST);
    const all = await walletAmount({ decimals: each.decimals }, { baseUnits: each.baseUnits * BigInt(3) });
    return [
      `Send this app: up to ${each.displayAmount} PLAY a time, ${all.displayAmount} PLAY in all`,
      'Prove what you own of PLAY',
    ];
  }

  async function sessionView(s: AppSession): Promise<pb.ConnectSessionV1> {
    const play = playAnchor();
    const lines = await scopeLines();
    const spent = play ? await shown(play, s.spent) : '';
    const each = play ? await entered(play, PRACTICE_APP_PER_REQUEST) : undefined;
    const total = play && each ? await shown(play, each.baseUnits * BigInt(3)) : '';
    return new pb.ConnectSessionV1({
      sessionId: s.sessionId,
      displayName: PRACTICE_APP_NAME,
      peerDeviceId: practiceBytes('PRACT1CEAPP'),
      endpoint: 'practice mode',
      lastSeq: s.lastSeq,
      status: s.status,
      scopeLines: lines,
      spent: play ? [new pb.ConnectSpentV1({ policyCommit: fromB32(play), spent: s.spent, spentDisplay: spent, totalDisplay: total, symbol: 'PLAY' })] : [],
    });
  }

  const sessionOf = (id: Uint8Array): AppSession | undefined => sessions.find((s) => same(s.sessionId, id));

  async function connectPreview(body: Uint8Array): Promise<Uint8Array | undefined> {
    const req = pb.ConnectPreviewRequestV1.fromBinary(body);
    // Any other code is a real application's: the gate keeps it from Rust.
    if (req.code.trim() !== PRACTICE_CONNECT_CODE) return undefined;
    await book.ready();
    book.emit('appPreviewed');
    return connectReply({
      case: 'preview',
      value: new pb.ConnectPreviewV1({
        offerDigest: practiceBytes('PRACT1CE0FFER'),
        displayName: PRACTICE_APP_NAME,
        appDeviceId: practiceBytes('PRACT1CEAPP'),
        endpoint: 'practice mode',
        scopeLines: await scopeLines(),
      }),
    });
  }

  async function connectApprove(body: Uint8Array): Promise<Uint8Array | undefined> {
    const req = pb.ConnectApproveRequestV1.fromBinary(body);
    if (!same(req.offerDigest, practiceBytes('PRACT1CE0FFER'))) return undefined;
    const play = playAnchor();
    if (!play) return refused('connect.approve: the practice wallet holds no PLAY');
    made.sessions += 1;
    // Once connected, the practice app asks for more than the grant covers: that request waits here.
    const s: AppSession = {
      sessionId: practiceBytes(`PRACT1CESESS10N${made.sessions}`),
      status: pb.ConnectSessionStatus.CONNECTED,
      spent: BigInt(0),
      pending: [{ seq: BigInt(1), amount: await entered(play, PRACTICE_APP_ASK) }],
      log: [],
      lastSeq: BigInt(1),
    };
    sessions.push(s);
    book.emit('appApproved');
    return connectReply({ case: 'session', value: await sessionView(s) });
  }

  const sessionList = async (): Promise<Uint8Array> => connectReply({
    case: 'sessions',
    value: new pb.ConnectSessionsV1({ sessions: await Promise.all(sessions.map(sessionView)) }),
  });

  const pendingList = (): Uint8Array => connectReply({
    case: 'pending',
    value: new pb.ConnectPendingListV1({
      pending: sessions.filter((s) => s.status === pb.ConnectSessionStatus.CONNECTED).flatMap((s) => s.pending.map((p) => new pb.ConnectPendingV1({
        sessionId: s.sessionId,
        seq: p.seq,
        displayName: PRACTICE_APP_NAME,
        summary: `Send ${p.amount.displayAmount} PLAY for a bigger box`,
        reason: `${p.amount.displayAmount} PLAY is above the ${PRACTICE_APP_PER_REQUEST} PLAY the grant allows per request`,
      }))),
    }),
  });

  async function connectRespond(body: Uint8Array): Promise<Uint8Array | undefined> {
    const req = pb.ConnectRespondRequestV1.fromBinary(body);
    const s = sessionOf(req.sessionId);
    if (!s) return undefined;
    const waiting = s.pending.find((p) => p.seq === req.seq);
    if (!waiting) return refused('connect.respond: nothing waits under that request');
    const play = playAnchor();
    if (!play) return refused('connect.respond: the practice wallet holds no PLAY');
    return book.inTurn(async () => {
      s.pending = s.pending.filter((p) => p.seq !== req.seq);
      const summary = `Send ${waiting.amount.displayAmount} PLAY for a bigger box`;
      let outcome = pb.ConnectOutcome.DECLINED;
      if (req.decision === pb.ConnectDecision.APPROVE) {
        await adjust(play, -waiting.amount.baseUnits);
        s.spent += waiting.amount.baseUnits;
        outcome = pb.ConnectOutcome.CARRIED_OUT;
      }
      const word = outcome === pb.ConnectOutcome.CARRIED_OUT ? 'carried out' : 'declined';
      s.log.push(new pb.ConnectLogEntryV1({ seq: req.seq, summary, outcome, detail: word }));
      book.emit('appRequestDecided');
      return connectReply({
        case: 'decided',
        value: new pb.ConnectDecidedV1({ session: await sessionView(s), outcome, line: `${PRACTICE_APP_NAME}: ${summary}, ${word}.` }),
      });
    });
  }

  async function connectDisconnect(body: Uint8Array): Promise<Uint8Array | undefined> {
    const s = sessionOf(pb.ConnectSessionRefV1.fromBinary(body).sessionId);
    if (!s) return undefined;
    s.status = pb.ConnectSessionStatus.DISCONNECTED;
    s.pending = [];
    book.emit('appDisconnected');
    return connectReply({ case: 'session', value: await sessionView(s) });
  }

  function connectLog(body: Uint8Array): Uint8Array | undefined {
    const s = sessionOf(pb.ConnectSessionRefV1.fromBinary(body).sessionId);
    if (!s) return undefined;
    return connectReply({ case: 'log', value: new pb.ConnectLogV1({ entries: s.log }) });
  }

  // ── Token creation ───────────────────────────────────────────────────────
  async function tokenCreate(body: Uint8Array): Promise<Uint8Array> {
    const pack = pb.TokenCreateRequest.fromBinary(body);
    const ticker = pack.ticker.trim().toUpperCase();
    if (ticker === '') return refused('token.create: name a ticker');
    if (book.balances.some((b) => b.symbol.toUpperCase() === ticker)) {
      return refused(`token.create: you already hold a token called ${ticker}`);
    }
    await book.ready();
    const era = book.balances.find((b) => b.tokenId === 'ERA');
    if (!era?.policyAnchorB32) return refused('token.create: practice ERA is not counted yet');
    const eraAnchor = era.policyAnchorB32;
    // A created token is held as the practice coin is: a token of the user's, not one the protocol defines.
    const coin = book.balances.find((b) => b.tokenId === 'PLAY');
    if (!coin) return refused('token.create: the practice wallet holds no practice coin');
    return book.inTurn(async () => {
      const supply = await walletAmount({ decimals: pack.decimals }, { entered: pack.genesisSupplyEntered });
      if (supply.baseUnits <= BigInt(0)) return refused('token.create: the supply must be above zero');
      const fee = await entered(eraAnchor, PRACTICE_CREATION_FEE);
      await adjust(eraAnchor, -fee.baseUnits);
      made.tokens += 1;
      const anchor = practiceId(`PRACT1CET0KEN${made.tokens}`);
      book.balances.push({
        tokenId: ticker,
        tokenName: pack.alias.trim() === '' ? ticker : pack.alias.trim(),
        symbol: ticker,
        decimals: supply.decimals,
        baseUnits: supply.baseUnits,
        displayAmount: supply.displayAmount,
        protocolDefined: coin.protocolDefined,
        policyAnchorB32: anchor,
        anchorFingerprint: anchor.slice(0, 8),
      });
      const created = book.balances.some((b) => b.policyAnchorB32 === anchor);
      book.emit('tokenCreated');
      return framed({
        case: 'tokenCreateResponse',
        value: new pb.TokenCreateResponse({
          success: created,
          tokenId: ticker,
          policyAnchor: fromB32(anchor),
          message: `Practice: created ${ticker}. ${fee.displayAmount} ERA burned.`,
          ticker,
        }),
      });
    });
  }

  return async (method: string, args: Uint8Array): Promise<Uint8Array | undefined> => {
    try {
      const body = bodyOf(args);
      switch (method) {
        case 'sofi.findRoute': return await findRoute(body);
        case 'sofi.trade': {
          const r = pb.SofiTradeRequest.fromBinary(body);
          return await trade(r.vaultId, anchorOf(r.tokenInPolicyCommit), anchorOf(r.tokenOutPolicyCommit), r.amountInEntered, r.minAmountOutEntered);
        }
        case 'sofi.route': {
          const r = pb.SofiRouteRequest.fromBinary(body);
          const first = r.vaultIds[0];
          if (first === undefined) return refused('sofi.route: the route names no vault');
          return await trade(first, anchorOf(r.tokenInPolicyCommit), anchorOf(r.tokenOutPolicyCommit), r.amountInEntered, r.minAmountOutEntered);
        }
        case 'sofi.createVault': return await createVault(body);
        case 'sofi.vaults': return await ownedVaults();
        case 'sofi.close': return await close(body);
        case 'escrow.party':
          return framed({ case: 'escrowPartyResponse', value: new pb.EscrowPartyResponse({ genesis: myGenesis(), deviceId: me() }) });
        case 'escrow.lock': return await escrowLock(body);
        case 'escrow.vaults': return escrowRows(escrows);
        case 'escrow.locked': {
          const cell = pb.EscrowLockedRequest.fromBinary(body).verdictCell;
          return escrowRows(escrows.filter((e) => same(e.verdictCell, cell)));
        }
        case 'escrow.verdict': {
          const e = escrowOf(pb.EscrowVerdictRequest.fromBinary(body).vaultId);
          return e ? verdictAnswer(e) : refused('escrow.verdict: no such escrow vault in practice');
        }
        case 'escrow.sign': return await escrowDecide(body, 'sign');
        case 'escrow.adjudicate': return await escrowDecide(body, 'decide');
        case 'escrow.release': return await escrowRelease(body);
        case 'connect.preview': return await connectPreview(body);
        case 'connect.approve': return await connectApprove(body);
        case 'connect.list':
        case 'connect.sync': return await sessionList();
        case 'connect.pending': return pendingList();
        case 'connect.respond': return await connectRespond(body);
        case 'connect.disconnect': return await connectDisconnect(body);
        case 'connect.log': return connectLog(body);
        case 'token.create': return await tokenCreate(body);
        default: return undefined;
      }
    } catch (e) {
      // A refusal is the route's answer, in the words of whoever refused.
      return refused(`${method}: ${whyNot(e)}`);
    }
  };
}
