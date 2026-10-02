// SPDX-License-Identifier: Apache-2.0
//
// Practice mode for the guided tour.
//
// While the tour runs, the real screens stay on screen but the calls they make
// for the things a beginner tries (balances, contacts, history, sending, the
// faucet, adding a contact) are answered from a small in-memory practice
// wallet. Every other call whose name says it changes state is refused. When
// the tour ends, the real client is put back exactly as it was, so nothing the
// user does in the tour ever reaches the device's real state.
//
// Every figure the practice wallet shows is Rust's. It asks `wallet.amount` to
// parse what the user typed and to render each balance it keeps, as the real
// wallet's figures are parsed and rendered, so practice ERA counts as ERA does.

import { dsmClient } from '../../services/dsmClient';
import { walletAmount } from '../../dsm/amount';
import type { AmountForms } from '../../dsm/amount';
import type {
  DomainContact,
  DomainIdentity,
  DomainTransaction,
} from '../../domain/types';
import type { TokenBalanceView } from '../../dsm/types';

export type PracticeEvent = 'sent' | 'claimed' | 'contactAdded';

export const PRACTICE_BLOCKED_MESSAGE =
  'Practice mode: this is switched off until the tour ends. Your real wallet is untouched.';

/** Calls whose names start like this change state, so practice mode refuses them. */
const STATE_CHANGING =
  /^(send|load|unload|create|claim|add|remove|delete|publish|withdraw|deposit|swap|import|export|mint|burn|update|accept|reject|register|approve|revoke|write|reset|close|open|unlock|lock|execute|submit|broadcast|sign|pair|unpair|sync|reconcile|recover|restore|enroll|admit|fund|redeem|transfer|post|put|store|bind|advance|commit|finalize|apply|generate|start|stop|cancel|retry|refresh|clear|forget|rotate|set)/;

/** Real even in practice: display preferences only. */
const ALWAYS_REAL = new Set(['getPreference', 'setPreference']);

// Practice ids use only Base32 Crockford characters, so any code that decodes
// an id keeps working.
const PAD = '0'.repeat(52);
const practiceId = (stem: string): string => (stem + PAD).slice(0, 52);

export const PRACTICE_CONTACT_ALIAS = 'alice';
/** The practice contact's device id: what the send screen names a recipient by. */
export const PRACTICE_CONTACT_DEVICE_ID = practiceId('PRACT1CEA11CE');
/** The practice ERA the tour starts with, and what its faucet pays, as people count ERA. */
export const PRACTICE_ERA_HELD = '1000';
export const PRACTICE_FAUCET_AMOUNT = '100';

type PracticeState = {
  identity: DomainIdentity;
  balances: TokenBalanceView[];
  contacts: DomainContact[];
  history: DomainTransaction[];
  sequence: number;
};

function freshState(): PracticeState {
  return {
    identity: {
      genesisHash: practiceId('PRACT1CEY0VGENES1S'),
      deviceId: practiceId('PRACT1CEY0VDEV1CE'),
    },
    // The practice coin is counted in whole units. Practice ERA joins it once
    // Rust has counted it (seedEra).
    balances: [
      { tokenId: 'PLAY', tokenName: 'Practice Coin', symbol: 'PLAY', decimals: 0, baseUnits: BigInt(50), displayAmount: '50', protocolDefined: false },
    ],
    contacts: [
      {
        alias: PRACTICE_CONTACT_ALIAS,
        deviceId: PRACTICE_CONTACT_DEVICE_ID,
        genesisHash: practiceId('PRACT1CEA11CEGENES1S'),
        signingPublicKey: practiceId('PRACT1CEA11CEKEY'),
        // Practice contacts are never paired over BLE.
        pairing: 'idle',
        genesisVerifiedOnline: true,
        sendReady: true,
        sendCheckState: 'ready',
      },
    ],
    history: [],
    sequence: 0,
  };
}

/**
 * Practice ERA as Rust counts ERA: the tour's starting amount parsed at the
 * decimals of ERA's committed policy, and the welcome payment that brought it.
 */
async function seedEra(state: PracticeState): Promise<void> {
  const held = await walletAmount({ tokenId: 'ERA' }, { entered: PRACTICE_ERA_HELD });
  state.balances.unshift({
    tokenId: 'ERA',
    tokenName: 'ERA',
    symbol: 'ERA',
    decimals: held.decimals,
    baseUnits: held.baseUnits,
    displayAmount: held.displayAmount,
    protocolDefined: true,
  });
  state.history.push({
    txId: 'practice-welcome',
    txHash: practiceId('PRACT1CEWE1C0ME'),
    txType: 'online',
    type: 'online',
    amount: held.baseUnits,
    displayAmount: held.displayAmount,
    tokenId: 'ERA',
    recipient: 'practice',
    status: 'confirmed',
    fromDeviceId: practiceId('PRACT1CESENDER'),
    toDeviceId: practiceId('PRACT1CEY0VDEV1CE'),
    memo: 'Practice tokens for the tour',
    receiptVerified: false,
  });
}

const pause = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** A practice debit: the balance left and the amount taken, or why it was refused. */
type Debit = { balance: bigint; taken: AmountForms } | { refused: string };

/**
 * Takes `amount`, as the user typed it, from a practice holding. Rust parses it
 * at the holding's decimals as a send parses it, and renders what is left; a
 * refusal is Rust's, in its words.
 */
async function debit(state: PracticeState, tokenId: string, amount: string | number | bigint): Promise<Debit> {
  const holding = state.balances.find((b) => b.tokenId === tokenId);
  if (!holding) return { refused: `You hold no ${tokenId} in practice.` };
  let taken: AmountForms;
  try {
    taken = await walletAmount({ decimals: holding.decimals }, { entered: String(amount) });
  } catch (e) {
    return { refused: e instanceof Error ? e.message : String(e) };
  }
  if (taken.baseUnits <= BigInt(0)) return { refused: 'Enter an amount above zero.' };
  if (taken.baseUnits > holding.baseUnits) {
    return { refused: `Not enough ${holding.symbol}: you have ${holding.displayAmount}.` };
  }
  const left = await walletAmount({ decimals: holding.decimals }, { baseUnits: holding.baseUnits - taken.baseUnits });
  holding.baseUnits = left.baseUnits;
  holding.displayAmount = left.displayAmount;
  return { balance: holding.baseUnits, taken };
}

/** Adds `amount`, as people count the token, to a practice holding; Rust parses and renders it. */
async function credit(state: PracticeState, tokenId: string, amount: string): Promise<AmountForms> {
  const holding = state.balances.find((b) => b.tokenId === tokenId);
  if (!holding) throw new Error(`You hold no ${tokenId} in practice.`);
  const paid = await walletAmount({ decimals: holding.decimals }, { entered: amount });
  const now = await walletAmount({ decimals: holding.decimals }, { baseUnits: holding.baseUnits + paid.baseUnits });
  holding.baseUnits = now.baseUnits;
  holding.displayAmount = now.displayAmount;
  return paid;
}

function recordSend(state: PracticeState, to: string, tokenId: string, taken: AmountForms, memo: string | undefined, mode: 'online' | 'offline'): string {
  state.sequence += 1;
  const txId = `practice-${state.sequence}`;
  const contact = state.contacts.find((c) => c.deviceId === to);
  state.history = [
    {
      txId,
      txHash: practiceId(`PRACT1CETX${state.sequence}`),
      txType: mode === 'offline' ? 'bilateral_offline' : 'online',
      type: mode,
      amount: -taken.baseUnits,
      // An outgoing amount, signed as Rust signs one: its rendered form after a minus.
      displayAmount: `-${taken.displayAmount}`,
      tokenId,
      recipient: contact?.alias ?? to,
      status: 'confirmed',
      fromDeviceId: state.identity.deviceId,
      toDeviceId: contact?.deviceId ?? practiceId('PRACT1CEPEER'),
      memo,
      receiptVerified: false,
    },
    ...state.history,
  ];
  return txId;
}

type AnyFn = (...args: never[]) => unknown;

function simulations(state: PracticeState, emit: (event: PracticeEvent) => void): Record<string, AnyFn> {
  // Practice ERA is counted by Rust the first time a call needs it, and every
  // such call waits for that count; a refusal is the call's answer.
  let seeded: Promise<void> | undefined;
  const ready = (): Promise<void> => {
    if (!seeded) seeded = seedEra(state);
    return seeded;
  };
  // One change to the practice wallet at a time: a debit's check and the
  // balance Rust renders after it belong together, so the next change waits.
  let turn: Promise<unknown> = Promise.resolve();
  const inTurn = <T>(change: () => Promise<T>): Promise<T> => {
    const next = turn.then(change, change);
    turn = next;
    return next;
  };
  return {
    getIdentity: async () => ({ ...state.identity }),
    getAllBalances: async () => {
      await ready();
      return state.balances.map((b) => ({ ...b }));
    },
    getContacts: async () => ({ contacts: state.contacts.map((c) => ({ ...c })) }),
    getWalletHistory: async () => {
      await ready();
      return { transactions: [...state.history] };
    },
    sendOnlineTransferSmart: async (recipientDeviceId: string, enteredAmount: string | number | bigint, memo?: string, tokenId?: string) => {
      await pause(700);
      // As Rust answers: a send that names no token is refused, never sent as ERA.
      if (!tokenId) return { success: false, message: 'wallet.sendSmart: the request names no token' };
      const token = tokenId;
      await ready();
      const result = await inTurn(() => debit(state, token, enteredAmount));
      // The real call answers a refusal as { success, message }.
      if ('refused' in result) return { success: false, message: result.refused };
      recordSend(state, recipientDeviceId, token, result.taken, memo, 'online');
      emit('sent');
      return { success: true, newBalance: result.balance };
    },
    // Answers in the shape the real sendOfflineTransfer does (GenericTxResponse).
    sendOfflineTransfer: async (params: { tokenId: string; to: string; amount: number | bigint | string; memo?: string }) => {
      await pause(700);
      if (!params.tokenId) return { accepted: false, result: 'wallet.sendOffline: the request names no token' };
      const token = params.tokenId;
      await ready();
      const result = await inTurn(() => debit(state, token, params.amount));
      if ('refused' in result) return { accepted: false, result: result.refused };
      recordSend(state, params.to, token, result.taken, params.memo, 'offline');
      emit('sent');
      return { accepted: true, result: 'Practice transfer complete' };
    },
    // Answers in the shape the real claimFaucet does; the faucet releases ERA,
    // and its message shows ERA as Rust renders it.
    claimFaucet: async () => {
      await pause(600);
      await ready();
      const paid = await inTurn(() => credit(state, 'ERA', PRACTICE_FAUCET_AMOUNT));
      emit('claimed');
      return {
        success: true,
        tokensReceived: paid.baseUnits,
        message: `Practice: claimed ${paid.displayAmount} ERA`,
      };
    },
    addContact: async (input: { alias: string; genesisHash: string | Uint8Array; deviceId: string | Uint8Array }) => {
      await pause(400);
      state.contacts.push({
        alias: input.alias,
        genesisHash: typeof input.genesisHash === 'string' ? input.genesisHash : practiceId('PRACT1CEGENES1S'),
        deviceId: typeof input.deviceId === 'string' ? input.deviceId : practiceId('PRACT1CEDEV1CE'),
        signingPublicKey: practiceId('PRACT1CEKEY'),
        pairing: 'idle',
        genesisVerifiedOnline: true,
        sendReady: true,
        sendCheckState: 'ready',
      });
      emit('contactAdded');
      return { ok: true };
    },
  };
}

function refused(name: string): AnyFn {
  return async () => {
    throw new Error(`${PRACTICE_BLOCKED_MESSAGE} (${name})`);
  };
}

class PracticeMode {
  private state: PracticeState | null = null;
  private originals = new Map<string, unknown>();
  private listeners = new Set<(event: PracticeEvent) => void>();

  get active(): boolean {
    return this.state !== null;
  }

  enter(): void {
    if (this.state) return;
    const state = freshState();
    this.state = state;
    const client = dsmClient as unknown as Record<string, unknown>;
    const simulated = simulations(state, (event) => this.listeners.forEach((listener) => listener(event)));
    for (const key of Object.keys(client)) {
      const value = client[key];
      if (typeof value !== 'function' || ALWAYS_REAL.has(key)) continue;
      if (Object.prototype.hasOwnProperty.call(simulated, key)) {
        this.originals.set(key, value);
        client[key] = simulated[key];
      } else if (STATE_CHANGING.test(key)) {
        this.originals.set(key, value);
        client[key] = refused(key);
      }
    }
  }

  leave(): void {
    if (!this.state) return;
    const client = dsmClient as unknown as Record<string, unknown>;
    this.originals.forEach((value, key) => {
      client[key] = value;
    });
    this.originals.clear();
    this.state = null;
  }

  onEvent(listener: (event: PracticeEvent) => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }
}

export const practiceMode = new PracticeMode();
