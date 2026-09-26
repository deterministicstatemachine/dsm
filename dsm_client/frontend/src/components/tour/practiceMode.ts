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

import { dsmClient } from '../../services/dsmClient';
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
  /^(send|create|claim|add|remove|delete|publish|withdraw|deposit|swap|import|export|mint|burn|update|accept|reject|register|approve|revoke|write|reset|close|open|unlock|lock|execute|submit|broadcast|sign|pair|unpair|sync|reconcile|recover|restore|enroll|admit|fund|redeem|transfer|post|put|store|bind|advance|commit|finalize|apply|generate|start|stop|cancel|retry|refresh|clear|forget|rotate|set)/;

/** Real even in practice: display preferences only. */
const ALWAYS_REAL = new Set(['getPreference', 'setPreference']);

// Practice ids use only Base32 Crockford characters, so any code that decodes
// an id keeps working.
const PAD = '0'.repeat(52);
const practiceId = (stem: string): string => (stem + PAD).slice(0, 52);

export const PRACTICE_CONTACT_ALIAS = 'alice';
export const PRACTICE_FAUCET_AMOUNT = 100;

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
    balances: [
      { tokenId: 'ERA', tokenName: 'ERA', symbol: 'ERA', decimals: 0, baseUnits: BigInt(1000), displayAmount: '1000' },
      { tokenId: 'PLAY', tokenName: 'Practice Coin', symbol: 'PLAY', decimals: 0, baseUnits: BigInt(50), displayAmount: '50' },
    ],
    contacts: [
      {
        alias: PRACTICE_CONTACT_ALIAS,
        deviceId: practiceId('PRACT1CEA11CE'),
        genesisHash: practiceId('PRACT1CEA11CEGENES1S'),
        status: 'VERIFIED',
        genesisVerifiedOnline: true,
        sendReady: true,
        sendCheckState: 'ready',
      },
    ],
    history: [
      {
        txId: 'practice-welcome',
        txHash: practiceId('PRACT1CEWE1C0ME'),
        txType: 'online',
        type: 'online',
        amount: BigInt(1000),
        displayAmount: '1000',
        tokenId: 'ERA',
        recipient: 'practice',
        status: 'confirmed',
        fromDeviceId: practiceId('PRACT1CESENDER'),
        toDeviceId: practiceId('PRACT1CEY0VDEV1CE'),
        memo: 'Practice tokens for the tour',
        receiptVerified: false,
      },
    ],
    sequence: 0,
  };
}

const pause = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

function wholeAmount(value: string | number | bigint): bigint | null {
  try {
    const text = String(value).trim();
    if (!/^\d+$/.test(text)) return null;
    return BigInt(text);
  } catch {
    return null;
  }
}

type Debit = { ok: true; balance: bigint } | { ok: false; message: string };

function debit(state: PracticeState, tokenId: string, amount: string | number | bigint): Debit {
  const units = wholeAmount(amount);
  if (units === null || units <= BigInt(0)) return { ok: false, message: 'Enter a whole amount above zero.' };
  const holding = state.balances.find((b) => b.tokenId === tokenId);
  if (!holding) return { ok: false, message: `You hold no ${tokenId} in practice.` };
  if (units > holding.baseUnits) {
    return { ok: false, message: `Not enough ${holding.symbol}: you have ${holding.displayAmount}.` };
  }
  holding.baseUnits -= units;
  holding.displayAmount = holding.baseUnits.toString();
  return { ok: true, balance: holding.baseUnits };
}

function credit(state: PracticeState, tokenId: string, units: number): void {
  const holding = state.balances.find((b) => b.tokenId === tokenId) ?? state.balances[0];
  holding.baseUnits += BigInt(units);
  holding.displayAmount = holding.baseUnits.toString();
}

function recordSend(state: PracticeState, to: string, tokenId: string, amount: string | number | bigint, memo: string | undefined, mode: 'online' | 'offline'): string {
  state.sequence += 1;
  const txId = `practice-${state.sequence}`;
  const units = wholeAmount(amount) ?? BigInt(0);
  const contact = state.contacts.find((c) => c.alias === to || c.deviceId === to);
  state.history = [
    {
      txId,
      txHash: practiceId(`PRACT1CETX${state.sequence}`),
      txType: mode === 'offline' ? 'bilateral_offline' : 'online',
      type: mode,
      amount: -units,
      displayAmount: `-${units.toString()}`,
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
  return {
    getIdentity: async () => ({ ...state.identity }),
    getAllBalances: async () => state.balances.map((b) => ({ ...b })),
    getContacts: async () => ({ contacts: state.contacts.map((c) => ({ ...c })) }),
    getWalletHistory: async () => ({ transactions: [...state.history] }),
    resolveBleAddressForContact: async () => undefined,
    sendOnlineTransferSmart: async (recipientAlias: string, scaledAmountStr: string | number | bigint, memo?: string, tokenId?: string) => {
      await pause(700);
      const token = tokenId || 'ERA';
      const result = debit(state, token, scaledAmountStr);
      if (!result.ok) return { success: false, error: { message: result.message } };
      recordSend(state, recipientAlias, token, scaledAmountStr, memo, 'online');
      emit('sent');
      return { success: true, newBalance: result.balance };
    },
    sendOfflineTransfer: async (params: { tokenId: string; to: string; amount: number | bigint | string; memo?: string }) => {
      await pause(700);
      const token = params.tokenId || 'ERA';
      const result = debit(state, token, params.amount);
      if (!result.ok) return { success: false, message: result.message };
      const transactionId = recordSend(state, params.to, token, params.amount, params.memo, 'offline');
      emit('sent');
      return { success: true, transactionId };
    },
    claimFaucet: async (tokenId?: string) => {
      await pause(600);
      credit(state, tokenId || 'ERA', PRACTICE_FAUCET_AMOUNT);
      emit('claimed');
      return { success: true, message: `Practice: ${PRACTICE_FAUCET_AMOUNT} ERA added`, tokensReceived: PRACTICE_FAUCET_AMOUNT };
    },
    addContact: async (input: { alias: string; genesisHash: string | Uint8Array; deviceId: string | Uint8Array }) => {
      await pause(400);
      state.contacts.push({
        alias: input.alias,
        genesisHash: typeof input.genesisHash === 'string' ? input.genesisHash : practiceId('PRACT1CEGENES1S'),
        deviceId: typeof input.deviceId === 'string' ? input.deviceId : practiceId('PRACT1CEDEV1CE'),
        status: 'VERIFIED',
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
