// SPDX-License-Identifier: Apache-2.0
/**
 * FxProvider — one place that decides when a StateBoy FX scene plays.
 *
 * Screens ask for a scene with `useFx().play(...)`; app-wide moments
 * (a deposit landing, an offline transfer sealing, a clone being refused,
 * a device pairing, the device being anchored, the lock being armed) are
 * cued here from bridge events and app-state transitions. Scenes queue and
 * show one at a time in the FxLayer, a rounded popup inside the screen.
 */
import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { useBridgeEvent } from '../../hooks/useBridgeEvents';
import { LOCK_SETUP_COMPLETE_EVENT } from '../../services/lock/lockService';
import type { AppState } from '../../types/app';
import { setFxMuted, type FxAnim } from './fxEngine';
import { FxPopup, type FxTone } from './FxPopup';

export interface FxRequest {
  anim: FxAnim;
  title: string;
  caption?: string;
  /** Amount caption inside the confirm/fail scenes (already signed, <= 17 chars). */
  amount?: string;
  muted?: boolean;
  autoClose?: boolean;
  tone?: FxTone;
  okLabel?: string;
  /** Requests sharing a key collapse while one is still queued. */
  key?: string;
}

type Queued = FxRequest & { id: number };

interface FxActions {
  play: (req: FxRequest) => void;
  dismiss: () => void;
}

const ActionsCtx = createContext<FxActions>({ play: () => undefined, dismiss: () => undefined });
const CurrentCtx = createContext<Queued | null>(null);

/** Scene controls for screens: `play` queues a popup, `dismiss` closes the current one. */
export function useFx(): FxActions {
  return useContext(ActionsCtx);
}

/** Skip an incoming-credit cue this soon after a confirm the user already saw. */
const CREDIT_ECHO_MS = 15_000;
/** One "paired" popup per device within this window. */
const PAIR_REPEAT_MS = 20_000;
/** The lock scene is armed by lock setup; forget it if the lock never lands. */
const LOCK_ARM_MS = 10_000;
/** Scenes waiting behind the one on screen. Beyond this, later cues are dropped. */
const MAX_QUEUED = 3;

interface ProviderProps {
  children?: React.ReactNode;
  appState?: AppState;
  soundEnabled?: boolean;
}

export function FxProvider({ children, appState, soundEnabled }: ProviderProps) {
  const [queue, setQueue] = useState<Queued[]>([]);
  const nextId = useRef(0);
  const lastConfirmAt = useRef(0);

  const play = useCallback((req: FxRequest) => {
    if (req.anim === 'confirm') lastConfirmAt.current = Date.now();
    setQueue((q) => {
      if (req.key && q.some((item) => item.key === req.key)) return q;
      // A burst of events must not become a stack of popups to tap through.
      if (q.length >= MAX_QUEUED) return q;
      nextId.current += 1;
      return [...q, { ...req, id: nextId.current }];
    });
  }, []);

  const dismiss = useCallback(() => setQueue((q) => q.slice(1)), []);

  useEffect(() => {
    if (soundEnabled !== undefined) setFxMuted(!soundEnabled);
  }, [soundEnabled]);

  useFxCues(play, appState, lastConfirmAt);

  const actions = useMemo<FxActions>(() => ({ play, dismiss }), [play, dismiss]);
  const current = queue[0] ?? null;

  return (
    <ActionsCtx.Provider value={actions}>
      <CurrentCtx.Provider value={current}>{children}</CurrentCtx.Provider>
    </ActionsCtx.Provider>
  );
}

/** Renders the scene at the head of the queue. Mount it inside the screen host. */
export function FxLayer() {
  const current = useContext(CurrentCtx);
  const { dismiss } = useContext(ActionsCtx);
  if (!current) return null;
  const { id, key: _key, ...props } = current;
  void _key;
  return <FxPopup key={id} {...props} onClose={dismiss} />;
}

/** App-wide cues: bridge events and app-state transitions that deserve a scene. */
function useFxCues(play: (req: FxRequest) => void, appState: AppState | undefined, lastConfirmAt: React.MutableRefObject<number>) {
  const prevState = useRef<AppState | undefined>(appState);
  const lockArmedUntil = useRef(0);
  const pairedAt = useRef<Map<string, number>>(new Map());

  // dBTC: a deposit was credited, a withdrawal was delivered.
  useBridgeEvent('deposit.completed', (detail?: { depositId: string; amount: string }) => {
    const amount = detail?.amount ? `${detail.amount} BTC` : undefined;
    play({
      anim: 'confirm',
      title: 'Deposit complete',
      caption: amount ? `${amount} arrived as dBTC` : 'Your dBTC balance is updated',
      amount: amount ? `+${amount}`.slice(0, 17) : undefined,
      key: detail?.depositId ? `deposit:${detail.depositId}` : undefined,
    });
  }, [play]);

  useBridgeEvent('wallet.exitCompleted', () => {
    play({ anim: 'confirm', title: 'Bitcoin sent', caption: 'Your withdrawal was delivered on-chain', key: 'exit' });
  }, [play]);

  // A settled credit landed that this wallet did not just watch happen.
  useBridgeEvent('wallet.creditReceived', (detail?: { tokenId?: string }) => {
    if (Date.now() - lastConfirmAt.current < CREDIT_ECHO_MS) return;
    const token = detail?.tokenId ? String(detail.tokenId) : '';
    play({
      anim: 'confirm',
      title: 'Payment received',
      caption: token ? `${token.length > 12 ? `${token.slice(0, 8)}…` : token} landed in your wallet` : 'Your balance is updated',
      muted: true, // the coin sound already plays for this
      key: 'credit',
    });
  }, [play]);

  // Device-to-device transfer signed, sealed and settled.
  useBridgeEvent('bilateral.transferComplete', () => {
    play({ anim: 'seal', title: 'Transfer sealed', caption: 'Signed, sealed and settled device to device', key: 'seal' });
  }, [play]);

  // Rust refused a link: cloned state, replay, fork. Stays until dismissed.
  useBridgeEvent('dsm.deterministicSafety', (detail?: { classification: string; message?: string }) => {
    const what = detail?.classification ? String(detail.classification) : 'safety stop';
    play({
      anim: 'tamper',
      title: 'Link refused',
      caption: detail?.message ? `${what}: ${detail.message}` : what,
      tone: 'bad',
      okLabel: 'Dismiss',
      key: `safety:${what}`,
    });
  }, [play]);

  // Bluetooth pairing finished.
  useBridgeEvent('ble.pairingStatus', (detail?: { deviceId: string; status: string; message: string }) => {
    if (detail?.status !== 'paired') return;
    const id = detail.deviceId || '';
    const now = Date.now();
    const last = pairedAt.current.get(id) ?? 0;
    if (now - last < PAIR_REPEAT_MS) return;
    pairedAt.current.set(id, now);
    play({ anim: 'pair', title: 'Paired', caption: detail.message || 'Secure Bluetooth link established', key: `pair:${id}` });
  }, [play]);

  // Lock setup finished: the next lock is the one to celebrate.
  useEffect(() => {
    const arm = () => { lockArmedUntil.current = Date.now() + LOCK_ARM_MS; };
    window.addEventListener(LOCK_SETUP_COMPLETE_EVENT, arm);
    return () => window.removeEventListener(LOCK_SETUP_COMPLETE_EVENT, arm);
  }, []);

  // App-state transitions.
  useEffect(() => {
    const prev = prevState.current;
    prevState.current = appState;
    if (prev === appState || !appState) return;
    if ((prev === 'securing_device' || prev === 'publication_pending') && appState === 'wallet_ready') {
      play({ anim: 'trace', title: 'Device ready', caption: 'Your device key is enrolled and your identity is published', key: 'anchored' });
    }
    if (appState === 'locked' && Date.now() < lockArmedUntil.current) {
      lockArmedUntil.current = 0;
      play({ anim: 'lock', title: 'Lock enabled', caption: 'This wallet now asks for your PIN or button combo', key: 'lock' });
    }
  }, [appState, play]);
}

export default FxProvider;
