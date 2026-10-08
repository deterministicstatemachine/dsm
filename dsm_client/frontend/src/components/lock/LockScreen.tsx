// SPDX-License-Identifier: Apache-2.0
/**
 * LockScreen — full-viewport lock overlay. What the user enters goes to Rust
 * (session.unlock), which checks it and counts each miss. This screen shows
 * Rust's answer: open, wrong with the tries left, or that only the wallet's
 * recovery phrase opens it now. It checks nothing itself, and no wait or
 * restart gives a try back. While the wallet is locked Rust answers nothing
 * the app asks but its session, so once it opens the wallet and the contacts
 * read again.
 */

import React, { useCallback, useRef, useState } from 'react';
import PinInput from './PinInput';
import StateboyComboInput, { type ComboButton } from './StateboyComboInput';
import { applySessionSnapshot, tryUnlockViaRouter, type UnlockKey } from '../../dsm/WebViewBridge';
import { useNativeSessionStore } from '../../runtime/nativeSessionStore';
import type { NativeSessionReport } from '../../runtime/nativeSessionTypes';
import { walletStore } from '../../stores/walletStore';
import { contactsStore } from '../../stores/contactsStore';
import { Notice } from '../common/ScreenFrame';
import './LockScreen.css';

const POW_WORDS = ['POW!', 'ZAP!', 'BAM!', 'BOOM!', '✓ OPEN'];
const pickPow = () => POW_WORDS[Math.floor(Math.random() * (POW_WORDS.length - 1))];
/** How long the POW plays before the wallet shows. */
const POW_MS = 780;
/** How long a wrong try shakes and inverts the screen. */
const WRONG_MS = 800;

/** What the last try came to, as Rust answered it. */
type Answer =
  | { kind: 'wrong' }
  | { kind: 'not_this_wallet' }
  | { kind: 'error'; text: string };

function messageOf(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function triesLeft(n: number): string {
  return n === 1 ? '1 TRY LEFT' : `${n} TRIES LEFT`;
}

export default function LockScreen() {
  const lock = useNativeSessionStore().lock_status;
  const [checking, setChecking] = useState<UnlockKey | null>(null);
  const [answer, setAnswer] = useState<Answer | null>(null);
  // Wrong answers still shaking the screen.
  const [shaking, setShaking] = useState(0);
  const [opened, setOpened] = useState<NativeSessionReport | null>(null);
  const [phrase, setPhrase] = useState('');
  const powWord = useRef(pickPow());

  const tries = lock.tries;
  const phraseRequired = tries !== null && tries.phrase_required;

  const tryKey = useCallback(async (key: UnlockKey) => {
    setChecking(key);
    setAnswer(null);
    try {
      const after = await tryUnlockViaRouter(key);
      if (after.lock_status.locked) {
        applySessionSnapshot(after);
        setAnswer('secret' in key ? { kind: 'wrong' } : { kind: 'not_this_wallet' });
        setShaking((n) => n + 1);
        setTimeout(() => setShaking((n) => n - 1), WRONG_MS);
      } else {
        // Rust has opened the session; the wallet shows once the POW has played.
        setOpened(after);
        setTimeout(() => {
          applySessionSnapshot(after);
          walletStore.initialize();
          contactsStore.refreshContacts();
        }, POW_MS);
      }
    } catch (e) {
      setAnswer({ kind: 'error', text: messageOf(e) });
    } finally {
      setChecking(null);
    }
  }, []);

  const shake = shaking > 0 ? ' lock-screen--shake lock-screen--flash' : '';

  return (
    <div className={`lock-screen sb-screen${shake}`}>

      {opened !== null && (
        <div className="lock-pow-overlay">
          <div className="pow-star pow-star--bg" />
          <div className="pow-star pow-star--fg" />
          <div className="pow-text">{powWord.current}</div>
        </div>
      )}

      <div className="sb-screen__body lock-screen__body">
        <section className="sb-card sb-card--dark sb-card--hero lock-header">
          <div className="sb-hero__label lock-subtitle">AUTHENTICATION REQUIRED</div>
          <div className="sb-hero__value lock-icon">[LOCKED]</div>
        </section>

        {checking !== null && (
          <Notice>VERIFYING…</Notice>
        )}

        {checking === null && opened === null && phraseRequired && (
          <section className="sb-card lock-body">
            <p className="sb-hint">
              Only this wallet&apos;s recovery phrase opens it now: the words, in order.
            </p>
            <div className="sb-field">
              <label htmlFor="lock-recovery-phrase">Recovery phrase</label>
              <input
                id="lock-recovery-phrase"
                type="password"
                className="sb-input sb-input--mono"
                value={phrase}
                onChange={(e) => setPhrase(e.target.value)}
                autoComplete="off"
                autoCapitalize="none"
              />
            </div>
            <button
              type="button"
              className="sb-btn sb-btn--primary sb-btn--block"
              onClick={() => tryKey({ recoveryPhrase: phrase })}
              disabled={phrase.trim() === ''}
            >
              Open
            </button>
          </section>
        )}

        {checking === null && opened === null && !phraseRequired && (
          <section className="sb-card lock-body">
            {lock.method === 'pin' && (
              <PinInput onComplete={(pin: string) => tryKey({ secret: pin })} label="ENTER PIN" />
            )}

            {lock.method === 'combo' && (
              <StateboyComboInput
                onComplete={(combo: ComboButton[]) => tryKey({ secret: combo.join(',') })}
                label="ENTER BUTTON COMBO"
              />
            )}
          </section>
        )}

        {answer?.kind === 'wrong' && tries !== null && (
          <Notice kind="error">
            {tries.phrase_required ? '✗ INCORRECT — NO TRIES LEFT' : `✗ INCORRECT — ${triesLeft(tries.misses_left)}`}
          </Notice>
        )}

        {answer?.kind === 'not_this_wallet' && (
          <Notice kind="error">That phrase does not open this wallet.</Notice>
        )}

        {answer?.kind === 'error' && (
          <Notice kind="error">{answer.text}</Notice>
        )}
      </div>
    </div>
  );
}
