// SPDX-License-Identifier: Apache-2.0
// The Modern skin's Send page: who, how much, a note, review, send. The send
// is the one both skins make (domain/sendTransfer). When the sender has email
// receipts on and the person has an email, a receipt follows; the send never
// waits on it or depends on it. The review names the device paid by its
// fingerprint beside the person's name, and says when another contact goes by
// the same name: a name is what the person chose, the device is who is paid.

import React, { useMemo, useRef, useState } from 'react';
import { useWallet } from '../../contexts/WalletContext';
import { useContacts } from '../../contexts/ContactsContext';
import { useAppRuntimeStore } from '../../runtime/appRuntimeStore';
import { sendTransfer, sendingWords, UNKNOWN_OUTCOME, type SendMode } from '../../domain/sendTransfer';
import type { PendingBilateralPhase } from '../../domain/bilateral';
import { emailReceiptIfDue } from '../../domain/sendReceipt';
import { Avatar, Icon, PageTitle, Sheet, mainBalance, personName, sendable } from './parts';
import { modernNav } from './modernNav';
import type { DomainContact } from '../../domain/types';
import type { TokenBalanceView } from '../../dsm/types';
import { contactsNamed, deviceFingerprint } from '../../domain/displayName';
import { ScreenGuard } from '../common/ScreenGuard';
import ModernOffline from './ModernOffline';

const QUICK = ['10', '50', '100', '200'];

/** Exactly what a review shows and its Send sends: fixed when the review opens. */
type Reviewed = { contact: DomainContact; token: TokenBalanceView; amount: string; note: string; mode: SendMode };

type Stage =
  | { kind: 'form' }
  | { kind: 'review'; reviewed: Reviewed }
  | { kind: 'sending'; phase: PendingBilateralPhase | null }
  | { kind: 'done'; sent: 'sent' | 'open'; message: string; receipt: string | null }
  | { kind: 'failed'; message: string }
  | { kind: 'unknown'; message: string };

export default function ModernSend({ to, tokenId: asked }: { to: string | null; tokenId?: string }): React.JSX.Element {
  const wallet = useWallet();
  const { contacts } = useContacts();
  const runtime = useAppRuntimeStore();
  const main = mainBalance(wallet.balances);
  const first = asked !== undefined ? asked : main !== null ? main.tokenId : null;
  const tokens = useMemo(() => sendable(wallet.balances, first), [wallet.balances, first]);
  const [recipient, setRecipient] = useState<string | null>(to);
  const [tokenId, setTokenId] = useState<string | null>(first);
  const [amount, setAmount] = useState('');
  const [note, setNote] = useState('');
  const [mode, setMode] = useState<SendMode>('online');
  const [stage, setStage] = useState<Stage>({ kind: 'form' });
  // Leaving the screen while an offline step is in flight: the step goes on, the screen stops waiting.
  const leave = useRef<AbortController | null>(null);

  const contact: DomainContact | null = contacts.find((c) => c.deviceId === recipient) ?? null;
  // The token chosen, or the first on offer while none has been chosen. A
  // chosen token that is no longer on offer is no token: the screen never
  // puts another in its place.
  const token = tokenId !== null
    ? tokens.find((b) => b.tokenId === tokenId) ?? null
    : tokens.length > 0 ? tokens[0] : null;
  const amountOk = /^\d+(\.\d+)?$/.test(amount.trim()) && Number(amount) > 0;
  // What still stands between the form and a review, said rather than shown
  // as a grey button.
  const missing = contact === null
    ? 'Choose who to send to.'
    : token === null
      ? 'There is no token to send yet.'
      : amountOk
        ? null
        : 'Enter an amount above zero.';
  // Set once Review Send is tapped while something is missing: from then on
  // the screen says what is still missing, and stops once nothing is.
  const [tried, setTried] = useState<'tried' | 'not_tried'>('not_tried');

  // Sends what the review showed, whatever the form or the wallet holds by
  // the time Send is tapped.
  const send = ({ contact, token, amount, note, mode }: Reviewed) => {
    setStage({ kind: 'sending', phase: null });
    const sentAtLocal = new Date().toLocaleString();
    const controller = new AbortController();
    leave.current = controller;
    const watch = {
      onPhase: (phase: PendingBilateralPhase) => setStage((at) => (at.kind === 'sending' ? { kind: 'sending', phase } : at)),
      leave: controller.signal,
    };
    sendTransfer({ mode, to: contact.deviceId, tokenId: token.tokenId, amount, note }, watch).then(
      (outcome) => {
        if (outcome.kind === 'refused') {
          setStage({ kind: 'failed', message: outcome.message });
          return undefined;
        }
        if (outcome.kind === 'unknown') {
          setStage({ kind: 'unknown', message: outcome.message });
          return wallet.refreshAll();
        }
        const message = `${amount.trim()} ${token.symbol} to ${personName(contact)}`;
        if (outcome.kind === 'open') {
          setStage({ kind: 'done', sent: 'open', message: outcome.message, receipt: null });
          return wallet.refreshAll();
        }
        const receipt = emailReceiptIfDue({
          receiptsEmail: runtime.receiptsEmail, contact, token: token.symbol, amount, note, reference: outcome.reference, sentAtLocal,
        });
        setStage({ kind: 'done', sent: 'sent', message, receipt: receipt !== null ? 'Emailing a receipt…' : null });
        if (receipt !== null) {
          receipt.then(
            (to) => setStage({ kind: 'done', sent: 'sent', message, receipt: `Receipt emailed to ${to}` }),
            (e: unknown) => setStage({ kind: 'done', sent: 'sent', message, receipt: `The receipt was not emailed: ${e instanceof Error ? e.message : String(e)}` }),
          );
        }
        return wallet.refreshAll();
      },
      (e: unknown) => setStage({ kind: 'failed', message: e instanceof Error ? e.message : String(e) }),
    );
  };

  return (
    <>
      <PageTitle title="Send Money" onBack={() => modernNav.back()} />

      <section className="s-card" aria-label="To">
        <div className="s-label">To</div>
        {contacts.length === 0 ? (
          <div className="s-empty">
            No people yet.{' '}
            <button type="button" className="s-chip" onClick={() => modernNav.open({ kind: 'add_contact' })}>Add someone</button>
          </div>
        ) : contact !== null ? (
          <button type="button" className="s-row" onClick={() => setRecipient(null)} aria-label={`Change who: ${personName(contact)}`}>
            <Avatar name={personName(contact)} lookupKey={contact.profile?.phoneLookupKey} deviceId={contact.deviceId} />
            <span className="s-row-main">
              <span className="s-row-title" style={{ display: 'block' }}>{personName(contact)}</span>
              <span className="s-row-sub" style={{ display: 'block' }}>{contact.profile?.email || contact.profile?.phone || 'On DSM'}</span>
            </span>
            <Icon name="chevron" />
          </button>
        ) : (
          contacts.map((c) => (
            <button key={c.deviceId} type="button" className="s-row" onClick={() => setRecipient(c.deviceId)}>
              <Avatar name={personName(c)} lookupKey={c.profile?.phoneLookupKey} deviceId={c.deviceId} />
              <span className="s-row-main"><span className="s-row-title" style={{ display: 'block' }}>{personName(c)}</span></span>
            </button>
          ))
        )}
      </section>

      {token !== null ? (
        <section className="s-card s-balance" aria-label="Available balance">
          <div className="s-balance-label">{mode === 'offline' ? 'Cash in hand' : 'Available Balance'}</div>
          {mode === 'offline' && !token.offline ? (
            <div className="s-balance-amount" style={{ fontSize: 32 }} data-testid="send-offline-unknown">—<small>{token.symbol}</small></div>
          ) : (
            <div className="s-balance-amount" style={{ fontSize: 32 }}>
              {mode === 'offline' && token.offline ? token.offline.displayAmount : token.displayAmount}<small>{token.symbol}</small>
            </div>
          )}
          {mode === 'offline' ? (
            <div className="s-balance-other">
              {token.offline ? `Online account ${token.displayAmount} ${token.symbol}` : 'Offline allocation unknown until the appliance connects.'}
            </div>
          ) : null}
        </section>
      ) : (
        <div className="s-notice">There is nothing to send yet.</div>
      )}

      <section className="s-card" aria-label="Amount">
        <label className="s-label" htmlFor="s-amount">Amount</label>
        <input
          id="s-amount"
          className="s-amount-input"
          inputMode="decimal"
          placeholder="0"
          value={amount}
          onChange={(e) => {
            // A comma is the decimal point on some keyboards; one point is kept.
            const typed = e.target.value.replace(/,/g, '.').replace(/[^\d.]/g, '');
            const point = typed.indexOf('.');
            setAmount(point < 0 ? typed : `${typed.slice(0, point + 1)}${typed.slice(point + 1).replace(/\./g, '')}`);
          }}
        />
        <div className="s-quick">
          {QUICK.map((q) => (
            <button key={q} type="button" aria-pressed={amount === q} onClick={() => setAmount(q)}>
              {q}
              <div style={{ fontSize: 12 }}>{token !== null ? token.symbol : ''}</div>
            </button>
          ))}
        </div>
        {tokens.length > 1 ? (
          <div className="s-token-pick" role="group" aria-label="Token">
            {tokens.map((b) => (
              <button key={b.tokenId} type="button" aria-pressed={token !== null && token.tokenId === b.tokenId} onClick={() => setTokenId(b.tokenId)}>{b.symbol}</button>
            ))}
          </div>
        ) : null}
      </section>

      <div className="s-field">
        <label className="s-label" htmlFor="s-note">Note (Optional)</label>
        <input id="s-note" className="s-input" maxLength={200} placeholder="Thanks for lunch!" value={note} onChange={(e) => setNote(e.target.value)} />
      </div>

      {/* Offline is offered in full, and in Simple mode when switched on there. */}
      {runtime.simpleMode === 'off' || runtime.simpleOffline === 'on' ? (
        <div className="s-field">
          <div className="s-seg" role="group" aria-label="How to send">
            <button type="button" aria-pressed={mode === 'online'} onClick={() => setMode('online')}>Online</button>
            <button type="button" aria-pressed={mode === 'offline'} onClick={() => setMode('offline')}>Offline</button>
          </div>
          {mode === 'offline' ? (
            <p className="s-hint" style={{ marginTop: 10 }}>
              <strong>Offline needs Bluetooth.</strong> Both appliances next to each other, Bluetooth on; the person accepts it in their app.
            </p>
          ) : null}
        </div>
      ) : null}
      {mode === 'offline' ? <ModernOffline token={token} onMoved={wallet.refreshAll} /> : null}

      <button
        type="button"
        className={`s-btn s-btn-primary${missing !== null ? ' s-btn-waiting' : ''}`}
        aria-disabled={missing !== null}
        onClick={() => {
          if (missing !== null) {
            setTried('tried');
            return;
          }
          if (contact === null || token === null) return;
          setStage({ kind: 'review', reviewed: { contact, token, amount, note, mode } });
        }}
      >
        <Icon name="send" /> Review Send
      </button>
      {tried === 'tried' && missing !== null ? <p className="s-hint" role="alert" style={{ textAlign: 'center', marginTop: 10 }}>{missing}</p> : null}

      {stage.kind === 'review' ? (
        <ReviewSheet
          reviewed={stage.reviewed}
          namesakes={contactsNamed(contacts, personName(stage.reviewed.contact), stage.reviewed.contact.deviceId)}
          receiptsEmail={runtime.receiptsEmail}
          onSend={() => send(stage.reviewed)}
          onCancel={() => setStage({ kind: 'form' })}
        />
      ) : null}

      {stage.kind === 'sending' ? (
        <Sheet label="Sending" onClose={() => undefined}>
          <h2>{mode === 'offline' && contact !== null ? sendingWords(stage.phase, personName(contact)) : 'Sending…'}</h2>
          {mode === 'offline' ? (
            <>
              <p>
                {stage.phase === 'pending_user_action'
                  ? 'They accept it on their phone. Nothing moves until they do.'
                  : 'Over Bluetooth, appliance to appliance.'}
              </p>
              <button type="button" className="s-btn s-btn-quiet" onClick={() => leave.current?.abort()}>
                Leave it open
              </button>
              <p className="s-hint" style={{ marginTop: 8 }}>
                The payment stays open on both appliances and completes when you are together again.
              </p>
            </>
          ) : null}
        </Sheet>
      ) : null}

      {stage.kind === 'done' ? (
        <Sheet label="Sent" onClose={() => modernNav.back()}>
          <h2>{stage.sent === 'sent' ? 'Sent' : 'Not finished yet'}</h2>
          <p>{stage.message}</p>
          {stage.receipt !== null ? <p>{stage.receipt}</p> : null}
          <button type="button" className="s-btn s-btn-primary" onClick={() => modernNav.back()}>Done</button>
        </Sheet>
      ) : null}

      {stage.kind === 'unknown' ? (
        <Sheet label="Outcome unknown" onClose={() => modernNav.back()}>
          <h2>Outcome unknown</h2>
          <p data-testid="send-outcome-unknown">{UNKNOWN_OUTCOME}</p>
          <p className="s-hint">{stage.message}</p>
          <button type="button" className="s-btn s-btn-primary" onClick={() => modernNav.back()}>Done</button>
        </Sheet>
      ) : null}

      {stage.kind === 'failed' ? (
        <Sheet label="Not sent" onClose={() => setStage({ kind: 'form' })}>
          <h2>Not sent</h2>
          <p>{stage.message}</p>
          <button type="button" className="s-btn s-btn-quiet" onClick={() => setStage({ kind: 'form' })}>Back</button>
        </Sheet>
      ) : null}
    </>
  );
}

/** The review of one send: what it shows is what its Send sends. */
function ReviewSheet({ reviewed, namesakes, receiptsEmail, onSend, onCancel }: {
  reviewed: Reviewed;
  namesakes: DomainContact[];
  receiptsEmail: string;
  onSend: () => void;
  onCancel: () => void;
}): React.JSX.Element {
  const { contact, token, amount, note } = reviewed;
  return (
    <Sheet label="Review send" onClose={onCancel}>
      <ScreenGuard kind="confirm" />
      <h2>Send {amount.trim()} {token.symbol}?</h2>
      <p>To <strong>{personName(contact)}</strong>{note.length > 0 ? ` · “${note}”` : ''}</p>
      <p data-testid="send-review-device">Device <strong style={{ fontFamily: 'ui-monospace, monospace' }}>{deviceFingerprint(contact.deviceId)}</strong></p>
      {namesakes.length > 0 ? (
        <div className="s-notice s-error" role="alert">
          Also named {personName(contact)}: {namesakes.map((c) => deviceFingerprint(c.deviceId)).join(', ')}.
          Check the device above is the person you mean.
        </div>
      ) : null}
      {receiptsEmail === 'on' && contact.profile?.email ? <p>A receipt will be emailed to {contact.profile.email}.</p> : null}
      <div className="s-stack">
        <button type="button" className="s-btn s-btn-primary" onClick={onSend}><Icon name="send" /> Send now</button>
        <button type="button" className="s-btn s-btn-quiet" onClick={onCancel}>Cancel</button>
      </div>
    </Sheet>
  );
}
