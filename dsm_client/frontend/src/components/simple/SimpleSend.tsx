// SPDX-License-Identifier: Apache-2.0
// The Simple skin's Send page: who, how much, a note, review, send. The send
// is the one both skins make (domain/sendTransfer). When the sender has email
// receipts on and the person has an email, a receipt follows; the send never
// waits on it or depends on it.

import React, { useMemo, useState } from 'react';
import { useWallet } from '../../contexts/WalletContext';
import { useContacts } from '../../contexts/ContactsContext';
import { useAppRuntimeStore } from '../../runtime/appRuntimeStore';
import { sendTransfer, type SendMode } from '../../domain/sendTransfer';
import { emailReceipt } from '../../dsm/receipts';
import UnderConstructionModal from '../UnderConstructionModal';
import { Avatar, Icon, PageTitle, Sheet, mainBalance, personName } from './parts';
import { simpleNav } from './simpleNav';
import type { DomainContact } from '../../domain/types';

const QUICK = ['10', '50', '100', '200'];

type Stage =
  | { kind: 'form' }
  | { kind: 'review' }
  | { kind: 'sending' }
  | { kind: 'done'; sent: 'sent' | 'open'; message: string; receipt: string | null }
  | { kind: 'failed'; message: string };

export default function SimpleSend({ to }: { to: string | null }): React.JSX.Element {
  const wallet = useWallet();
  const { contacts } = useContacts();
  const runtime = useAppRuntimeStore();
  const currencies = useMemo(() => wallet.balances.filter((b) => b.holding === 'currency'), [wallet.balances]);
  const main = mainBalance(wallet.balances);
  const [recipient, setRecipient] = useState<string | null>(to);
  const [tokenId, setTokenId] = useState<string | null>(main !== null ? main.tokenId : null);
  const [amount, setAmount] = useState('');
  const [note, setNote] = useState('');
  const [mode, setMode] = useState<SendMode>('online');
  const [notice, setNotice] = useState<string | null>(null);
  const [stage, setStage] = useState<Stage>({ kind: 'form' });

  const contact: DomainContact | null = contacts.find((c) => c.deviceId === recipient) ?? null;
  const token = currencies.find((b) => b.tokenId === tokenId) ?? main;
  const amountOk = /^\d+(\.\d+)?$/.test(amount.trim()) && Number(amount) > 0;
  const ready = contact !== null && token !== null && amountOk;

  const send = () => {
    if (contact === null || token === null) return;
    setStage({ kind: 'sending' });
    const sentAtLocal = new Date().toLocaleString();
    sendTransfer({ mode, to: contact.deviceId, tokenId: token.tokenId, amount, note }).then(
      (outcome) => {
        if (outcome.kind === 'refused') {
          setStage({ kind: 'failed', message: outcome.message });
          return undefined;
        }
        const message = `${amount.trim()} ${token.symbol} to ${personName(contact)}`;
        if (outcome.kind === 'open') {
          setStage({ kind: 'done', sent: 'open', message: outcome.message, receipt: null });
          return wallet.refreshAll();
        }
        const email = contact.profile?.email;
        const wantsReceipt = runtime.receiptsEmail === 'on' && email !== undefined && email.length > 0 && outcome.reference !== null;
        setStage({ kind: 'done', sent: 'sent', message, receipt: wantsReceipt ? 'Emailing a receipt…' : null });
        if (wantsReceipt && outcome.reference !== null) {
          emailReceipt({
            recipientDeviceId: contact.deviceId,
            token: token.symbol,
            amount: amount.trim(),
            memo: note,
            reference: outcome.reference,
            sentAtLocal,
          }).then(
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
      <PageTitle title="Send Money" onBack={() => simpleNav.back()} />

      <section className="s-card" aria-label="To">
        <div className="s-label">To</div>
        {contacts.length === 0 ? (
          <div className="s-empty">
            No people yet.{' '}
            <button type="button" className="s-chip" onClick={() => simpleNav.open({ kind: 'add_contact' })}>Add someone</button>
          </div>
        ) : contact !== null ? (
          <button type="button" className="s-row" onClick={() => setRecipient(null)} aria-label={`Change who: ${personName(contact)}`}>
            <Avatar name={personName(contact)} lookupKey={contact.profile?.phoneLookupKey} />
            <span className="s-row-main">
              <span className="s-row-title" style={{ display: 'block' }}>{personName(contact)}</span>
              <span className="s-row-sub" style={{ display: 'block' }}>{contact.profile?.email || contact.profile?.phone || 'On DSM'}</span>
            </span>
            <Icon name="chevron" />
          </button>
        ) : (
          contacts.map((c) => (
            <button key={c.deviceId} type="button" className="s-row" onClick={() => setRecipient(c.deviceId)}>
              <Avatar name={personName(c)} lookupKey={c.profile?.phoneLookupKey} />
              <span className="s-row-main"><span className="s-row-title" style={{ display: 'block' }}>{personName(c)}</span></span>
            </button>
          ))
        )}
      </section>

      {token !== null ? (
        <section className="s-card s-balance" aria-label="Available balance">
          <div className="s-balance-label">Available Balance</div>
          <div className="s-balance-amount" style={{ fontSize: 32 }}>{token.displayAmount}<small>{token.symbol}</small></div>
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
          onChange={(e) => setAmount(e.target.value.replace(/[^\d.]/g, ''))}
        />
        <div className="s-quick">
          {QUICK.map((q) => (
            <button key={q} type="button" aria-pressed={amount === q} onClick={() => setAmount(q)}>
              {q}
              <div style={{ fontSize: 12 }}>{token !== null ? token.symbol : ''}</div>
            </button>
          ))}
        </div>
        {currencies.length > 1 ? (
          <div className="s-seg" style={{ marginTop: 12 }} role="group" aria-label="Currency">
            {currencies.map((b) => (
              <button key={b.tokenId} type="button" aria-pressed={token !== null && token.tokenId === b.tokenId} onClick={() => setTokenId(b.tokenId)}>{b.symbol}</button>
            ))}
          </div>
        ) : null}
      </section>

      <div className="s-field">
        <label className="s-label" htmlFor="s-note">Note (Optional)</label>
        <input id="s-note" className="s-input" maxLength={200} placeholder="Thanks for lunch!" value={note} onChange={(e) => setNote(e.target.value)} />
      </div>

      {runtime.simpleOffline === 'on' ? (
        <div className="s-field">
          <div className="s-seg" role="group" aria-label="How to send">
            <button type="button" aria-pressed={mode === 'online'} onClick={() => setMode('online')}>Online</button>
            <button type="button" aria-pressed={mode === 'offline'} onClick={() => setNotice('Under construction, check back soon.')}>Offline</button>
          </div>
        </div>
      ) : null}

      <button type="button" className="s-btn s-btn-primary" disabled={!ready} onClick={() => setStage({ kind: 'review' })}>
        <Icon name="send" /> Review Send
      </button>

      <UnderConstructionModal title="Offline" message={notice} onClose={() => setNotice(null)} />

      {stage.kind === 'review' && contact !== null && token !== null ? (
        <Sheet label="Review send" onClose={() => setStage({ kind: 'form' })}>
          <h2>Send {amount.trim()} {token.symbol}?</h2>
          <p>To <strong>{personName(contact)}</strong>{note.length > 0 ? ` · “${note}”` : ''}</p>
          {runtime.receiptsEmail === 'on' && contact.profile?.email ? <p>A receipt will be emailed to {contact.profile.email}.</p> : null}
          <div className="s-stack">
            <button type="button" className="s-btn s-btn-primary" onClick={send}><Icon name="send" /> Send now</button>
            <button type="button" className="s-btn s-btn-quiet" onClick={() => setStage({ kind: 'form' })}>Cancel</button>
          </div>
        </Sheet>
      ) : null}

      {stage.kind === 'sending' ? (
        <Sheet label="Sending" onClose={() => undefined}>
          <h2>Sending…</h2>
        </Sheet>
      ) : null}

      {stage.kind === 'done' ? (
        <Sheet label="Sent" onClose={() => simpleNav.back()}>
          <h2>{stage.sent === 'sent' ? 'Sent' : 'Not finished yet'}</h2>
          <p>{stage.message}</p>
          {stage.receipt !== null ? <p>{stage.receipt}</p> : null}
          <button type="button" className="s-btn s-btn-primary" onClick={() => simpleNav.back()}>Done</button>
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
