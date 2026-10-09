// SPDX-License-Identifier: Apache-2.0
// SoFi's Escrow tab: lock a stake of one of your tokens in an escrow vault,
// see your escrow vaults and what their verdict cells hold, sign or decide an
// outcome you decide, and release a stake an outcome pays you. It explains the
// mechanics only: what an escrow is for is the business of the app that uses
// it. Rust names every party's keys, orders the terms, checks every field and
// answers every state shown here (SoFi §19.9, Amendment S21).

import React, { useCallback, useEffect, useMemo, useState } from 'react';
import * as escrow from '../../../dsm/escrow';
import type { PositionResult } from '../../../dsm/sofi';
import { decodeBase32Crockford, encodeBase32Crockford } from '../../../utils/textId';
import { useContacts } from '../../../contexts/ContactsContext';
import { Disclosure, Notice, middleTruncate } from '../../common/ScreenFrame';
import { TokenSelect, type TokenOption } from '../../common/TokenSelect';
import { copyText } from '../../../utils/anchorDisplay';

type Status = { kind: 'info' | 'success' | 'error'; text: string };

/** A party the user can name: this device, or a contact, by its device id (Base32). */
type Party = { id: string; label: string };

/** An outcome as the user fills it in. */
type OutcomeRow = { key: number; label: string; decidedBy: string[]; pays: string };

function messageOf(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

const utf8 = new TextEncoder();
const fromUtf8 = new TextDecoder();

/** An outcome as text where its bytes are text, else in Base32. */
function outcomeText(bytes: Uint8Array): string {
  const text = fromUtf8.decode(bytes);
  const back = utf8.encode(text);
  const isText = back.length === bytes.length && back.every((b, i) => b === bytes[i]);
  return isText ? text : encodeBase32Crockford(bytes);
}

/** Base32 the user entered or picked, as bytes; Rust checks what they must be. */
function idBytes(what: string, text: string): Uint8Array {
  try {
    return decodeBase32Crockford(text.trim());
  } catch (e) {
    throw new Error(`${what}: ${messageOf(e)}`);
  }
}

function verdictWords(v: escrow.EscrowVerdict): string {
  switch (v.state) {
    case 'none': return 'No outcome decided yet';
    case 'leaderHeld': return `Decided, not final yet: ${outcomeText(v.outcome)}`;
    case 'preserved': return `Decided and copied, not final yet: ${outcomeText(v.outcome)}`;
    case 'final': return `Final: ${outcomeText(v.outcome)}`;
  }
}

function releaseWords(r: PositionResult): string {
  switch (r.state) {
    case 'realized': return `Released at position ${r.position}`;
    case 'void': return 'Void: nothing moved';
    case 'invalid': return 'Invalid: the release does not validate';
    case 'retriesExhausted': return 'Network retries ran out; resolve again later';
  }
}

let rowKeys = 0;
const newRow = (): OutcomeRow => ({ key: rowKeys++, label: '', decidedBy: [], pays: '' });

type CardProps = {
  vault: escrow.EscrowVault;
  verdict: escrow.EscrowVerdict | undefined;
  busy: boolean;
  onVerdict: () => void;
  onSign: (outcome: Uint8Array) => void;
  onDecide: (outcome: Uint8Array) => void;
  onRelease: () => void;
  onCopy: (what: string, text: string) => void;
};

function VaultCard({ vault, verdict, busy, onVerdict, onSign, onDecide, onRelease, onCopy }: CardProps): React.JSX.Element {
  const id = encodeBase32Crockford(vault.vaultId);
  const cell = encodeBase32Crockford(vault.verdictCell);
  const active = vault.status === 'active';
  const paysThisDevice = vault.outcomes.some((o) => o.paysThisDevice);
  return (
    <section className="sb-card" aria-label={`Escrow vault ${middleTruncate(id, 6, 4)}`}>
      <div className="sb-card__title">
        {active ? `${vault.amountDisplay} ${vault.tokenSymbol}` : `Released · ${vault.tokenSymbol}`}
      </div>
      <div className="sb-kv">
        <span className="sb-kv__k">Vault</span>
        <span className="sb-kv__v sb-kv__v--mono">{middleTruncate(id, 8, 6)}</span>
      </div>
      <div className="sb-kv">
        <span className="sb-kv__k">{vault.decidedByProgram === undefined ? 'Verdict cell' : 'Match cell'}</span>
        <span className="sb-kv__v sb-kv__v--mono">{middleTruncate(cell, 8, 6)}</span>
      </div>
      {vault.decidedByProgram !== undefined && (
        <>
          <div className="sb-kv">
            <span className="sb-kv__k">Decided by</span>
            <span className="sb-kv__v">program {vault.decidedByProgram}</span>
          </div>
          <p className="sb-hint sb-hint--tight">
            No referee: the outcome is computed from both players&apos; signed moves.
          </p>
        </>
      )}
      {vault.outcomes.map((o) => {
        const text = outcomeText(o.outcome);
        return (
          <React.Fragment key={text}>
            <div className="sb-kv">
              <span className="sb-kv__k">
                {text}
                {o.decidedByThisDevice && <span className="sb-tag" style={{ marginLeft: 6 }}>you decide</span>}
                {o.paysThisDevice && <span className="sb-tag" style={{ marginLeft: 6 }}>pays you</span>}
              </span>
            </div>
            {active && o.decidedByThisDevice && (
              <div className="sb-actions" style={{ margin: '4px 0 8px' }}>
                <button type="button" className="sb-btn sb-btn--small" aria-label={`Sign ${text}`} onClick={() => onSign(o.outcome)} disabled={busy}>
                  Sign
                </button>
                <button type="button" className="sb-btn sb-btn--small sb-btn--primary" aria-label={`Decide ${text}`} onClick={() => onDecide(o.outcome)} disabled={busy}>
                  Decide
                </button>
              </div>
            )}
          </React.Fragment>
        );
      })}
      {verdict !== undefined && <p className="sb-hint">{verdictWords(verdict)}</p>}
      {active && paysThisDevice && (
        <button type="button" className="sb-btn sb-btn--primary sb-btn--block" style={{ marginTop: 8 }} onClick={onRelease} disabled={busy}>
          Release
        </button>
      )}
      <div className="sb-actions" style={{ margin: '8px 0 0' }}>
        <button type="button" className="sb-btn" onClick={() => onCopy('Verdict cell', cell)}>Copy cell</button>
        <button type="button" className="sb-btn" onClick={onVerdict} disabled={busy}>Check outcome</button>
      </div>
    </section>
  );
}

type Props = {
  /** The held tokens that carry an anchor, as SoFi offers them. */
  tokenOptions: TokenOption[];
  /** After a stake moved: the wallet reads its balances again. */
  onMoved: () => Promise<void>;
};

export default function EscrowTab({ tokenOptions, onMoved }: Props): React.JSX.Element {
  const { contacts } = useContacts();
  const [me, setMe] = useState<escrow.EscrowParty | null>(null);
  const [mine, setMine] = useState<escrow.EscrowVault[] | null>(null);
  const [searched, setSearched] = useState<Uint8Array | null>(null);
  const [found, setFound] = useState<escrow.EscrowVault[] | null>(null);
  const [verdicts, setVerdicts] = useState<Record<string, escrow.EscrowVerdict>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [status, setStatus] = useState<Status | null>(null);

  // The lock form.
  const [token, setToken] = useState('');
  const [amount, setAmount] = useState('');
  const [agreement, setAgreement] = useState('');
  const [rows, setRows] = useState<OutcomeRow[]>(() => [newRow()]);
  const [linked, setLinked] = useState('');
  const [created, setCreated] = useState<escrow.EscrowLocked | null>(null);
  const [cell, setCell] = useState('');

  const myId = me === null ? null : encodeBase32Crockford(me.deviceId);
  const parties: Party[] = useMemo(() => [
    ...(myId === null ? [] : [{ id: myId, label: 'This device' }]),
    ...contacts.map((c) => ({ id: c.deviceId, label: c.alias })),
  ], [myId, contacts]);

  // This device as a party, then the escrow vaults it locked.
  useEffect(() => {
    const load = async () => {
      try {
        setMe(await escrow.party());
        setMine(await escrow.vaults());
      } catch (e) {
        setStatus({ kind: 'error', text: `Escrow: ${messageOf(e)}` });
      }
    };
    load();
  }, []);

  const run = useCallback(async (what: string, f: () => Promise<string>) => {
    setBusy(what);
    setStatus({ kind: 'info', text: `${what}…` });
    try {
      setStatus({ kind: 'success', text: await f() });
    } catch (e) {
      setStatus({ kind: 'error', text: `${what} failed: ${messageOf(e)}` });
    } finally {
      setBusy(null);
    }
  }, []);

  /** Read the vaults shown again, as Rust now holds them. */
  const reread = useCallback(async () => {
    setMine(await escrow.vaults());
    if (searched !== null) setFound(await escrow.locked(searched));
  }, [searched]);

  const setRow = (key: number, patch: Partial<OutcomeRow>) =>
    setRows((rs) => rs.map((r) => (r.key === key ? { ...r, ...patch } : r)));
  const toggleDecider = (key: number, id: string) =>
    setRows((rs) => rs.map((r) => {
      if (r.key !== key) return r;
      const decidedBy = r.decidedBy.includes(id) ? r.decidedBy.filter((d) => d !== id) : [...r.decidedBy, id];
      return { ...r, decidedBy };
    }));

  const filled = token !== '' && amount.trim() !== '' && agreement !== ''
    && rows.every((r) => r.label !== '' && r.decidedBy.length > 0 && r.pays !== '');

  const onLock = () => run('Lock stake', async () => {
    const done = await escrow.lock({
      external: utf8.encode(agreement),
      token: idBytes('the token', token),
      amountEntered: amount,
      outcomes: rows.map((r) => ({
        outcome: utf8.encode(r.label),
        decidedBy: r.decidedBy.map((id) => idBytes('a party', id)),
        pays: idBytes('the payee', r.pays),
      })),
      linkedVaultId: linked.trim() === '' ? undefined : idBytes('the linked vault', linked),
    });
    setCreated(done);
    await reread();
    await onMoved();
    return `Locked in vault ${middleTruncate(encodeBase32Crockford(done.vaultId), 8, 6)}`;
  });

  const keyOf = (v: escrow.EscrowVault) => encodeBase32Crockford(v.vaultId);
  const remember = (v: escrow.EscrowVault, got: escrow.EscrowVerdict) =>
    setVerdicts((held) => ({ ...held, [keyOf(v)]: got }));

  const onVerdict = (v: escrow.EscrowVault) => run('Check outcome', async () => {
    const got = await escrow.verdict(v.vaultId);
    remember(v, got);
    return verdictWords(got);
  });
  const onSign = (v: escrow.EscrowVault, outcome: Uint8Array) => run(`Sign ${outcomeText(outcome)}`, async () => {
    await escrow.sign(v.vaultId, outcome);
    return `Signed ${outcomeText(outcome)}`;
  });
  const onDecide = (v: escrow.EscrowVault, outcome: Uint8Array) => run(`Decide ${outcomeText(outcome)}`, async () => {
    const got = await escrow.decide(v.vaultId, outcome);
    remember(v, got);
    await reread();
    return verdictWords(got);
  });
  const onRelease = (v: escrow.EscrowVault) => run('Release', async () => {
    const r = await escrow.release(v.vaultId);
    await reread();
    await onMoved();
    return releaseWords(r);
  });
  const onFind = () => run('Find', async () => {
    const at = idBytes('the verdict cell', cell);
    const got = await escrow.locked(at);
    setSearched(at);
    setFound(got);
    return `${got.length} escrow vault${got.length === 1 ? '' : 's'} on this verdict cell`;
  });
  const onCopy = (what: string, text: string) => {
    copyText(text).then(
      (copied) => setStatus(copied ? { kind: 'success', text: `${what} copied` } : { kind: 'error', text: `${what}: copying failed` }),
      (e: unknown) => setStatus({ kind: 'error', text: `${what}: ${messageOf(e)}` }),
    );
  };

  const card = (v: escrow.EscrowVault) => (
    <VaultCard
      key={keyOf(v)}
      vault={v}
      verdict={verdicts[keyOf(v)]}
      busy={busy !== null}
      onVerdict={() => onVerdict(v)}
      onSign={(o) => onSign(v, o)}
      onDecide={(o) => onDecide(v, o)}
      onRelease={() => onRelease(v)}
      onCopy={onCopy}
    />
  );

  return (
    <div className="escrow-tab">
      {status && <Notice kind={status.kind} onClose={() => setStatus(null)}>{status.text}</Notice>}

      <p className="sb-hint">
        Lock a stake of one of your tokens in an escrow vault. Its terms list outcomes, and each names who decides
        it and who it pays. The vault keeps the hash of the agreed text, never the text. Once an outcome is
        decided, the party it pays releases the whole stake, once. An app that uses escrow tells you what to enter.
      </p>

      <section className="sb-card">
        <div className="sb-card__title">Your escrow vaults</div>
        {mine === null && <p className="sb-hint">Reading…</p>}
        {mine !== null && mine.length === 0 && <p className="sb-hint">No escrow vaults yet.</p>}
      </section>
      {mine !== null && mine.map(card)}

      {created && (
        <section className="sb-card sb-card--dark">
          <div className="sb-card__title">Escrow vault locked</div>
          <div className="sb-kv">
            <span className="sb-kv__k">Vault</span>
            <span className="sb-kv__v sb-kv__v--mono">{middleTruncate(encodeBase32Crockford(created.vaultId), 8, 6)}</span>
          </div>
          <div className="sb-kv">
            <span className="sb-kv__k">Verdict cell</span>
            <span className="sb-kv__v sb-kv__v--mono">{middleTruncate(encodeBase32Crockford(created.verdictCell), 8, 6)}</span>
          </div>
          <p className="sb-hint">
            The verdict cell finds every vault bound to this agreement and these outcomes: give it to the other parties.
          </p>
          <div className="sb-actions" style={{ margin: '8px 0 0' }}>
            <button type="button" className="sb-btn" onClick={() => onCopy('Verdict cell', encodeBase32Crockford(created.verdictCell))}>Copy cell</button>
            <button type="button" className="sb-btn sb-btn--primary" onClick={() => setCreated(null)}>OK</button>
          </div>
        </section>
      )}

      <section className="sb-card">
        <div className="sb-card__title">Lock a stake</div>
        <div className="sb-field">
          <label htmlFor="escrow-amount">Stake</label>
          <div className="sb-input-row">
            <input
              id="escrow-amount"
              type="text"
              inputMode="decimal"
              className="sb-input sb-input--mono"
              placeholder="0"
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
            />
            <TokenSelect label="Stake token" className="sb-tokensel--inline" value={token} options={tokenOptions} onChange={setToken} placeholder="Token" />
          </div>
        </div>
        <div className="sb-field">
          <label htmlFor="escrow-agreement">Agreement, exactly as every party has it</label>
          <textarea
            id="escrow-agreement"
            className="sb-input sb-input--mono"
            rows={3}
            value={agreement}
            onChange={(e) => setAgreement(e.target.value)}
          />
        </div>
        <p className="sb-hint sb-hint--tight">
          Every vault locked on the same agreement and the same outcomes shares one verdict.
        </p>

        {rows.map((r, i) => (
          <div key={r.key} style={{ borderTop: '1px dashed var(--border)', paddingTop: 8, marginBottom: 8 }}>
            <div className="sb-field">
              <label htmlFor={`escrow-outcome-${r.key}`}>Outcome {i + 1}</label>
              <input
                id={`escrow-outcome-${r.key}`}
                type="text"
                className="sb-input"
                value={r.label}
                onChange={(e) => setRow(r.key, { label: e.target.value })}
              />
            </div>
            <div className="sb-field" role="group" aria-label={`Outcome ${i + 1} decided by`}>
              <span className="sb-label">Decided by</span>
              {parties.map((p) => (
                <label key={p.id} className="sb-hint" style={{ display: 'block' }}>
                  <input
                    type="checkbox"
                    aria-label={`Outcome ${i + 1} decided by ${p.label}`}
                    checked={r.decidedBy.includes(p.id)}
                    onChange={() => toggleDecider(r.key, p.id)}
                  />
                  {' '}{p.label}
                </label>
              ))}
            </div>
            <div className="sb-field">
              <label htmlFor={`escrow-pays-${r.key}`}>Pays</label>
              <select
                id={`escrow-pays-${r.key}`}
                className="sb-input sb-input--small"
                value={r.pays}
                onChange={(e) => setRow(r.key, { pays: e.target.value })}
              >
                <option value="">Choose who it pays</option>
                {parties.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
              </select>
            </div>
            {rows.length > 1 && (
              <button type="button" className="sb-btn sb-btn--small" onClick={() => setRows((rs) => rs.filter((x) => x.key !== r.key))}>
                Remove outcome {i + 1}
              </button>
            )}
          </div>
        ))}
        <button type="button" className="sb-btn sb-btn--block" onClick={() => setRows((rs) => [...rs, newRow()])}>
          Add outcome
        </button>
        <p className="sb-hint sb-hint--tight">
          An outcome decided by more than one party is decided once each of them has signed it.
        </p>

        <Disclosure summary="Link to another escrow vault" className="escrow-linked">
          <div className="sb-field">
            <label htmlFor="escrow-linked">Linked vault id</label>
            <input
              id="escrow-linked"
              type="text"
              className="sb-input sb-input--mono sb-input--small"
              value={linked}
              onChange={(e) => setLinked(e.target.value)}
            />
          </div>
          <p className="sb-hint sb-hint--tight">The stake is locked only once that vault is active on the same verdict cell.</p>
        </Disclosure>

        <button
          type="button"
          className="sb-btn sb-btn--primary sb-btn--block"
          onClick={onLock}
          disabled={busy !== null || !filled}
        >
          Lock stake
        </button>
      </section>

      <section className="sb-card">
        <div className="sb-card__title">Escrow vaults by verdict cell</div>
        <div className="sb-field">
          <label htmlFor="escrow-cell">Verdict cell</label>
          <input
            id="escrow-cell"
            type="text"
            className="sb-input sb-input--mono"
            value={cell}
            onChange={(e) => setCell(e.target.value)}
          />
        </div>
        <button type="button" className="sb-btn sb-btn--block" onClick={onFind} disabled={busy !== null || cell.trim() === ''}>
          Find
        </button>
        <p className="sb-hint sb-hint--tight">Lists every vault bound to the cell, whoever locked it, so the party an outcome pays can release it.</p>
      </section>
      {found !== null && found.map(card)}
    </div>
  );
}
