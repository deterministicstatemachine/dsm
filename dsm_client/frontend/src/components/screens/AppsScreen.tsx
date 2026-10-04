// SPDX-License-Identifier: Apache-2.0
// path: src/components/screens/AppsScreen.tsx
// Apps (DSM Amendment A11) on the StateBoy frame: the Web2 applications this
// wallet is connected to. Scan an application's connect code, read what it
// asks for, approve it once; after that it can ask this wallet for what it
// was granted without the player switching back to the phone, and anything
// else waits here. Rust verifies every offer, keeps every grant and carries
// out every request; this screen renders what Rust answers.

import React, { useCallback, useEffect, useRef, useState } from 'react';
import * as connect from '../../dsm/connect';
import { encodeBase32Crockford } from '../../utils/textId';
import { Disclosure, Notice, ScreenFrame, ScreenTabs, middleTruncate } from '../common/ScreenFrame';
import { InfoTip } from '../common/InfoTip';

type AppsTab = 'apps' | 'waiting';

type Status = { kind: 'info' | 'success' | 'error'; text: string };

/** How often the screen asks Rust for the sessions and waiting requests. */
const REFRESH_MS = 3000;

function messageOf(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function short(bytes: Uint8Array): string {
  return middleTruncate(encodeBase32Crockford(bytes), 6, 4);
}

const OUTCOME_LABEL: Record<connect.LogEntry['outcome'], string> = {
  carriedOut: 'carried out',
  awaitingApproval: 'waiting for you',
  declined: 'declined',
  failed: 'failed',
};

function SessionCard({
  session,
  busy,
  onDisconnect,
}: {
  session: connect.Session;
  busy: boolean;
  onDisconnect: (s: connect.Session) => void;
}): React.JSX.Element {
  const [entries, setEntries] = useState<connect.LogEntry[] | null>(null);
  const [logError, setLogError] = useState<string | null>(null);
  const loadLog = useCallback(async () => {
    try {
      setEntries(await connect.log(session.sessionId));
      setLogError(null);
    } catch (e: unknown) {
      setLogError(messageOf(e));
    }
  }, [session.sessionId]);
  return (
    <section className="sb-card" data-testid="connected-app">
      <div className="sb-row sb-row--between">
        <b>{session.displayName}</b>
        <span className="sb-hint">{session.connected ? 'connected' : 'disconnected'}</span>
      </div>
      <div className="sb-hint sb-hint--tight">
        Account {short(session.peerDeviceId)} · {session.endpoint}
      </div>
      <ul className="sb-list">
        {session.scopeLines.map((line) => (
          <li key={line}>{line}</li>
        ))}
      </ul>
      {session.spent.length > 0 && (
        <div className="sb-hint">
          Spent under this grant:{' '}
          {session.spent.map((s) => `${s.spent} of ${s.total} ${s.symbol}`).join(', ')}
        </div>
      )}
      <div className="sb-hint">Requests handled: {session.lastSeq.toString()}</div>
      {session.lastError !== '' && (
        <Notice kind="info">{session.lastError}</Notice>
      )}
      <Disclosure summary="What this wallet did for it">
        {logError !== null && <Notice kind="error">{logError}</Notice>}
        {entries === null ? (
          <button type="button" className="sb-btn sb-btn--small" onClick={loadLog}>
            Show
          </button>
        ) : entries.length === 0 ? (
          <div className="sb-hint">Nothing yet.</div>
        ) : (
          <ul className="sb-list">
            {entries.map((e) => (
              <li key={e.seq.toString()}>
                #{e.seq.toString()} {e.summary}: {OUTCOME_LABEL[e.outcome]}
                {e.detail !== '' ? ` (${e.detail})` : ''}
              </li>
            ))}
          </ul>
        )}
      </Disclosure>
      {session.connected && (
        <button
          type="button"
          className="sb-btn sb-btn--block"
          disabled={busy}
          onClick={() => onDisconnect(session)}
        >
          Disconnect
        </button>
      )}
    </section>
  );
}

export default function AppsScreen(): React.JSX.Element {
  const [tab, setTab] = useState<AppsTab>('apps');
  /// What is running, while something is: the buttons wait for it.
  const [running, setRunning] = useState<string | null>(null);
  const busy = running !== null;
  const [status, setStatus] = useState<Status | null>(null);
  const [sessions, setSessions] = useState<connect.Session[]>([]);
  const [waiting, setWaiting] = useState<connect.Pending[]>([]);
  const [code, setCode] = useState('');
  const [offer, setOffer] = useState<connect.Preview | null>(null);
  /// A camera scan this screen started and has not heard back from. The
  /// camera answers on the shared `dsm-event` channel, so a result is this
  /// screen's only while it is waiting for one.
  const scanRef = useRef<'idle' | 'waiting'>('idle');

  const refresh = useCallback(async () => {
    try {
      const [listed, held] = await Promise.all([connect.list(), connect.pending()]);
      setSessions(listed);
      setWaiting(held);
    } catch (e: unknown) {
      setStatus({ kind: 'error', text: `Reading connected apps failed: ${messageOf(e)}` });
    }
  }, []);

  useEffect(() => {
    const tick = () => {
      refresh().catch((e: unknown) =>
        setStatus({ kind: 'error', text: `Reading connected apps failed: ${messageOf(e)}` }),
      );
    };
    tick();
    const timer = window.setInterval(tick, REFRESH_MS);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const run = useCallback(
    async (what: string, f: () => Promise<string>) => {
      setRunning(what);
      setStatus({ kind: 'info', text: `${what}…` });
      try {
        setStatus({ kind: 'success', text: await f() });
      } catch (e: unknown) {
        setStatus({ kind: 'error', text: `${what} failed: ${messageOf(e)}` });
      } finally {
        setRunning(null);
        await refresh();
      }
    },
    [refresh],
  );

  const readCode = useCallback(
    (text: string) =>
      run('Reading the code', async () => {
        const read = await connect.preview(text);
        setOffer(read);
        return `${read.displayName} asks to connect. Read what it asks for, then approve or cancel.`;
      }),
    [run],
  );

  const scan = useCallback(async () => {
    if (scanRef.current === 'waiting') return;
    setStatus(null);
    scanRef.current = 'waiting';
    try {
      const { startNativeQrScannerViaRouter } = await import('../../dsm/WebViewBridge');
      await startNativeQrScannerViaRouter();
    } catch (e: unknown) {
      scanRef.current = 'idle';
      setStatus({ kind: 'error', text: `The camera could not be opened: ${messageOf(e)}` });
    }
  }, []);

  useEffect(() => {
    const onScanResult = (e: Event) => {
      const ce = e as CustomEvent<{ topic: string; payloadText?: string }>;
      if (ce.detail?.topic !== 'qr_scan_result' || scanRef.current !== 'waiting') return;
      scanRef.current = 'idle';
      const scanned = ce.detail.payloadText;
      // Empty: the scan was cancelled, or the camera read nothing.
      if (typeof scanned !== 'string' || !scanned.trim()) return;
      setCode(scanned.trim());
      readCode(scanned).catch((err: unknown) =>
        setStatus({ kind: 'error', text: `Reading the code failed: ${messageOf(err)}` }),
      );
    };
    window.addEventListener('dsm-event', onScanResult);
    return () => window.removeEventListener('dsm-event', onScanResult);
  }, [readCode]);

  const onApprove = () =>
    run('Connecting', async () => {
      if (offer === null) throw new Error('read a code first');
      const connected = await connect.approve(offer.offerDigest);
      setOffer(null);
      setCode('');
      return `Connected to ${connected.displayName}.`;
    });

  const onDisconnect = (s: connect.Session) =>
    run('Disconnecting', async () => {
      await connect.disconnect(s.sessionId);
      return `${s.displayName} is disconnected; it can ask for nothing more.`;
    });

  const onSync = () =>
    run('Checking connected apps', async () => {
      const synced = await connect.sync();
      return synced.length === 0
        ? 'No app is connected.'
        : `Checked ${synced.length} connected app${synced.length === 1 ? '' : 's'}.`;
    });

  const onDecide = (p: connect.Pending, choice: 'approve' | 'decline') =>
    run(choice === 'approve' ? 'Approving' : 'Declining', async () => {
      await connect.respond(p.sessionId, p.seq, choice);
      return choice === 'approve'
        ? `${p.displayName}: ${p.summary}, carried out.`
        : `${p.displayName}: ${p.summary}, declined.`;
    });

  const tabs: ReadonlyArray<{ id: AppsTab; label: string }> = [
    { id: 'apps', label: 'Apps' },
    { id: 'waiting', label: waiting.length > 0 ? `Waiting (${waiting.length})` : 'Waiting' },
  ];

  return (
    <ScreenFrame
      title="Apps"
      className="apps-screen"
      info={(
        <InfoTip title="Apps">
          <p>Connect a Web2 app, such as a game, to this wallet. The app keeps running as it always does; what you own in it lives here, in this wallet.</p>
          <p><b>Connect</b>: scan the code the app shows. You see exactly what it asks for before you approve. Once approved, it can ask this wallet for those things without you switching back to the phone.</p>
          <p>Anything outside what you approved waits in <b>Waiting</b> for you to approve or decline. Disconnecting ends the grant.</p>
          <p>An app never holds your keys. Every payment, trade or object goes through this wallet, checked exactly as if you made it yourself.</p>
        </InfoTip>
      )}
      actions={(
        <button
          type="button"
          className="sb-btn sb-btn--small"
          onClick={onSync}
          disabled={busy}
          title="Take in connected apps' requests now"
        >
          Check
        </button>
      )}
      tabs={<ScreenTabs tabs={tabs} active={tab} onChange={setTab} ariaLabel="Apps sections" />}
      banner={status ? (
        <Notice banner kind={status.kind} onClose={() => setStatus(null)}>{status.text}</Notice>
      ) : null}
    >
      {tab === 'apps' && (
        <div className="apps-tab">
          {offer === null ? (
            <section className="sb-card">
              <div className="sb-field">
                <label htmlFor="connect-code">Connect an app</label>
                <input
                  id="connect-code"
                  type="text"
                  className="sb-input sb-input--mono sb-input--small"
                  placeholder="dsm:connect/v1:…"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  autoCorrect="off"
                  autoCapitalize="none"
                />
              </div>
              <div className="sb-row">
                <button type="button" className="sb-btn" disabled={busy} onClick={scan}>
                  SCAN CODE
                </button>
                <button
                  type="button"
                  className="sb-btn sb-btn--primary"
                  disabled={busy || code.trim() === ''}
                  onClick={() => readCode(code)}
                >
                  READ
                </button>
              </div>
            </section>
          ) : (
            <section className="sb-card" data-testid="connect-offer">
              <b>{offer.displayName}</b> asks to connect.
              <div className="sb-hint sb-hint--tight">
                Account {short(offer.appDeviceId)} · {offer.endpoint}
              </div>
              <p className="sb-hint">If you approve, it can do these without asking you again:</p>
              <ul className="sb-list">
                {offer.scopeLines.map((line) => (
                  <li key={line}>{line}</li>
                ))}
              </ul>
              <p className="sb-hint">Anything else waits here for you. It never holds your keys.</p>
              <div className="sb-row">
                <button type="button" className="sb-btn" disabled={busy} onClick={() => setOffer(null)}>
                  CANCEL
                </button>
                <button type="button" className="sb-btn sb-btn--primary" disabled={busy} onClick={onApprove}>
                  APPROVE
                </button>
              </div>
            </section>
          )}
          {sessions.length === 0 ? (
            <p className="sb-hint">No app is connected yet.</p>
          ) : (
            sessions.map((s) => (
              <SessionCard
                key={encodeBase32Crockford(s.sessionId)}
                session={s}
                busy={busy}
                onDisconnect={onDisconnect}
              />
            ))
          )}
        </div>
      )}
      {tab === 'waiting' && (
        <div className="waiting-tab">
          {waiting.length === 0 ? (
            <p className="sb-hint">Nothing is waiting for you.</p>
          ) : (
            waiting.map((p) => (
              <section className="sb-card" key={`${encodeBase32Crockford(p.sessionId)}:${p.seq.toString()}`}>
                <b>{p.displayName}</b>: {p.summary}
                <div className="sb-hint">Outside what you approved: {p.reason}</div>
                <div className="sb-row">
                  <button type="button" className="sb-btn" disabled={busy} onClick={() => onDecide(p, 'decline')}>
                    DECLINE
                  </button>
                  <button type="button" className="sb-btn sb-btn--primary" disabled={busy} onClick={() => onDecide(p, 'approve')}>
                    APPROVE
                  </button>
                </div>
              </section>
            ))
          )}
        </div>
      )}
    </ScreenFrame>
  );
}
