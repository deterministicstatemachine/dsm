// SPDX-License-Identifier: Apache-2.0
// The Simple skin's Settings tab: the look, offline payments, email receipts,
// your card, the lock, and reporting a problem.

import React, { useState } from 'react';
import { useAppRuntimeStore, type Scheme, type Skin, type Switch } from '../../runtime/appRuntimeStore';
import { chooseScheme, chooseSkin, setSimpleOffline } from '../../runtime/skinPreferences';
import { navigationStore } from '../../runtime/navigationStore';
import { Icon } from './parts';
import { simpleNav } from './simpleNav';

const OPEN_DIAGNOSTICS_EVENT = 'dsm-open-diagnostics';

function Seg<T extends string>({ label, value, options, onPick }: { label: string; value: T; options: { id: T; text: string }[]; onPick: (v: T) => void }): React.JSX.Element {
  return (
    <div className="s-field">
      <div className="s-label">{label}</div>
      <div className="s-seg" role="group" aria-label={label}>
        {options.map((o) => (
          <button key={o.id} type="button" aria-pressed={value === o.id} onClick={() => onPick(o.id)}>{o.text}</button>
        ))}
      </div>
    </div>
  );
}

function Link({ title, sub, onOpen }: { title: string; sub: string; onOpen: () => void }): React.JSX.Element {
  return (
    <button type="button" className="s-row" onClick={onOpen}>
      <span className="s-row-main">
        <span className="s-row-title" style={{ display: 'block' }}>{title}</span>
        <span className="s-row-sub" style={{ display: 'block' }}>{sub}</span>
      </span>
      <Icon name="chevron" />
    </button>
  );
}

export default function SimpleSettings(): React.JSX.Element {
  const runtime = useAppRuntimeStore();
  const [said, setSaid] = useState<string | null>(null);

  const report = (what: Promise<void>) => {
    what.then(
      () => setSaid(null),
      (e: unknown) => setSaid(e instanceof Error ? e.message : String(e)),
    );
  };

  return (
    <>
      <h1 className="s-title">Settings</h1>
      {said !== null ? <div className="s-notice s-error">{said}</div> : null}

      <section className="s-card" aria-label="Appearance">
        <div className="s-section-title" style={{ marginBottom: 10 }}>Appearance</div>
        <Seg<Skin>
          label="Wallet style"
          value={runtime.skin !== null ? runtime.skin : 'simple'}
          options={[{ id: 'simple', text: 'Simple' }, { id: 'classic', text: 'Classic' }]}
          onPick={(v) => report(chooseSkin(v))}
        />
        <Seg<Scheme>
          label="Colours"
          value={runtime.scheme}
          options={[{ id: 'light', text: 'Light' }, { id: 'dark', text: 'Dark' }]}
          onPick={(v) => report(chooseScheme(v))}
        />
        <Seg<Switch>
          label="Offline payments (appliance)"
          value={runtime.simpleOffline}
          options={[{ id: 'off', text: 'Off' }, { id: 'on', text: 'On' }]}
          onPick={(v) => report(setSimpleOffline(v))}
        />
      </section>

      <section className="s-card" aria-label="You">
        <Link title="My contact card" sub="Your name, and what your DSM code shares" onOpen={() => simpleNav.open({ kind: 'my_card' })} />
        <Link
          title="Email receipts"
          sub={runtime.receiptsEmail === 'on' ? 'On: people you pay get a receipt' : 'Off'}
          onOpen={() => simpleNav.open({ kind: 'receipts' })}
        />
      </section>

      <section className="s-card" aria-label="Security and help">
        <Link title="Lock" sub="A passcode for this wallet" onOpen={() => navigationStore.navigate('lock_setup')} />
        <Link title="Report a problem" sub="Send the wallet's report to the DSM team" onOpen={() => window.dispatchEvent(new CustomEvent(OPEN_DIAGNOSTICS_EVENT))} />
      </section>
      <p className="s-hint" style={{ textAlign: 'center' }}>Classic shows every DSM feature: trading, tokens, storage and more.</p>
    </>
  );
}
