// SPDX-License-Identifier: Apache-2.0
// The Simple skin from the first screen to the last: starting up, setting up
// a new wallet (its recovery phrase, publishing it, securing the device),
// restoring one, the lock, and errors. Once the wallet is ready, the Simple
// shell. Each phase is the app's own (runtime appState); this only draws it.

import React from 'react';
import AppScreenRouter from '../AppScreenRouter';
import LockScreen from '../lock/LockScreen';
import type { AppState, ScreenType } from '../../types/app';
import { Icon } from './parts';
import SimplePhrase from './SimplePhrase';
import SimpleShell from './SimpleShell';

/** The restore screens a wallet with no identity yet may open. */
const RESTORE = new Set<ScreenType>(['recovery', 'nfc_recovery', 'recovery_pipeline']);

type Props = {
  appState: AppState;
  error: string | null;
  securingProgress: number;
  currentScreen: ScreenType;
  navigate: (to: ScreenType) => void;
  handleGenerateGenesis: () => Promise<void> | void;
  cancelPhraseBackup: () => void;
  answerPhraseCheck: (word: string) => Promise<void>;
  eraTokenSrc: string;
  btcLogoSrc: string;
};

function Frame({ children }: { children: React.ReactNode }): React.JSX.Element {
  return (
    <div className="s-app">
      <header className="s-topbar">
        <div className="s-brand"><span className="s-brand-mark" aria-hidden /> DSM Wallet</div>
      </header>
      <main className="s-body">{children}</main>
    </div>
  );
}

function Waiting({ title, lines }: { title: string; lines: string[] }): React.JSX.Element {
  return (
    <Frame>
      <div className="s-waiting" aria-live="polite">
        <div className="s-spinner" aria-hidden />
        <h1 className="s-title" style={{ textAlign: 'center' }}>{title}</h1>
        {lines.map((line) => <p key={line} className="s-hint" style={{ textAlign: 'center' }}>{line}</p>)}
      </div>
    </Frame>
  );
}

export default function SimpleBoot(props: Props): React.JSX.Element {
  const { appState, navigate } = props;

  switch (appState) {
    case 'wallet_ready':
      return <SimpleShell eraTokenSrc={props.eraTokenSrc} btcLogoSrc={props.btcLogoSrc} />;

    case 'loading':
    case 'runtime_loading':
      return <Waiting title="Starting your wallet" lines={['Connecting to the DSM network…']} />;

    case 'needs_genesis':
      if (RESTORE.has(props.currentScreen)) {
        return (
          <Frame>
            <div className="s-classic">
              <button type="button" className="s-icon-btn" aria-label="Back" onClick={() => navigate('home')}>
                <Icon name="back" />
              </button>
              <AppScreenRouter currentScreen={props.currentScreen} navigate={navigate} eraTokenSrc={props.eraTokenSrc} btcLogoSrc={props.btcLogoSrc} />
            </div>
          </Frame>
        );
      }
      return (
        <Frame>
          <h1 className="s-title">Welcome to DSM</h1>
          <p className="s-subtitle" style={{ margin: '0 0 10px' }}>Your money, on your phone.</p>
          <section className="s-card s-balance">
            <p className="s-row-title" style={{ whiteSpace: 'normal' }}>Send and receive with the people you know.</p>
            <p className="s-hint" style={{ marginTop: 8 }}>
              Setting up takes a minute. You will write down a few words that are the only way to get your wallet back, so have a pen and paper ready.
            </p>
          </section>
          <div className="s-stack">
            <button type="button" className="s-btn s-btn-primary" onClick={() => { props.handleGenerateGenesis(); }}>
              Create my wallet
            </button>
            <button type="button" className="s-btn s-btn-quiet" onClick={() => navigate('recovery')}>
              Restore from my recovery ring
            </button>
          </div>
          {props.error !== null ? <div className="s-notice s-error" style={{ marginTop: 14 }}>{props.error}</div> : null}
        </Frame>
      );

    case 'backup_phrase':
      return (
        <Frame>
          <SimplePhrase onCancel={props.cancelPhraseBackup} onAnswer={props.answerPhraseCheck} />
        </Frame>
      );

    case 'publication_pending':
      return <Waiting title="Almost ready" lines={['Putting your wallet on the DSM network…', 'This can take a moment.']} />;

    case 'securing_device':
      return (
        <Frame>
          <div className="s-waiting" aria-live="assertive">
            <h1 className="s-title" style={{ textAlign: 'center' }}>Securing your phone</h1>
            <div className="s-progress" role="progressbar" aria-label="Securing your phone" aria-valuenow={props.securingProgress} aria-valuemin={0} aria-valuemax={100}>
              <div style={{ width: `${props.securingProgress}%` }} />
            </div>
            <div className="s-notice" style={{ marginTop: 18 }}>
              This only happens once. Keep the app open until it finishes.
            </div>
          </div>
        </Frame>
      );

    case 'locked':
      return (
        <Frame>
          <div className="s-classic">
            <LockScreen />
          </div>
        </Frame>
      );

    case 'error':
      return (
        <Frame>
          <h1 className="s-title">Something went wrong</h1>
          <div className="s-notice s-error">{props.error !== null ? props.error : 'The wallet could not start.'}</div>
          <button type="button" className="s-btn s-btn-primary" onClick={() => window.location.reload()}>Try again</button>
        </Frame>
      );
  }
}
