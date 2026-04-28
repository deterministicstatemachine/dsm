/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import React from 'react';
import type { AppState, ScreenType } from '../types/app';
import LoadingSpinner from './common/LoadingSpinner';
import SplashController from './SplashController';
import LockScreen from './lock/LockScreen';
import LockPromptModal from './lock/LockPromptModal';
import AppScreenRouter from './AppScreenRouter';
import { buildHomeStatusLines } from '../viewmodels/homeViewModel';

type Props = {
  appState: AppState;
  error: string | null;
  showIntro: boolean;
  introGifSrc: string;
  eraTokenSrc: string;
  btcLogoSrc: string;
  dsmLogoSrc: string;
  chameleonSrc: string;
  setChameleonSrc: React.Dispatch<React.SetStateAction<string>>;
  soundEnabled: boolean;
  securingProgress: number;
  currentScreen: ScreenType;
  navigate: (to: ScreenType) => void;
  handleGenerateGenesis: () => Promise<void> | void;
  showLockPrompt: boolean;
  dismissLockPrompt: () => void;
  unlockToWallet: () => void;
  menuItems: string[];
  currentMenuIndex: number;
  setCurrentMenuIndex: (next: number) => void;
};

type MenuOptions = {
  itemClassName?: string;
  actions?: { [key: string]: () => void };
};

function MenuRenderer({
  items,
  currentMenuIndex,
  setCurrentMenuIndex,
  options,
}: {
  items: string[];
  currentMenuIndex: number;
  setCurrentMenuIndex: (next: number) => void;
  options?: MenuOptions;
}) {
  return (
    <div className="dsm-menu" role="menu" aria-label="Main Menu">
      {items.map((item, index) => (
        <div
          key={`${item}-${index}`}
          className={`dsm-menu-item ${options?.itemClassName ?? ''} ${index === currentMenuIndex ? 'focused' : ''}`}
          data-label={item}
          role="menuitem"
          tabIndex={0}
          onClick={() => {
            setCurrentMenuIndex(index);
            if (options?.actions?.[item]) options.actions[item]();
          }}
          onKeyDown={(event) => {
            if (event.key === 'Enter' || event.key === ' ') {
              event.preventDefault();
              setCurrentMenuIndex(index);
              if (options?.actions?.[item]) options.actions[item]();
            }
          }}
        >
          <span className={`brick-label ${options?.itemClassName ? 'visible' : ''}`}>{item}</span>
        </div>
      ))}
    </div>
  );
}

function StatusText({ lines, style }: { lines: string[]; style?: React.CSSProperties }) {
  return (
    <div className="status-text" style={style}>
      {lines.map((line, index) => (
        <React.Fragment key={`${line}-${index}`}>
          {line}
          {index < lines.length - 1 ? <br /> : null}
        </React.Fragment>
      ))}
    </div>
  );
}

const securingContentStyle: React.CSSProperties = {
  width: '100%',
  maxWidth: '320px',
  gap: '12px',
  paddingTop: '24px',
};

const securingAlertStackStyle: React.CSSProperties = {
  display: 'flex',
  flexDirection: 'column',
  width: '100%',
};

const securingWarningStyle: React.CSSProperties = {
  display: 'flex',
  flexDirection: 'column',
  gap: '2px',
  width: '100%',
  textAlign: 'center',
  color: 'var(--text-dark)',
  fontFamily: "'Martian Mono', monospace",
  fontWeight: 900,
  letterSpacing: '0.08em',
  lineHeight: 1.4,
  textTransform: 'uppercase',
  animation: 'dsmSecuringBlink 1.8s steps(1, end) infinite',
};

const securingPrimaryWarningLineStyle: React.CSSProperties = {
  fontSize: '14px',
};

const securingCriticalWarningLineStyle: React.CSSProperties = {
  fontSize: '16px',
  lineHeight: 1.45,
};

const securingProgressTrackStyle: React.CSSProperties = {
  width: '100%',
  height: '16px',
  padding: '2px',
  border: '2px solid var(--border)',
  borderRadius: '6px',
  background: 'rgba(var(--text-rgb), 0.10)',
  boxSizing: 'border-box',
  overflow: 'hidden',
};

const securingStatusTextStyle: React.CSSProperties = {
  marginTop: 0,
  width: '100%',
  textAlign: 'center',
};

const securingBlinkKeyframes = `
  @keyframes dsmSecuringBlink {
    0%, 44% { opacity: 1; }
    45%, 78% { opacity: 0; }
    79%, 100% { opacity: 1; }
  }
`;

export default function AppContent({
  appState,
  error,
  showIntro,
  introGifSrc,
  eraTokenSrc,
  btcLogoSrc,
  dsmLogoSrc,
  chameleonSrc,
  setChameleonSrc,
  soundEnabled,
  securingProgress,
  currentScreen,
  navigate,
  handleGenerateGenesis,
  showLockPrompt,
  dismissLockPrompt,
  unlockToWallet,
  menuItems,
  currentMenuIndex,
  setCurrentMenuIndex,
}: Props) {
  if (showIntro) {
    return <SplashController showIntro={showIntro} introGifSrc={introGifSrc} />;
  }

  const errorMenuItems = ['RETRY CONNECTION', 'VIEW ERROR LOG'];

  switch (appState) {
    case 'loading':
      return (
        <div className="dsm-content">
            <LoadingSpinner message="Wallet" size="large" eraTokenSrc={eraTokenSrc} />
          <StatusText
            lines={[
              'INITIALIZING DSM',
              'CONNECTING TO NETWORK',
              'VERIFYING DEVICE',
              'PLEASE WAIT...',
            ]}
          />
        </div>
      );

    case 'runtime_loading':
      return (
        <div className="dsm-content">
            <LoadingSpinner message="Starting Runtime" size="large" eraTokenSrc={eraTokenSrc} />
          <StatusText
            lines={[
              'STARTING RUNTIME',
              'WARMING UP BRIDGE',
              'PLEASE WAIT...',
            ]}
          />
        </div>
      );

    case 'needs_genesis':
      return (
        <div className="dsm-content dsm-content--home">
          <img
            src={chameleonSrc}
            onError={() => setChameleonSrc('images/vaulthunters/chameleon-green(default).GIF')}
            alt="Chameleon"
            style={{ width: '260px', height: 'auto', position: 'absolute', top: '-43px', left: '-23px', zIndex: 1000 }}
          />
          <div className="dsm-logo-placeholder" style={{ marginTop: '80px', marginBottom: '10px' }}>
            <img src={eraTokenSrc} alt="Setup..." style={{ width: '60px', height: '60px', objectFit: 'contain' }} />
          </div>
          <div style={{ marginBottom: '20px', fontSize: '10px', color: 'var(--text-dark)', letterSpacing: '1px' }}>
            WALLET SETUP REQUIRED
          </div>
          <MenuRenderer
            items={['INITIALIZE']}
            currentMenuIndex={currentMenuIndex}
            setCurrentMenuIndex={setCurrentMenuIndex}
            options={{
              itemClassName: 'home-brick',
              actions: { INITIALIZE: () => void handleGenerateGenesis() },
            }}
          />
          <StatusText lines={buildHomeStatusLines({ appState, soundEnabled, error })} />
        </div>
      );

    case 'securing_device':
      return (
        <div className="dsm-content dsm-content--securing" style={securingContentStyle}>
          <style>{securingBlinkKeyframes}</style>
          <LoadingSpinner message="Securing Device" size="large" eraTokenSrc={eraTokenSrc} />
          <div className="dsm-securing-alerts" aria-live="assertive" style={securingAlertStackStyle}>
            <div
              className="dsm-securing-warning dsm-securing-warning--blink"
              style={securingWarningStyle}
            >
              <span style={securingPrimaryWarningLineStyle}>THIS ONLY HAPPENS ONCE</span>
              <span style={securingCriticalWarningLineStyle}>DO NOT LEAVE THE SCREEN UNTIL FINISHED</span>
            </div>
          </div>
          <div className="dsm-progress" aria-label="Securing device progress" style={securingProgressTrackStyle}>
            <div
              className="dsm-progress__fill"
              style={{
                width: `${securingProgress}%`,
                height: '100%',
                background:
                  'linear-gradient(0deg, rgba(var(--bg-rgb),0.16), rgba(var(--bg-rgb),0.04)), repeating-linear-gradient(45deg, rgba(var(--bg-rgb),0.35) 0px, rgba(var(--bg-rgb),0.35) 4px, rgba(var(--bg-rgb),0.15) 4px, rgba(var(--bg-rgb),0.15) 8px), var(--stateboy-dark)',
                transition: 'width 180ms ease-out',
              }}
            />
          </div>
          <StatusText
            lines={[
              'SECURING YOUR DEVICE',
              'SILICON FINGERPRINT ENROLLMENT',
              'DBRW SALT INITIALIZATION',
            ]}
            style={securingStatusTextStyle}
          />
        </div>
      );

    case 'wallet_ready':
      if (currentScreen === 'home') {
        return (
          <div className="dsm-content dsm-content--home">
            <img
              src={chameleonSrc}
              onError={() => setChameleonSrc('images/vaulthunters/chameleon.gif')}
              alt="Chameleon"
              style={{ width: '260px', height: 'auto', position: 'absolute', top: '-43px', left: '-23px', zIndex: 1000 }}
            />
            <div className="dsm-logo-placeholder" style={{ marginTop: '80px', marginBottom: '10px' }}>
              <img src={dsmLogoSrc} alt="DSM StateBoy Logo" style={{ width: '140%', height: '140%', objectFit: 'contain' }} />
            </div>
            <MenuRenderer
              items={menuItems}
              currentMenuIndex={currentMenuIndex}
              setCurrentMenuIndex={setCurrentMenuIndex}
              options={{
                itemClassName: 'home-brick',
                actions: {
                  WALLET: () => navigate('wallet'),
                  TOKENS: () => navigate('accounts'),
                  LIQUIDITY: () => navigate('liquidity'),
                  MAIL: () => navigate('mail'),
                  CONTACTS: () => navigate('contacts'),
                  STORAGE: () => navigate('storage'),
                  SETTINGS: () => navigate('settings'),
                },
              }}
            />
            <StatusText lines={buildHomeStatusLines({ appState, soundEnabled, error })} />
            {showLockPrompt ? (
              <LockPromptModal
                onNavigate={navigate}
                onDismiss={dismissLockPrompt}
              />
            ) : null}
          </div>
        );
      }

      return (
        <AppScreenRouter
          currentScreen={currentScreen}
          navigate={navigate}
          eraTokenSrc={eraTokenSrc}
          btcLogoSrc={btcLogoSrc}
        />
      );

    case 'locked':
      return <LockScreen onUnlock={unlockToWallet} />;

    case 'error':
      return (
        <div className="dsm-content">
          <div className="dsm-logo-placeholder" style={{ marginTop: '80px', marginBottom: '10px' }}>
            <div style={{ color: 'var(--text-dark)', fontSize: '24px' }}>ERROR</div>
          </div>
          <div style={{ marginBottom: '20px', fontSize: '10px', color: 'var(--text-dark)', letterSpacing: '1px' }}>SYSTEM ERROR</div>
          <MenuRenderer
            items={errorMenuItems}
            currentMenuIndex={currentMenuIndex}
            setCurrentMenuIndex={setCurrentMenuIndex}
            options={{ actions: { 'RETRY CONNECTION': () => window.location.reload() } }}
          />
          <StatusText lines={buildHomeStatusLines({ appState, soundEnabled, error })} />
        </div>
      );

    default:
      return null;
  }
}
