// SPDX-License-Identifier: MIT OR Apache-2.0

// src/components/screens/SettingsMainScreen.tsx
// Settings on the StateBoy frame: the version (and its 7-tap developer
// unlock), the tour, the wallet lock, and the developer options once unlocked.
import React, { useCallback, useEffect, useRef, useState, memo } from 'react';
import { dsmClient } from '../../services/dsmClient';
import { tourStore } from '../tour/tourStore';
import { chooseSkin, setReceiptsEmail } from '../../runtime/skinPreferences';
import { RECEIPT_CONSENT } from '../../domain/receiptConsent';
import { useAppRuntimeStore } from '../../runtime/appRuntimeStore';
import { versionLabel } from '../../appVersion';
import { Notice, ScreenFrame } from '../common/ScreenFrame';
import { InfoTip } from '../common/InfoTip';

const client = dsmClient;
const DEV_MODE_PREF_KEY = 'dev_mode';
const OPEN_DIAGNOSTICS_EVENT = 'dsm-open-diagnostics';
let cachedDevMode: boolean | null = null;

interface SettingsMainScreenProps {
  onNavigate?: (screen: string) => void;
}

const SettingsMainScreen: React.FC<SettingsMainScreenProps> = ({ onNavigate }) => {
  const runtime = useAppRuntimeStore();
  const [devMode, setDevMode] = useState<boolean>(() => cachedDevMode ?? false);
  const [devModeResolved, setDevModeResolved] = useState<boolean>(() => cachedDevMode !== null);
  const [tapCount, setTapCount] = useState<number>(0);
  const devModeUnlockingRef = useRef(false);
  const [status, setStatus] = useState<string>('');

  // Initial preferences load (deterministic, event-driven only)
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const devPref = await client.getPreference(DEV_MODE_PREF_KEY);
        const unlocked = devPref === '1' || devPref === 'true';
        cachedDevMode = unlocked;
        if (!cancelled) {
          setDevMode(unlocked);
        }
      } catch (e) {
        // Not unlocked until the preference says so; the failure is logged, not hidden.
        console.warn('[Settings] the developer-mode preference was not read:', e);
      } finally {
        if (!cancelled) {
          setDevModeResolved(true);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const enableDevMode = useCallback(async () => {
    devModeUnlockingRef.current = true;
    try {
      await client.setPreference(DEV_MODE_PREF_KEY, '1');
      cachedDevMode = true;
      setDevMode(true);
      setDevModeResolved(true);
      setStatus('Developer options enabled');
    } catch {
      setStatus('Failed to enable developer options');
    } finally {
      devModeUnlockingRef.current = false;
      setTapCount(0);
    }
  }, []);

  const onVersionTap = useCallback(() => {
    if (devMode || !devModeResolved || devModeUnlockingRef.current) {
      return;
    }
    setTapCount((current) => {
      const next = current + 1;
      if (next >= 7) {
        void enableDevMode();
        return 0;
      }
      return next;
    });
  }, [devMode, devModeResolved, enableDevMode]);

  const openDiagnosticsWorkspace = useCallback(() => {
    if (typeof window === 'undefined') return;
    window.dispatchEvent(new CustomEvent(OPEN_DIAGNOSTICS_EVENT, { detail: { autoGather: true } }));
    setStatus('Diagnostics workspace opened');
  }, []);

  return (
    <ScreenFrame
      title="Settings"
      className="settings-screen"
      banner={status ? (
        <Notice banner kind="success" onClose={() => setStatus('')}>{status}</Notice>
      ) : null}
    >
      {/* Version row with 7-tap unlock (deterministic counter, no timers) */}
      <button
        type="button"
        className="sb-card"
        onClick={onVersionTap}
        aria-describedby={!devMode ? 'dev-hint' : undefined}
      >
        <div className="sb-kv">
          <span className="sb-kv__k">Version</span>
          <span className="sb-kv__v">{versionLabel()}</span>
        </div>
        {!devMode && devModeResolved && (
          <div id="dev-hint" className="sb-hint sb-hint--tight">
            TAP 7X FOR DEV OPTIONS ({tapCount}/7)
          </div>
        )}
      </button>

      {/* The wallet's look: this Game Boy (DGen), or the Modern wallet. In the
          Modern skin these settings open inside it, and its own Settings
          changes the look. */}
      {runtime.skin === 'dgen' ? (
        <section className="sb-card" aria-labelledby="look-section-title">
          <div id="look-section-title" className="sb-card__title">Wallet style</div>
          <p className="sb-hint">Modern is a full-screen wallet with every DSM feature, light or dark, and a Simple mode. Switch back here from its Settings.</p>
          <button
            type="button"
            className="sb-btn sb-btn--block"
            onClick={() => {
              chooseSkin('modern').then(
                () => undefined,
                (e: unknown) => setStatus(e instanceof Error ? e.message : String(e)),
              );
            }}
          >
            Switch to Modern
          </button>
        </section>
      ) : null}

      {/* Your contact card and email receipts (DSM Amendment A17). The Modern
          skin has its own pages for both. */}
      {runtime.skin === 'dgen' ? (
        <section className="sb-card" aria-labelledby="card-section-title">
          <div id="card-section-title" className="sb-card__title">Contact card and receipts</div>
          <p className="sb-hint">Your name, email and phone ride on your contact code.</p>
          <button type="button" className="sb-btn sb-btn--block" onClick={() => onNavigate?.('mycontact')}>
            Edit my contact card
          </button>
          <p className="sb-hint" style={{ marginTop: 10 }}>{RECEIPT_CONSENT.lead} {RECEIPT_CONSENT.given}</p>
          <ul className="sb-hint">
            {RECEIPT_CONSENT.items.map((item) => <li key={item}>{item}</li>)}
          </ul>
          <p className="sb-hint">{RECEIPT_CONSENT.after}</p>
          <p className="sb-hint">Email receipts: {runtime.receiptsEmail === 'on' ? 'on' : 'off'}</p>
          <button
            type="button"
            className={`sb-btn sb-btn--block${runtime.receiptsEmail === 'on' ? '' : ' sb-btn--primary'}`}
            onClick={() => {
              setReceiptsEmail(runtime.receiptsEmail === 'on' ? 'off' : 'on').then(
                () => undefined,
                (e: unknown) => setStatus(e instanceof Error ? e.message : String(e)),
              );
            }}
          >
            {runtime.receiptsEmail === 'on' ? 'Turn receipts off' : 'I agree, turn receipts on'}
          </button>
        </section>
      ) : null}

      {/* The guided tour walks the Game Boy's buttons: DGen only. */}
      {runtime.skin === 'dgen' ? (
        <section className="sb-card" aria-labelledby="tour-section-title">
          <div id="tour-section-title" className="sb-card__title">Guided tour</div>
          <button
            type="button"
            className="sb-btn sb-btn--block"
            data-tour="tutorial-button"
            onClick={() => tourStore.start()}
          >
            Replay tutorial
          </button>
        </section>
      ) : null}

      {/* Security / Wallet Lock */}
      <section className="sb-card" aria-labelledby="security-section-title">
        <div id="security-section-title" className="sb-card__title">
          <span>Security</span>
          <InfoTip title="Wallet lock">
            <p>A lock asks for a PIN or a sequence of the shell&apos;s buttons before the wallet opens.</p>
            <p>It locks on leaving the app if you choose so. After three wrong tries only the wallet&apos;s recovery phrase opens it, and neither a wait nor a restart gives a try back.</p>
          </InfoTip>
        </div>
        <p className="sb-hint">Protect your wallet with a PIN or a button combo.</p>
        <button
          type="button"
          className="sb-btn sb-btn--primary sb-btn--block"
          onClick={() => onNavigate?.('lock_setup')}
        >
          Configure wallet lock
        </button>
      </section>

      {/* Developer Options (only when unlocked) */}
      {devMode && (
        <section className="sb-card" aria-labelledby="dev-section-title">
          <div id="dev-section-title" className="sb-card__title">Developer options</div>
          <div style={{ display: 'grid', gap: 8 }}>
            <button
              type="button"
              className="sb-btn sb-btn--block"
              onClick={() => onNavigate?.('dev_policy')}
            >
              Policy tools
            </button>
            <button
              type="button"
              className="sb-btn sb-btn--block"
              onClick={openDiagnosticsWorkspace}
            >
              Report issue / feedback
            </button>
          </div>
        </section>
      )}
    </ScreenFrame>
  );
};

export default memo(SettingsMainScreen);
