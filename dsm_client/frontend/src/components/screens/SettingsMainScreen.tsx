// SPDX-License-Identifier: MIT OR Apache-2.0

// src/components/screens/SettingsMainScreen.tsx
// Settings on the StateBoy frame: the version (and its 7-tap developer
// unlock), the tour, the wallet lock, the ring backup as Rust reports it, and
// the developer options once unlocked.
import React, { useCallback, useEffect, useRef, useState, memo } from 'react';
import { dsmClient } from '../../services/dsmClient';
import {
  getNfcBackupStatus,
  setAutoWriteEnabled,
  type NfcBackupStatus,
} from '../../services/recovery/nfcRecoveryService';
import { getNfcBackupUiModel } from '../../services/recovery/nfcBackupUi';
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

/** The backup status as Rust reported it, the failure of asking, or not asked yet. */
type NfcStatusRead = { status: NfcBackupStatus } | { error: string } | undefined;

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

  // --- Compact NFC status (full management is on NfcRecoveryScreen) ---
  // A status that could not be read is shown as that failure; it used to be
  // shown as "NOT SET", the status of a device with no backup at all.
  const [nfcRead, setNfcRead] = useState<NfcStatusRead>(undefined);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const status = await getNfcBackupStatus();
        if (!cancelled) setNfcRead({ status });
      } catch (e) {
        if (!cancelled) setNfcRead({ error: e instanceof Error ? e.message : String(e) });
      }
    })();
    return () => { cancelled = true; };
  }, []);

  const nfcStatus = nfcRead && 'status' in nfcRead ? nfcRead.status : null;
  const nfcUi = nfcStatus ? getNfcBackupUiModel(nfcStatus) : null;

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

  const onToggleAutoWrite = useCallback((next: boolean) => {
    if (!nfcStatus || nfcStatus.autoWriteEnabled === next) return;
    void setAutoWriteEnabled(next).then(() =>
      setNfcRead({ status: { ...nfcStatus, autoWriteEnabled: next } }),
    );
  }, [nfcStatus]);

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
          <span className="sb-kv__k">VERSION</span>
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

      {/* NFC Ring Backup — compact card, full management on dedicated screen */}
      <section className="sb-card sb-card--dark" aria-labelledby="nfc-section-title">
        <div id="nfc-section-title" className="sb-card__title">NFC ring backup</div>
        <div className="sb-hero__value" style={{ fontSize: 14, marginTop: 0 }}>
          {nfcRead === undefined ? '…' : nfcUi ? nfcUi.backupLabel : 'NOT READ'}
          {nfcUi && nfcUi.writeStateLabel !== '--' ? ` / ${nfcUi.writeStateLabel}` : ''}
        </div>
        <div className="sb-hint sb-hint--tight" style={{ marginBottom: 8 }}>
          {nfcRead === undefined
            ? 'Reading the backup status…'
            : nfcUi
              ? nfcUi.compactSummary
              : `Status not read: ${(nfcRead as { error: string }).error}`}
        </div>
        <div style={{ display: 'grid', gap: 8 }}>
          <button type="button" className="sb-btn sb-btn--block" onClick={() => onNavigate?.('nfc_recovery')}>
            Manage backup
          </button>
          <button type="button" className="sb-btn sb-btn--block" onClick={() => onNavigate?.('recovery')}>
            Inspect or recover
          </button>
        </div>
        {nfcStatus && nfcStatus.enabled && nfcStatus.configured && (
          <div className="sb-kv" style={{ marginTop: 8, alignItems: 'center' }}>
            <span className="sb-kv__k">Auto-backup to ring</span>
            <div className="sb-seg" role="group" aria-label="Auto-backup to ring">
              <button
                type="button"
                className={`sb-seg__opt${nfcStatus.autoWriteEnabled ? ' active' : ''}`}
                aria-pressed={nfcStatus.autoWriteEnabled}
                onClick={() => onToggleAutoWrite(true)}
              >
                On
              </button>
              <button
                type="button"
                className={`sb-seg__opt${nfcStatus.autoWriteEnabled ? '' : ' active'}`}
                aria-pressed={!nfcStatus.autoWriteEnabled}
                onClick={() => onToggleAutoWrite(false)}
              >
                Off
              </button>
            </div>
          </div>
        )}
      </section>

      {/* Developer Options (only when unlocked) */}
      {devMode && (
        <section className="sb-card" aria-labelledby="dev-section-title">
          <div id="dev-section-title" className="sb-card__title">DEVELOPER OPTIONS</div>
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
