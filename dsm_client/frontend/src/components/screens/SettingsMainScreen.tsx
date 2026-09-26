// SPDX-License-Identifier: MIT OR Apache-2.0

/* eslint-disable @typescript-eslint/no-explicit-any */
// src/components/screens/SettingsMainScreen.tsx
import React, { useCallback, useEffect, useRef, useState, memo } from 'react';
import { dsmClient } from '../../services/dsmClient';
import {
  getNfcBackupStatus,
  setAutoWriteEnabled,
  type NfcBackupStatus,
} from '../../services/recovery/nfcRecoveryService';
import { getNfcBackupUiModel } from '../../services/recovery/nfcBackupUi';
import { tourStore } from '../tour/tourStore';
import './SettingsScreen.css';

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
  const [devMode, setDevMode] = useState<boolean>(() => cachedDevMode ?? false);
  const [devModeResolved, setDevModeResolved] = useState<boolean>(() => cachedDevMode !== null);
  const [tapCount, setTapCount] = useState<number>(0);
  const devModeUnlockingRef = useRef(false);
  // ringId is stored in native prefs via setPreference; no React state needed.
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

  return (
    <main className="settings-shell settings-shell--main" role="main" aria-labelledby="settings-title">
      <div id="settings-title" className="settings-shell__title">
        SETTINGS
      </div>

      {/* Version row with 7-tap unlock (deterministic counter, no timers) */}
      <button
        type="button"
        className="settings-shell__button settings-shell__button--stack"
        onClick={onVersionTap}
        aria-describedby={!devMode ? 'dev-hint' : undefined}
        style={{
          marginBottom: '12px',
          textAlign: 'left',
        }}
      >
        <div
          style={{
            fontSize: '10px',
            fontWeight: 'bold',
            marginBottom: '4px',
          }}
        >
          VERSION
        </div>
        <div style={{ fontSize: '9px' }}>1.0.0</div>
        {!devMode && devModeResolved && (
          <div
            id="dev-hint"
            style={{
              fontSize: '8px',
              opacity: 0.7,
              marginTop: '6px',
            }}
          >
            TAP 7X FOR DEV OPTIONS ({tapCount}/7)
          </div>
        )}
      </button>

      {/* Backup & Restore Section */}
      {/* Guided tour — replay at any time */}
      <section
        aria-labelledby="tour-section-title"
        className="settings-shell__panel"
      >
        <div
          id="tour-section-title"
          style={{
            fontSize: '10px',
            fontWeight: 'bold',
            marginBottom: '6px',
            letterSpacing: '1px',
          }}
        >
          GUIDED TOUR
        </div>
        <div className="settings-shell__button-row">
          <button
            type="button"
            className="settings-shell__button"
            data-tour="tutorial-button"
            onClick={() => tourStore.start()}
          >
            Replay tutorial
          </button>
        </div>
      </section>

      {/* Security / Wallet Lock */}
      <section
        aria-labelledby="security-section-title"
        className="settings-shell__panel"
      >
        <div
          id="security-section-title"
          style={{
            fontSize: '10px',
            fontWeight: 'bold',
            marginBottom: '8px',
            color: 'var(--text-dark)',
            letterSpacing: '1px',
          }}
        >
          SECURITY
        </div>
        <div
          style={{
            fontSize: '8px',
            color: 'var(--text-dark)',
            marginBottom: '12px',
            lineHeight: '1.4',
            opacity: 0.8,
          }}
        >
          PROTECT YOUR WALLET WITH A PIN, BUTTON COMBO, OR BIOMETRIC LOCK.
        </div>
        <button
          className="settings-shell__button"
          onClick={() => onNavigate?.('lock_setup')}
          style={{ fontSize: '9px', width: '100%' }}
        >
          CONFIGURE WALLET LOCK
        </button>
      </section>

      {/* NFC Ring Backup — compact card, full management on dedicated screen */}
      <section
        aria-labelledby="nfc-section-title"
        className="settings-shell__panel"
      >
        <div
          id="nfc-section-title"
          style={{
            fontSize: '10px',
            fontWeight: 'bold',
            marginBottom: '6px',
            letterSpacing: '1px',
          }}
        >
          NFC RING BACKUP
        </div>
        <div style={{ marginBottom: 8 }}>
          <div
            style={{
              fontSize: '9px',
              fontWeight: 'bold',
              color: 'var(--text-dark)',
              marginBottom: 4,
            }}
          >
            {nfcRead === undefined ? '…' : nfcUi ? nfcUi.backupLabel : 'NOT READ'}
            {nfcUi && nfcUi.writeStateLabel !== '--' ? ` / ${nfcUi.writeStateLabel}` : ''}
          </div>
          <div
            style={{
              fontSize: '8px',
              color: 'var(--text-dark)',
              lineHeight: '1.4',
              opacity: 0.82,
            }}
          >
            {nfcRead === undefined
              ? 'Reading the backup status…'
              : nfcUi
                ? nfcUi.compactSummary
                : `Status not read: ${(nfcRead as { error: string }).error}`}
          </div>
        </div>
        <div className="settings-shell__button-row">
          <button
            className="settings-shell__button"
            onClick={() => onNavigate?.('nfc_recovery')}
            style={{ fontSize: '9px' }}
          >
            MANAGE BACKUP
          </button>
          <button
            className="settings-shell__button"
            onClick={() => onNavigate?.('recovery')}
            style={{ fontSize: '9px' }}
          >
            INSPECT OR RECOVER
          </button>
        </div>
        {nfcStatus && nfcStatus.enabled && nfcStatus.configured && (
          <button
            className="settings-shell__button"
            onClick={() => {
              const next = !nfcStatus.autoWriteEnabled;
              void setAutoWriteEnabled(next).then(() =>
                setNfcRead({ status: { ...nfcStatus, autoWriteEnabled: next } }),
              );
            }}
            style={{ fontSize: '9px', width: '100%', marginTop: 6 }}
          >
            AUTO-BACKUP TO RING: {nfcStatus.autoWriteEnabled ? 'ON' : 'OFF'}
          </button>
        )}
      </section>

      {/* Developer Options (only when unlocked) */}
      {devMode && (
        <section
          aria-labelledby="dev-section-title"
          className="settings-shell__panel"
        >
          <div
            style={{
              fontSize: '10px',
              fontWeight: 'bold',
              marginBottom: '8px',
              color: 'var(--text-dark)',
              letterSpacing: '1px',
            }}
          >
            DEVELOPER OPTIONS
          </div>
          <div
            style={{
              display: 'grid',
              gap: '8px',
            }}
          >

            <button
              type="button"
              className="settings-shell__button"
              style={{ fontSize: '9px' }}
              onClick={() => onNavigate?.('dev_policy')}
            >
              POLICY TOOLS
            </button>


            <button
              type="button"
              className="settings-shell__button"
              style={{ fontSize: '9px' }}
              onClick={openDiagnosticsWorkspace}
            >
              REPORT ISSUE / FEEDBACK
            </button>

          </div>
        </section>
      )}

      {status && (
        <div
          role="status"
          aria-live="polite"
          className="settings-shell__status settings-shell__status--flush"
        >
          {status.toUpperCase()}
        </div>
      )}
    </main>
  );
};

export default memo(SettingsMainScreen);
