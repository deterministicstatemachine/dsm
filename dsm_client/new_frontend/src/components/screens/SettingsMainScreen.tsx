/* eslint-disable @typescript-eslint/no-explicit-any */
// src/components/screens/SettingsMainScreen.tsx
import React, { useCallback, useEffect, useRef, useState, memo } from 'react';
import { dsmClient } from '../../services/dsmClient';
import { exportStateBackupFile, importStateBackupFile } from '../../services/settings/backupService';

import { getNfcBackupStatus } from '../../services/recovery/nfcRecoveryService';
import './SettingsScreen.css';

type PrefValue = string | null;

interface NfcReadResult {
  ringId?: string;
}

interface ExtendedDsmClient {
  getPreference(key: string): Promise<PrefValue>;
  setPreference(key: string, value: string): Promise<void>;
  nfcReadRingId?: () => Promise<NfcReadResult | null>;
  nfcRegisterRingId?: (id: string) => Promise<boolean>;
  claimFaucet?: (tokenId?: string) => Promise<{ success: boolean; message?: string }>;
  exportStateBackup?: () => Promise<Uint8Array | ArrayBuffer | Blob | string>;
  importStateBackup?: (backup: Uint8Array) => Promise<{ success: boolean; message?: string }>;
}

const client = dsmClient as unknown as ExtendedDsmClient;
const DEV_MODE_PREF_KEY = 'dev_mode';
let cachedDevMode: boolean | null = null;

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
  const [backupStatus, setBackupStatus] = useState<string>('');
  const [backupProcessing, setBackupProcessing] = useState<boolean>(false);

  // --- Compact NFC status (full management is on NfcRecoveryScreen) ---
  const [nfcBackupEnabled, setNfcBackupEnabled] = useState(false);
  const [nfcCapsuleCount, setNfcCapsuleCount] = useState(0);
  const [nfcLastIndex, setNfcLastIndex] = useState(0);

  useEffect(() => {
    void (async () => {
      try {
        const s = await getNfcBackupStatus();
        setNfcBackupEnabled(s.enabled);
        setNfcCapsuleCount(s.capsuleCount);
        setNfcLastIndex(s.lastCapsuleIndex);
      } catch {
        /* tolerate — tables may not exist yet */
      }
    })();
  }, []);

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
      } catch {
        // Remain silent in UI; settings screen tolerates missing prefs
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

  const _onSetupRing = useCallback(async () => {
    try {
      const nfc = client.nfcReadRingId ? await client.nfcReadRingId() : null;
      let id: string | undefined = nfc?.ringId;

      if (!id) {
        const entered =
          typeof window !== 'undefined'
            ? window.prompt('Scan/enter Ring ID (read-only, provided by NFC):')
            : null;
        if (!entered || !entered.trim()) return;
        id = entered.trim();
      }

      const registered = client.nfcRegisterRingId
        ? await client.nfcRegisterRingId(id)
        : false;

      if (!registered) {
        await client.setPreference('nfc_ring_id', id);
      }

      setStatus('Ring registered successfully');
    } catch {
      setStatus('Failed to register ring');
    }
  }, []);

  const onExportBackup = useCallback(async () => {
    if (backupProcessing) return;
    setBackupProcessing(true);
    setBackupStatus('Exporting state...');
    try {
      const out = await exportStateBackupFile(client);
      if (out.blob && out.filename) {
        const url = URL.createObjectURL(out.blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = out.filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      }
      setBackupStatus(out.message || (out.ok ? 'Backup exported successfully' : 'Backup export failed'));
    } catch (err) {
      setBackupStatus(
        `Export failed: ${err instanceof Error ? err.message : 'unknown'}`
      );
    } finally {
      setBackupProcessing(false);
    }
  }, [backupProcessing]);

  const onImportBackup = useCallback(async () => {
    if (backupProcessing) return;

    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.bin,application/octet-stream';

    input.onchange = async e => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (!file) return;

      setBackupProcessing(true);
      setBackupStatus('Importing state...');

      try {
        const result = await importStateBackupFile(client, file);
        setBackupStatus(result.message);
      } catch (err) {
        setBackupStatus(
          `Import failed: ${err instanceof Error ? err.message : 'unknown'}`
        );
      } finally {
        setBackupProcessing(false);
      }
    };

    input.click();
  }, [backupProcessing]);

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
      <section
        aria-labelledby="backup-section-title"
        className="settings-shell__panel"
      >
        <div
          id="backup-section-title"
          style={{
            fontSize: '10px',
            fontWeight: 'bold',
            marginBottom: '8px',
            color: 'var(--text-dark)',
            letterSpacing: '1px',
          }}
        >
          BACKUP & RESTORE
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
          EXPORT YOUR STATE OR RESTORE FROM BACKUP
        </div>

        <div
          className="settings-shell__button-row"
          style={{
            marginBottom: '8px',
          }}
        >
          <button
            className="settings-shell__button"
            onClick={onExportBackup}
            disabled={backupProcessing}
            style={{
              flex: '1 1 140px',
              fontSize: '9px',
              opacity: backupProcessing ? 0.5 : 1,
              cursor: backupProcessing ? 'not-allowed' : 'pointer',
            }}
          >
            {backupProcessing ? 'EXPORTING...' : 'EXPORT BACKUP'}
          </button>

          <button
            className="settings-shell__button"
            onClick={onImportBackup}
            disabled={backupProcessing}
            style={{
              flex: '1 1 140px',
              fontSize: '9px',
              opacity: backupProcessing ? 0.5 : 1,
              cursor: backupProcessing ? 'not-allowed' : 'pointer',
            }}
          >
            {backupProcessing ? 'IMPORTING...' : 'IMPORT BACKUP'}
          </button>
        </div>
        {backupStatus && (
          <div className="settings-shell__status">
            {backupStatus}
          </div>
        )}
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
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
          <span style={{ fontSize: '9px', color: 'var(--text-dark)' }}>
            {nfcBackupEnabled ? 'ACTIVE' : 'OFF'}
            {nfcBackupEnabled && nfcCapsuleCount > 0 && ` — Capsule #${nfcLastIndex}`}
          </span>
        </div>
        <button
          className="settings-shell__button"
          onClick={() => onNavigate?.('nfc_recovery')}
          style={{ fontSize: '9px', width: '100%' }}
        >
          MANAGE
        </button>
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
              onClick={() => onNavigate?.('dev_dlv')}
            >
              DLV TOOLS
            </button>

            <button
              type="button"
              className="settings-shell__button"
              style={{ fontSize: '9px' }}
              onClick={() => onNavigate?.('dev_cdbrw')}
            >
              C-DBRW TOOLS
            </button>

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
              onClick={() => onNavigate?.('dev_detfi_launch')}
            >
              DETFI LAUNCH
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
