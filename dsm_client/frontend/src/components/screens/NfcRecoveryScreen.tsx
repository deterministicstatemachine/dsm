// SPDX-License-Identifier: Apache-2.0

import React, { useCallback, useEffect, useRef, useState, memo } from 'react';
import * as EventBridge from '../../dsm/EventBridge';
import {
  createCapsule,
  disableNfcBackup,
  enableNfcBackup,
  generateMnemonic,
  getCapsulePreview,
  getNfcBackupStatus,
  writeToNfcRing,
  type CapsulePreview,
  type NfcBackupStatus,
} from '../../services/recovery/nfcRecoveryService';
import { getNfcBackupUiModel } from '../../services/recovery/nfcBackupUi';
import './NfcRecoveryScreen.css';

type SetupMode = 'idle' | 'choose' | 'generate' | 'enable' | 'refresh' | 'writing';

interface NfcRecoveryScreenProps {
  onNavigate?: (screen: string) => void;
}

function shortenValue(value: string, size = 20): string {
  if (!value) return '--';
  if (value === 'UNKNOWN') return value;
  return value.length > size ? `${value.slice(0, size)}...` : value;
}

const emptyStatus: NfcBackupStatus = {
  enabled: false,
  configured: false,
  pendingCapsule: false,
  capsuleCount: 0,
  lastCapsuleIndex: 0,
  autoWriteEnabled: false,
};

const NfcRecoveryScreen: React.FC<NfcRecoveryScreenProps> = ({ onNavigate }) => {
  const [status, setStatus] = useState<NfcBackupStatus>(emptyStatus);
  const [preview, setPreview] = useState<CapsulePreview>(null);
  const [setupMode, setSetupMode] = useState<SetupMode>('idle');
  const [generatedMnemonic, setGeneratedMnemonic] = useState('');
  const [mnemonicInput, setMnemonicInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [statusMsg, setStatusMsg] = useState('');
  const mountedRef = useRef(true);

  const formatError = useCallback((error: unknown): string => {
    if (error instanceof Error && error.message) return error.message;
    return String(error);
  }, []);

  const refresh = useCallback(async () => {
    try {
      const [nextStatus, nextPreview] = await Promise.all([
        getNfcBackupStatus(),
        getCapsulePreview(),
      ]);
      if (!mountedRef.current) return;
      setStatus(nextStatus);
      setPreview(nextPreview);
    } catch (error: unknown) {
      if (!mountedRef.current) return;
      setStatusMsg(`Recovery backup status failed: ${formatError(error)}`);
    }
  }, [formatError]);

  useEffect(() => {
    mountedRef.current = true;
    try {
      EventBridge.initializeEventBridge();
    } catch {
      /* safe */
    }

    const unsubWritten = EventBridge.on('nfc.backup_written', () => {
      void refresh();
      if (!mountedRef.current) return;
      setStatusMsg(
        'Ring write committed. The ring now holds that capsule. This phone will arm another one after the next accepted state change or manual rebuild.',
      );
      setSetupMode('idle');
      setMnemonicInput('');
    });

    void refresh();

    // Auto-refresh when screen becomes visible again
    const onVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        void refresh();
      }
    };
    document.addEventListener('visibilitychange', onVisibilityChange);

    return () => {
      mountedRef.current = false;
      document.removeEventListener('visibilitychange', onVisibilityChange);
      try {
        unsubWritten();
      } catch {
        /* safe */
      }
    };
  }, [refresh]);

  const submitMnemonic = useCallback(
    async (mode: 'enable' | 'refresh', mnemonic: string) => {
      const trimmed = mnemonic.trim();
      if (trimmed.split(/\s+/).length < 12) {
        setStatusMsg('Enter a valid mnemonic first.');
        return;
      }

      setBusy(true);
      try {
        if (mode === 'enable') {
          await enableNfcBackup(trimmed);
          setStatusMsg(
            'Backup enabled. A capsule is now armed. Write it to the ring now, or let the next accepted state change re-arm a newer one later.',
          );
        } else {
          await createCapsule(trimmed);
          setStatusMsg('Fresh capsule armed. Press write, then hold the ring to the phone until it vibrates.');
        }
        setGeneratedMnemonic('');
        setMnemonicInput('');
        setSetupMode('idle');
        await refresh();
      } catch (error: unknown) {
        setStatusMsg(`Recovery backup failed: ${formatError(error)}`);
      } finally {
        setBusy(false);
      }
    },
    [formatError, refresh],
  );

  const onToggleBackup = useCallback(async () => {
    if (busy) return;

    if (status.enabled) {
      setBusy(true);
      try {
        await disableNfcBackup();
        await refresh();
        setSetupMode('idle');
        setStatusMsg('Backup disabled. The last written capsule stays available until you arm a newer one.');
      } catch (error: unknown) {
        setStatusMsg(`Disable failed: ${formatError(error)}`);
      } finally {
        setBusy(false);
      }
      return;
    }

    setSetupMode(status.configured ? 'enable' : 'choose');
    setStatusMsg('');
  }, [busy, formatError, refresh, status.configured, status.enabled]);

  const onGenerateMnemonic = useCallback(async () => {
    if (busy) return;
    setBusy(true);
    try {
      const words = await generateMnemonic();
      setGeneratedMnemonic(words);
      setSetupMode('generate');
    } catch (error: unknown) {
      setStatusMsg(`Mnemonic generation failed: ${formatError(error)}`);
    } finally {
      setBusy(false);
    }
  }, [busy, formatError]);

  const onWriteNow = useCallback(async () => {
    if (busy) return;
    if (!status.enabled) {
      setStatusMsg('Enable NFC backup first.');
      return;
    }
    if (!status.pendingCapsule) {
      // No armed capsule — show mnemonic input to rebuild first
      setSetupMode('refresh');
      setStatusMsg('No capsule armed. Enter your mnemonic to rebuild and write.');
      return;
    }

    // Transition to "ready to write" screen immediately
    setSetupMode('writing');
    setStatusMsg('');
    setBusy(true);
    try {
      await writeToNfcRing();
      // Stay in writing mode — the nfc.backup_written event handler
      // will set setupMode back to 'idle' once the write commits.
      setStatusMsg('Waiting for ring contact. Hold the ring to the phone until it vibrates.');
    } catch (error: unknown) {
      setSetupMode('idle');
      await refresh();
      setStatusMsg(`Write failed: ${formatError(error)}`);
    } finally {
      setBusy(false);
    }
  }, [busy, formatError, refresh, status.enabled, status.pendingCapsule]);

  const latestCapsuleLabel = status.capsuleCount > 0
    ? `#${status.lastCapsuleIndex}`
    : '--';
  const nfcUi = getNfcBackupUiModel(status);
  const writeButtonLabel = !status.enabled
    ? 'WRITE LATEST CAPSULE'
    : status.pendingCapsule
      ? 'WRITE TO RING'
      : 'REBUILD & WRITE';

  return (
    <div className="nfc-shell" role="main">
      <div className="nfc-header">
        <h2>NFC RING BACKUP</h2>
      </div>

      <div className="nfc-stage">
        {/* Status dashboard card */}
        <div className="nfc-card">
          <div className="nfc-stat-grid">
            <div className="nfc-stat-cell">
              <div className="nfc-stat-val-sm">
                {nfcUi.backupLabel}
              </div>
              <div className="nfc-stat-label">Backup</div>
            </div>
            <div className="nfc-stat-cell">
              <div className="nfc-stat-val-sm">{nfcUi.writeStateLabel}</div>
              <div className="nfc-stat-label">Write State</div>
            </div>
            <div className="nfc-stat-cell">
              <div className="nfc-stat-val">{latestCapsuleLabel}</div>
              <div className="nfc-stat-label">Latest Capsule</div>
            </div>
            <div className="nfc-stat-cell">
              <div className="nfc-stat-val-sm">{nfcUi.nextActionLabel}</div>
              <div className="nfc-stat-label">Next Step</div>
            </div>
          </div>

          <div className="nfc-note">
            {nfcUi.detailSummary}
          </div>
        </div>

        {/* First-time setup: choose flow */}
        {setupMode === 'choose' && (
          <div className="nfc-card">
            <div className="nfc-info-row">
              <span className="nfc-info-label">FIRST-TIME SETUP</span>
            </div>
            <div className="nfc-actions">
              <button className="nfc-btn" onClick={onGenerateMnemonic} disabled={busy}>
                GENERATE NEW MNEMONIC
              </button>
            </div>
            <div className="nfc-actions">
              <button
                className="nfc-btn"
                onClick={() => setSetupMode('enable')}
              >
                ENTER EXISTING MNEMONIC
              </button>
            </div>
          </div>
        )}

        {/* Generated mnemonic display */}
        {setupMode === 'generate' && generatedMnemonic && (
          <div className="nfc-card">
            <div className="nfc-info-row">
              <span className="nfc-info-label">
                WRITE THESE WORDS DOWN — REQUIRED TO REBUILD OR RECOVER
              </span>
            </div>
            <div style={{ padding: '0 10px 8px' }}>
              <textarea
                className="nfc-input"
                value={generatedMnemonic}
                readOnly
                rows={4}
                style={{ marginTop: 8 }}
              />
            </div>
            <div className="nfc-actions">
              <button
                className="nfc-btn"
                onClick={() => { void navigator.clipboard.writeText(generatedMnemonic); setStatusMsg('Copied to clipboard.'); }}
              >
                COPY TO CLIPBOARD
              </button>
            </div>
            <div className="nfc-actions">
              <button
                className="nfc-btn"
                onClick={() => void submitMnemonic('enable', generatedMnemonic)}
                disabled={busy}
              >
                {busy ? 'ARMING...' : 'I SAVED IT — ARM BACKUP'}
              </button>
            </div>
          </div>
        )}

        {/* Mnemonic input (enable or refresh) */}
        {(setupMode === 'enable' || setupMode === 'refresh') && (
          <div className="nfc-card">
            <div className="nfc-info-row">
              <span className="nfc-info-label">
                {setupMode === 'refresh' ? 'REBUILD THE LATEST CAPSULE' : 'ENTER YOUR MNEMONIC'}
              </span>
            </div>
            <div style={{ padding: '0 10px 8px' }}>
              <textarea
                className="nfc-input"
                value={mnemonicInput}
                onChange={(e) => setMnemonicInput(e.target.value)}
                placeholder="word1 word2 word3 ..."
                rows={4}
                style={{ marginTop: 8 }}
              />
            </div>
            <div className="nfc-actions">
              <button
                className="nfc-btn"
                onClick={() => void submitMnemonic(setupMode === 'refresh' ? 'refresh' : 'enable', mnemonicInput)}
                disabled={busy || mnemonicInput.trim().split(/\s+/).length < 12}
              >
                {busy ? 'WORKING...' : setupMode === 'refresh' ? 'REBUILD CAPSULE' : 'ENABLE BACKUP'}
              </button>
            </div>
            <div className="nfc-note">
              Rebuilding arms a fresh capsule in Rust. It does not write to the ring until you press
              the write action.
            </div>
          </div>
        )}

        {/* Writing mode — "ready to write" prompt */}
        {setupMode === 'writing' && (
          <div className="nfc-card">
            <div className="nfc-info-row">
              <span className="nfc-info-label" style={{ fontSize: '12px' }}>
                READY TO WRITE
              </span>
            </div>
            <div className="nfc-note" style={{ fontSize: '11px', fontWeight: 700, textAlign: 'center', padding: '16px 10px' }}>
              HOLD THE RING TO THE BACK OF THE PHONE.
              <br />
              <br />
              A VIBRATION MEANS THE WRITE COMMITTED.
              <br />
              DO NOT MOVE THE RING UNTIL THEN.
            </div>
            <div className="nfc-actions">
              <button
                className="nfc-btn"
                onClick={() => { setSetupMode('idle'); setStatusMsg('Write cancelled.'); }}
              >
                CANCEL
              </button>
            </div>
          </div>
        )}

        {/* Main action buttons card — only when idle */}
        {setupMode === 'idle' && (
          <div className="nfc-card">
            <div className="nfc-actions">
              <button className="nfc-btn" onClick={onToggleBackup} disabled={busy}>
                {busy ? '...' : status.enabled ? 'DISABLE BACKUP' : status.configured ? 'RE-ENABLE' : 'SET UP'}
              </button>
            </div>
            {status.enabled && (
              <div className="nfc-actions">
                <button
                  className="nfc-btn"
                  onClick={onWriteNow}
                  disabled={busy || !status.enabled}
                >
                  {writeButtonLabel}
                </button>
              </div>
            )}
            <div className="nfc-actions">
              <button className="nfc-btn" onClick={() => onNavigate?.('recovery')}>
                INSPECT OR RECOVER RING
              </button>
            </div>
          </div>
        )}

        {/* Local capsule snapshot — only when idle */}
        {setupMode === 'idle' && preview && (
          <div className="nfc-card">
            <div className="nfc-info-row">
              <span className="nfc-info-label">LOCAL CAPSULE SNAPSHOT</span>
            </div>
            <div className="nfc-stat-grid">
              <div className="nfc-stat-cell">
                <div className="nfc-stat-val">#{preview.capsuleIndex}</div>
                <div className="nfc-stat-label">Capsule</div>
              </div>
              <div className="nfc-stat-cell">
                <div className="nfc-stat-val">{preview.counterpartyCount}</div>
                <div className="nfc-stat-label">Peers</div>
              </div>
            </div>
            <div className="nfc-info-row">
              <span className="nfc-info-label">SMT Root</span>
              <span className="nfc-info-val" style={{ fontFamily: 'monospace', fontSize: 11 }}>
                {shortenValue(preview.smtRoot || 'UNKNOWN')}
              </span>
            </div>
          </div>
        )}

        {/* How-it-works card — only when idle */}
        {setupMode === 'idle' && (
          <div className="nfc-card">
            <div className="nfc-info-row">
              <span className="nfc-info-label">HOW IT WORKS</span>
            </div>
            <div className="nfc-note">
              1. Enter or confirm your recovery mnemonic. 2. Arm a capsule. 3. Press write and hold
              the ring to the phone. A vibration means the write committed. After a successful write,
              the ring keeps that capsule; this phone re-arms only after the next accepted state
              change or a manual rebuild.
            </div>
          </div>
        )}

        {/* Status message */}
        {statusMsg && (
          <div className="nfc-card">
            <div className="nfc-note nfc-note--strong">
              {statusMsg}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default memo(NfcRecoveryScreen);
