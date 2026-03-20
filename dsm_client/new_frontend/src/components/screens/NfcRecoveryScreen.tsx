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
import './StorageScreen.css';

type SetupMode = 'idle' | 'choose' | 'generate' | 'enable' | 'refresh';

interface NfcRecoveryScreenProps {
  onNavigate?: (screen: string) => void;
}

const emptyStatus: NfcBackupStatus = {
  enabled: false,
  configured: false,
  capsuleCount: 0,
  lastCapsuleIndex: 0,
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
      setStatusMsg('Ring write committed. Vibration means the latest capsule is backed up.');
      setSetupMode('idle');
      setMnemonicInput('');
    });

    void refresh();

    return () => {
      mountedRef.current = false;
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
          setStatusMsg('Backup enabled. The latest capsule now stays armed for the ring.');
        } else {
          await createCapsule(trimmed);
          setStatusMsg('Fresh capsule queued. Touch the ring until the phone vibrates.');
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
    if (status.capsuleCount === 0) {
      setSetupMode('refresh');
      setStatusMsg('No latest capsule is armed right now. Rebuild one with your mnemonic.');
      return;
    }

    setBusy(true);
    try {
      await writeToNfcRing();
      setStatusMsg('Touch the ring to the phone. Vibration means the write committed.');
    } catch (error: unknown) {
      await refresh();
      setStatusMsg(`Write failed: ${formatError(error)}`);
    } finally {
      setBusy(false);
    }
  }, [busy, formatError, refresh, status.capsuleCount, status.enabled]);

  const latestCapsuleLabel = status.capsuleCount > 0
    ? `#${status.lastCapsuleIndex}`
    : '--';

  return (
    <main className="settings-shell settings-shell--dev" role="main">
      <h2 style={{ textAlign: 'center', marginBottom: 12 }}>NFC RING BACKUP</h2>

      <div className="snd-card">
        <div className="snd-stat-grid-2">
          <div className="snd-stat-cell">
            <div className="snd-stat-val">
              {status.enabled ? 'ARMED' : status.configured ? 'OFF' : 'NOT SET'}
            </div>
            <div className="snd-stat-label">Backup</div>
          </div>
          <div className="snd-stat-cell">
            <div className="snd-stat-val">{latestCapsuleLabel}</div>
            <div className="snd-stat-label">Latest Capsule</div>
          </div>
        </div>

        <div className="snd-info-note" style={{ marginTop: 12 }}>
          Every state change overwrites the armed capsule in place. It waits there for the ring.
          Vibration means the latest state committed to the tag.
        </div>

        <div className="snd-actions">
          <button className="snd-btn" onClick={onToggleBackup} disabled={busy}>
            {busy ? '...' : status.enabled ? 'DISABLE BACKUP' : status.configured ? 'RE-ENABLE' : 'SET UP'}
          </button>
          <button
            className="snd-btn"
            onClick={onWriteNow}
            disabled={busy || !status.enabled}
            style={{ marginTop: 4 }}
          >
            WRITE LATEST CAPSULE
          </button>
        </div>
      </div>

      {preview && (
        <div className="snd-card">
          <div className="snd-info-row">
            <span className="snd-info-label">LOCAL CAPSULE SNAPSHOT</span>
          </div>
          <div className="snd-stat-grid-2">
            <div className="snd-stat-cell">
              <div className="snd-stat-val">#{preview.capsuleIndex}</div>
              <div className="snd-stat-label">Capsule</div>
            </div>
            <div className="snd-stat-cell">
              <div className="snd-stat-val">{preview.counterpartyCount}</div>
              <div className="snd-stat-label">Peers</div>
            </div>
          </div>
          <div className="snd-info-row">
            <span className="snd-info-label">SMT Root</span>
            <span className="snd-info-val" style={{ fontFamily: 'monospace', fontSize: 11 }}>
              {preview.smtRoot || 'UNKNOWN'}
            </span>
          </div>
          <div className="snd-info-row">
            <span className="snd-info-label">Tick</span>
            <span className="snd-info-val">{preview.createdTick}</span>
          </div>
        </div>
      )}

      {setupMode === 'choose' && (
        <div className="snd-card">
          <div className="snd-info-row">
            <span className="snd-info-label">FIRST-TIME SETUP</span>
          </div>
          <div className="snd-actions">
            <button className="snd-btn" onClick={onGenerateMnemonic} disabled={busy}>
              GENERATE NEW MNEMONIC
            </button>
            <button
              className="snd-btn"
              onClick={() => setSetupMode('enable')}
              style={{ marginTop: 4 }}
            >
              ENTER EXISTING MNEMONIC
            </button>
          </div>
        </div>
      )}

      {setupMode === 'generate' && generatedMnemonic && (
        <div className="snd-card">
          <div className="snd-info-row">
            <span className="snd-info-label">
              WRITE THESE WORDS DOWN. THIS KEY KEEPS THE CAPSULE LAZY AND REWRITABLE.
            </span>
          </div>
          <div
            style={{
              fontFamily: 'monospace',
              fontSize: '10px',
              lineHeight: '1.6',
              padding: 8,
              border: '2px solid var(--gb-border, var(--border))',
              borderRadius: 4,
              background: 'var(--gb-bg, var(--bg))',
              color: 'var(--gb-fg, var(--text-dark))',
              wordBreak: 'break-word',
            }}
          >
            {generatedMnemonic}
          </div>
          <div className="snd-actions">
            <button
              className="snd-btn"
              onClick={() => void submitMnemonic('enable', generatedMnemonic)}
              disabled={busy}
            >
              {busy ? 'ARMING...' : 'I SAVED IT - ARM BACKUP'}
            </button>
          </div>
        </div>
      )}

      {(setupMode === 'enable' || setupMode === 'refresh') && (
        <div className="snd-card">
          <div className="snd-info-row">
            <span className="snd-info-label">
              {setupMode === 'refresh' ? 'REBUILD THE LATEST CAPSULE' : 'ENTER YOUR MNEMONIC'}
            </span>
          </div>
          <textarea
            value={mnemonicInput}
            onChange={(e) => setMnemonicInput(e.target.value)}
            placeholder="word1 word2 word3 ..."
            rows={4}
            style={{
              width: '100%',
              boxSizing: 'border-box',
              padding: '10px 12px',
              fontFamily: "'Martian Mono', monospace",
              fontSize: '9px',
              backgroundColor: 'var(--gb-bg, var(--bg))',
              color: 'var(--gb-fg, var(--text-dark))',
              border: '2px solid var(--gb-border, var(--border))',
              borderRadius: 4,
              resize: 'none',
              marginTop: 8,
            }}
          />
          <div className="snd-actions">
            <button
              className="snd-btn"
              onClick={() => void submitMnemonic(setupMode === 'refresh' ? 'refresh' : 'enable', mnemonicInput)}
              disabled={busy || mnemonicInput.trim().split(/\s+/).length < 12}
            >
              {busy ? 'WORKING...' : setupMode === 'refresh' ? 'REBUILD CAPSULE' : 'ENABLE BACKUP'}
            </button>
          </div>
        </div>
      )}

      <div className="snd-card">
        <div className="snd-actions">
          <button className="snd-btn" onClick={() => onNavigate?.('recovery')}>
            READ RING ON THIS DEVICE
          </button>
        </div>
      </div>

      {statusMsg && (
        <div className="settings-shell__status">{statusMsg}</div>
      )}
    </main>
  );
};

export default memo(NfcRecoveryScreen);
