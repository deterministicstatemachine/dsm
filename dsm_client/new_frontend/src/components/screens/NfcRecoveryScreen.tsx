/* eslint-disable @typescript-eslint/no-explicit-any */
// src/components/screens/NfcRecoveryScreen.tsx
// SPDX-License-Identifier: Apache-2.0
// Dedicated NFC Ring Backup management screen.
// Extracted from SettingsMainScreen to give recovery its own dashboard.

import React, { useCallback, useEffect, useMemo, useState, memo } from 'react';
import * as EventBridge from '../../dsm/EventBridge';
import {
  capsuleBytesToBase32,
  capsulePreviewFromBase32,
  enableNfcBackup,
  disableNfcBackup,
  getNfcBackupStatus,
  generateMnemonic,
  createCapsule,
  writeToNfcRing,
  getCapsulePreview,
  getSyncStatus,
} from '../../services/recovery/nfcRecoveryService';
import './StorageScreen.css';

interface NfcRecoveryScreenProps {
  onNavigate?: (screen: string) => void;
}

const NfcRecoveryScreen: React.FC<NfcRecoveryScreenProps> = ({ onNavigate }) => {
  // --- NFC backup status ---
  const [nfcBackupEnabled, setNfcBackupEnabled] = useState(false);
  const [nfcBackupConfigured, setNfcBackupConfigured] = useState(false);
  const [nfcCapsuleCount, setNfcCapsuleCount] = useState(0);
  const [nfcLastIndex, setNfcLastIndex] = useState(0);

  // --- Setup flow ---
  const [setupMode, setSetupMode] = useState<
    'idle' | 'choose' | 'generate' | 'enter' | 'write' | 'enter-for-write'
  >('idle');
  const [generatedWords, setGeneratedWords] = useState('');
  const [mnemonicKey, setMnemonicKey] = useState('');
  const [busy, setBusy] = useState(false);
  const [statusMsg, setStatusMsg] = useState('');

  // --- Ring contents preview ---
  const [capsulePreview, setCapsulePreview] = useState<{
    capsuleIndex: number;
    smtRoot: string;
    createdTick: number;
    counterpartyCount: number;
  } | null>(null);

  // --- NFC capsule import (from ring read) ---
  const [nfcCapsuleBase32, setNfcCapsuleBase32] = useState<string | null>(null);

  // --- Sync status (during active recovery) ---
  const [syncStatus, setSyncStatus] = useState<{
    synced: number;
    total: number;
    pending: string[];
  } | null>(null);

  // Subscribe to NFC events
  useEffect(() => {
    try {
      EventBridge.initializeEventBridge();
    } catch {
      /* safe */
    }

    const unsubCapsule = EventBridge.on('nfc-recovery-capsule', (bytes) => {
      const b32 = capsuleBytesToBase32(bytes as Uint8Array);
      setNfcCapsuleBase32(b32);
      setStatusMsg(
        `Imported NFC capsule (${(bytes as Uint8Array).length} bytes).`,
      );
    });

    const unsubWritten = EventBridge.on('nfc.backup_written', () => {
      void refreshStatus();
      setStatusMsg('Backup written to ring!');
      setSetupMode('idle');
      setMnemonicKey('');
    });

    // Load status on mount
    void refreshStatus();
    void refreshCapsulePreview();
    void refreshSyncStatus();

    return () => {
      try {
        unsubCapsule();
      } catch {
        /* safe */
      }
      try {
        unsubWritten();
      } catch {
        /* safe */
      }
    };
  }, []);

  const nfcCapsulePreviewText = useMemo(() => {
    if (!nfcCapsuleBase32) return '';
    return capsulePreviewFromBase32(nfcCapsuleBase32);
  }, [nfcCapsuleBase32]);

  async function refreshStatus() {
    try {
      const s = await getNfcBackupStatus();
      setNfcBackupEnabled(s.enabled);
      setNfcBackupConfigured(s.configured);
      setNfcCapsuleCount(s.capsuleCount);
      setNfcLastIndex(s.lastCapsuleIndex);
    } catch {
      /* tolerate — tables may not exist yet */
    }
  }

  async function refreshCapsulePreview() {
    try {
      const preview = await getCapsulePreview();
      if (preview) setCapsulePreview(preview);
    } catch {
      /* tolerate */
    }
  }

  async function refreshSyncStatus() {
    try {
      const status = await getSyncStatus();
      if (status.total > 0) setSyncStatus(status);
    } catch {
      /* tolerate */
    }
  }

  // --- Toggle handlers ---
  const onToggle = useCallback(async () => {
    if (busy) return;
    setBusy(true);
    try {
      if (nfcBackupEnabled) {
        await disableNfcBackup();
        setNfcBackupEnabled(false);
        setSetupMode('idle');
        setStatusMsg('NFC backup disabled.');
      } else if (nfcBackupConfigured) {
        setSetupMode('enter');
      } else {
        setSetupMode('choose');
      }
    } catch (e: any) {
      setStatusMsg(`Toggle failed: ${String(e?.message ?? e)}`);
    } finally {
      setBusy(false);
    }
  }, [busy, nfcBackupEnabled, nfcBackupConfigured]);

  const onGenerateMnemonic = useCallback(async () => {
    setBusy(true);
    try {
      const words = await generateMnemonic();
      setGeneratedWords(words);
      setSetupMode('generate');
    } catch (e: any) {
      setStatusMsg(`Generation failed: ${String(e?.message ?? e)}`);
    } finally {
      setBusy(false);
    }
  }, []);

  const onEnableFinal = useCallback(
    async (mnemonic: string) => {
      setBusy(true);
      try {
        await enableNfcBackup(mnemonic.trim());
        await createCapsule(mnemonic.trim());
        setNfcBackupEnabled(true);
        setNfcBackupConfigured(true);
        setSetupMode('write');
        setMnemonicKey(mnemonic);
        setGeneratedWords('');
        await refreshStatus();
        await refreshCapsulePreview();
        setStatusMsg('Backup enabled. Tap ring to write.');
      } catch (e: any) {
        setStatusMsg(`Enable failed: ${String(e?.message ?? e)}`);
      } finally {
        setBusy(false);
      }
    },
    [],
  );

  const onWriteToRing = useCallback(async () => {
    setBusy(true);
    try {
      await writeToNfcRing();
      setStatusMsg('Hold ring near phone. Writing backup...');
    } catch (e: any) {
      setStatusMsg(`Write failed: ${String(e?.message ?? e)}`);
    } finally {
      setBusy(false);
    }
  }, []);

  const onManualWrite = useCallback(async () => {
    setBusy(true);
    try {
      await createCapsule(mnemonicKey.trim());
      await writeToNfcRing();
      await refreshStatus();
      await refreshCapsulePreview();
      setStatusMsg('Hold ring near phone. Writing backup...');
    } catch (e: any) {
      setStatusMsg(`Write failed: ${String(e?.message ?? e)}`);
    } finally {
      setBusy(false);
    }
  }, [mnemonicKey]);

  return (
    <main className="settings-shell settings-shell--dev" role="main">
      <h2 style={{ textAlign: 'center', marginBottom: 12 }}>
        NFC RING BACKUP
      </h2>

      {/* === STATUS CARD === */}
      <div className="snd-card">
        <div className="snd-stat-grid-2">
          <div className="snd-stat-cell">
            <div className="snd-stat-val">
              {nfcBackupEnabled
                ? 'ACTIVE'
                : nfcBackupConfigured
                  ? 'OFF'
                  : 'NOT SET UP'}
            </div>
            <div className="snd-stat-label">Status</div>
          </div>
          <div className="snd-stat-cell">
            <div className="snd-stat-val">
              {nfcCapsuleCount > 0 ? `#${nfcLastIndex}` : '--'}
            </div>
            <div className="snd-stat-label">Latest Capsule</div>
          </div>
        </div>

        {/* Toggle */}
        <div className="snd-actions">
          <button
            className="snd-btn"
            onClick={onToggle}
            disabled={busy}
          >
            {busy
              ? '...'
              : nfcBackupEnabled
                ? 'DISABLE'
                : nfcBackupConfigured
                  ? 'RE-ENABLE'
                  : 'SET UP'}
          </button>
        </div>
      </div>

      {/* === RING CONTENTS (when capsule exists) === */}
      {capsulePreview && nfcBackupEnabled && (
        <div className="snd-card">
          <div className="snd-info-row">
            <span className="snd-info-label">RING CONTENTS</span>
          </div>
          <div className="snd-stat-grid-2">
            <div className="snd-stat-cell">
              <div className="snd-stat-val">
                #{capsulePreview.capsuleIndex}
              </div>
              <div className="snd-stat-label">Capsule</div>
            </div>
            <div className="snd-stat-cell">
              <div className="snd-stat-val">
                {capsulePreview.counterpartyCount}
              </div>
              <div className="snd-stat-label">Contacts</div>
            </div>
          </div>
          <div className="snd-info-row">
            <span className="snd-info-label">SMT Root</span>
            <span
              className="snd-info-val"
              style={{ fontFamily: 'monospace', fontSize: 11 }}
            >
              {capsulePreview.smtRoot.slice(0, 16)}...
            </span>
          </div>
          <div className="snd-info-row">
            <span className="snd-info-label">Tick</span>
            <span className="snd-info-val">
              {capsulePreview.createdTick}
            </span>
          </div>
          {nfcCapsuleCount > 0 && (
            <div className="snd-info-note">
              {nfcCapsuleCount} capsule(s) stored locally. Auto-updated on
              every state transition.
            </div>
          )}
        </div>
      )}

      {/* === SETUP FLOW === */}

      {/* Choose: generate or enter mnemonic */}
      {setupMode === 'choose' && (
        <div className="snd-card">
          <div className="snd-info-row">
            <span className="snd-info-label">FIRST-TIME SETUP</span>
          </div>
          <div className="snd-actions">
            <button
              className="snd-btn"
              onClick={onGenerateMnemonic}
              disabled={busy}
            >
              GENERATE NEW MNEMONIC
            </button>
            <button
              className="snd-btn"
              onClick={() => setSetupMode('enter')}
              style={{ marginTop: 4 }}
            >
              ENTER EXISTING MNEMONIC
            </button>
          </div>
        </div>
      )}

      {/* Generated mnemonic display */}
      {setupMode === 'generate' && generatedWords && (
        <div className="snd-card">
          <div className="snd-info-row">
            <span className="snd-info-label">
              WRITE THESE 24 WORDS DOWN. THIS IS YOUR RECOVERY KEY.
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
              userSelect: 'text',
              WebkitUserSelect: 'text',
            }}
          >
            {generatedWords.split(' ').map((w, i) => (
              <span
                key={i}
                style={{
                  display: 'inline-block',
                  width: '48%',
                  marginRight: '2%',
                }}
              >
                {i + 1}. {w}
              </span>
            ))}
          </div>
          <div className="snd-actions">
            <button
              className="snd-btn"
              onClick={() => {
                try {
                  navigator.clipboard.writeText(generatedWords);
                  setStatusMsg('Copied to clipboard');
                } catch {
                  try {
                    const el = document.createElement('textarea');
                    el.value = generatedWords;
                    el.style.position = 'fixed';
                    el.style.opacity = '0';
                    document.body.appendChild(el);
                    el.select();
                    document.execCommand('copy');
                    document.body.removeChild(el);
                    setStatusMsg('Copied to clipboard');
                  } catch {
                    setStatusMsg('Copy failed — select words manually');
                  }
                }
              }}
            >
              COPY WORDS
            </button>
            <button
              className="snd-btn"
              onClick={() => onEnableFinal(generatedWords)}
              disabled={busy}
              style={{ marginTop: 4 }}
            >
              {busy ? 'ENABLING...' : 'I SAVED THEM — ENABLE'}
            </button>
          </div>
        </div>
      )}

      {/* Enter existing mnemonic */}
      {setupMode === 'enter' && (
        <div className="snd-card">
          <div className="snd-info-row">
            <span className="snd-info-label">ENTER MNEMONIC</span>
          </div>
          <input
            type="text"
            placeholder="Enter 24-word mnemonic"
            value={mnemonicKey}
            onChange={(e) => setMnemonicKey(e.target.value)}
            style={{
              fontSize: '9px',
              width: '100%',
              boxSizing: 'border-box' as const,
              padding: '10px 12px',
              fontFamily: "'Martian Mono', monospace",
              letterSpacing: '1px',
              backgroundColor: 'var(--gb-bg, var(--bg))',
              color: 'var(--gb-fg, var(--text-dark))',
              border: '2px solid var(--gb-border, var(--border))',
              borderRadius: 4,
              outline: 'none',
              marginTop: 8,
            }}
          />
          <div className="snd-actions">
            <button
              className="snd-btn"
              onClick={() => onEnableFinal(mnemonicKey)}
              disabled={
                busy || mnemonicKey.trim().split(/\s+/).length < 12
              }
            >
              {busy ? 'ENABLING...' : 'ENABLE BACKUP'}
            </button>
          </div>
        </div>
      )}

      {/* Write to ring step */}
      {setupMode === 'write' && (
        <div className="snd-card">
          <div className="snd-info-row">
            <span className="snd-info-label">
              TAP YOUR NFC RING TO WRITE BACKUP
            </span>
          </div>
          <div
            style={{
              textAlign: 'center',
              padding: 24,
              fontSize: 24,
              color: 'var(--gb-green, #0f380f)',
            }}
          >
            {busy ? 'WRITING...' : '[ TAP RING ]'}
          </div>
          <div className="snd-info-note">
            Hold the ring near the NFC antenna on the back of your phone.
          </div>
          <div className="snd-actions">
            <button
              className="snd-btn"
              onClick={onWriteToRing}
              disabled={busy}
            >
              {busy ? 'LAUNCHING...' : 'WRITE NOW'}
            </button>
            <button
              className="snd-btn"
              onClick={() => {
                setSetupMode('idle');
                setMnemonicKey('');
                setStatusMsg('Setup complete (write skipped)');
              }}
              style={{ marginTop: 4 }}
            >
              SKIP (WRITE LATER)
            </button>
          </div>
        </div>
      )}

      {/* Manual write (when already enabled) */}
      {setupMode === 'enter-for-write' && (
        <div className="snd-card">
          <div className="snd-info-row">
            <span className="snd-info-label">
              ENTER MNEMONIC TO CREATE FRESH CAPSULE
            </span>
          </div>
          <input
            type="text"
            placeholder="24-word mnemonic"
            value={mnemonicKey}
            onChange={(e) => setMnemonicKey(e.target.value)}
            style={{
              width: '100%',
              padding: 6,
              fontSize: '9px',
              fontFamily: 'monospace',
              background: 'var(--gb-bg, var(--bg))',
              color: 'var(--gb-fg, var(--text-dark))',
              border: '2px solid var(--gb-border, var(--border))',
              borderRadius: 4,
              marginTop: 8,
            }}
          />
          <div className="snd-actions">
            <button
              className="snd-btn"
              onClick={onManualWrite}
              disabled={
                busy || mnemonicKey.trim().split(/\s+/).length < 12
              }
            >
              {busy ? 'LAUNCHING...' : 'WRITE TO RING'}
            </button>
            <button
              className="snd-btn"
              onClick={() => {
                setSetupMode('idle');
                setMnemonicKey('');
              }}
              style={{ marginTop: 4 }}
            >
              CANCEL
            </button>
          </div>
        </div>
      )}

      {/* Write button when enabled and idle */}
      {nfcBackupEnabled && setupMode === 'idle' && (
        <div className="snd-card">
          <div className="snd-actions">
            <button
              className="snd-btn"
              onClick={() => setSetupMode('enter-for-write')}
            >
              WRITE TO RING NOW
            </button>
          </div>
        </div>
      )}

      {/* === NFC CAPSULE IMPORT (from ring read event) === */}
      {nfcCapsuleBase32 && (
        <div className="snd-card">
          <div className="snd-info-row">
            <span className="snd-info-label">IMPORTED CAPSULE</span>
            <span
              className="snd-info-val"
              style={{ fontFamily: 'monospace', fontSize: 11 }}
            >
              {nfcCapsulePreviewText}
            </span>
          </div>
        </div>
      )}

      {/* === SYNC STATUS (during active recovery) === */}
      {syncStatus && syncStatus.total > 0 && (
        <div className="snd-card">
          <div className="snd-info-row">
            <span className="snd-info-label">TOMBSTONE SYNC</span>
          </div>
          <div className="snd-stat-grid-2">
            <div className="snd-stat-cell">
              <div className="snd-stat-val">
                {syncStatus.synced}/{syncStatus.total}
              </div>
              <div className="snd-stat-label">Contacts Synced</div>
            </div>
            <div className="snd-stat-cell">
              <div className="snd-stat-val">
                {syncStatus.total - syncStatus.synced}
              </div>
              <div className="snd-stat-label">Waiting</div>
            </div>
          </div>
          {syncStatus.synced < syncStatus.total && (
            <div className="snd-info-note">
              All counterparties must acknowledge the tombstone before
              recovery can complete.
            </div>
          )}
          {syncStatus.synced >= syncStatus.total && (
            <div className="snd-info-note">
              All contacts synced. Recovery can proceed.
            </div>
          )}
        </div>
      )}

      {/* === RECOVER FROM RING === */}
      <div className="snd-card">
        <div className="snd-actions">
          <button
            className="snd-btn"
            onClick={() => onNavigate?.('recovery')}
          >
            RECOVER FROM RING
          </button>
        </div>
      </div>

      {/* Status message */}
      {statusMsg && (
        <div className="settings-shell__status">{statusMsg}</div>
      )}
    </main>
  );
};

export default memo(NfcRecoveryScreen);
