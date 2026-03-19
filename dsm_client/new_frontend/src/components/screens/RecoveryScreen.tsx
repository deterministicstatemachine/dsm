// SPDX-License-Identifier: Apache-2.0
// RecoveryScreen — GameBoy-themed NFC ring recovery wizard.
// States: MNEMONIC_ENTRY → TAP_RING → PREVIEW → TOMBSTONE → SUCCESSION → RESUMING → COMPLETE

import React, { useCallback, useEffect, useState } from 'react';
import { useDpadNav } from '../../hooks/useDpadNav';
import { useUX } from '../../contexts/UXContext';
import * as EventBridge from '../../dsm/EventBridge';
import {
  createTombstone,
  createSuccession,
  resumeRecovery,
  getSyncStatus,
} from '../../services/recovery/nfcRecoveryService';
import { decryptCapsuleFromBase32, capsuleBytesToBase32 } from '../../services/recovery/nfcRecoveryService';
import './StorageScreen.css';

type WizardState =
  | 'MNEMONIC_ENTRY'
  | 'TAP_RING'
  | 'PREVIEW'
  | 'TOMBSTONE'
  | 'SUCCESSION'
  | 'RESUMING'
  | 'COMPLETE';

export default function RecoveryScreen() {
  const { notifyToast } = useUX();

  const [wizardState, setWizardState] = useState<WizardState>('MNEMONIC_ENTRY');
  const [mnemonic, setMnemonic] = useState('');
  const [busy, setBusy] = useState(false);
  const [statusMsg, setStatusMsg] = useState('');
  const [errorMsg, setErrorMsg] = useState('');

  // Preview data from decrypted capsule
  const [previewData, setPreviewData] = useState<{
    smtRoot: string;
    counterpartyCount: number;
    capsuleIndex: number;
    rollupHash: string;
  } | null>(null);

  // Sync progress for RESUMING state
  const [syncProgress, setSyncProgress] = useState<{ synced: number; total: number; pending: string[] }>({
    synced: 0,
    total: 0,
    pending: [],
  });

  // Listen for NFC capsule read events
  useEffect(() => {
    try { EventBridge.initializeEventBridge(); } catch { /* safe */ }

    const unsub = EventBridge.on('nfc-recovery-capsule', (bytes) => {
      if (wizardState !== 'TAP_RING') return;
      const b32 = capsuleBytesToBase32(bytes as Uint8Array);
      setStatusMsg(`Capsule read (${(bytes as Uint8Array).length} bytes). Decrypting...`);
      handleDecrypt(b32);
    });

    return () => { try { unsub(); } catch { /* safe */ } };
  }, [wizardState, mnemonic, handleDecrypt]);

  // Poll sync status while in RESUMING state
  useEffect(() => {
    if (wizardState !== 'RESUMING') return;
    let cancelled = false;

    const poll = async () => {
      while (!cancelled) {
        try {
          const status = await getSyncStatus();
          if (!cancelled) {
            setSyncProgress(status);
            if (status.synced >= status.total && status.total > 0) {
              setWizardState('COMPLETE');
              return;
            }
          }
        } catch { /* retry */ }
        // Wait ~5 seconds between polls using a promise (not setTimeout for ordering)
        await new Promise<void>((r) => { const id = setTimeout(r, 5000); if (cancelled) clearTimeout(id); });
      }
    };

    poll();
    return () => { cancelled = true; };
  }, [wizardState]);

  const handleDecrypt = useCallback(async (capsuleBase32: string) => {
    try {
      setBusy(true);
      setErrorMsg('');
      const result = await decryptCapsuleFromBase32({
        capsuleBase32,
        mnemonic: mnemonic.trim(),
      });
      setPreviewData({
        smtRoot: result?.smtRoot || 'unknown',
        counterpartyCount: result?.counterpartyCount ?? 0,
        capsuleIndex: result?.capsuleIndex ?? 0,
        rollupHash: result?.rollupHash || 'unknown',
      });
      setWizardState('PREVIEW');
      setStatusMsg('Capsule decrypted. Review and confirm.');
    } catch (e) {
      setErrorMsg(`Decrypt failed: ${e instanceof Error ? e.message : String(e)}`);
      notifyToast('error', 'Capsule decryption failed');
    } finally {
      setBusy(false);
    }
  }, [mnemonic, notifyToast]);

  const handleConfirmRecovery = useCallback(async () => {
    try {
      setBusy(true);
      setErrorMsg('');

      // Step 1: Tombstone old device
      setWizardState('TOMBSTONE');
      setStatusMsg('Creating tombstone receipt...');
      await createTombstone(mnemonic.trim());

      // Step 2: Succession — bind new device
      setWizardState('SUCCESSION');
      setStatusMsg('Creating succession receipt...');
      await createSuccession(mnemonic.trim());

      // Step 3: Resume — gated on full sync
      setWizardState('RESUMING');
      setStatusMsg('Waiting for all contacts to acknowledge tombstone...');
      try {
        await resumeRecovery(mnemonic.trim());
        setWizardState('COMPLETE');
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        if (msg.includes('pending') || msg.includes('synced')) {
          // Expected — sync gate not yet met, stay in RESUMING
          setStatusMsg(msg);
        } else {
          throw e;
        }
      }
    } catch (e) {
      setErrorMsg(`Recovery failed: ${e instanceof Error ? e.message : String(e)}`);
      notifyToast('error', 'Recovery failed');
      setWizardState('MNEMONIC_ENTRY');
    } finally {
      setBusy(false);
    }
  }, [mnemonic, notifyToast]);

  const handleMnemonicSubmit = useCallback(() => {
    const words = mnemonic.trim().split(/\s+/);
    if (words.length < 12) {
      setErrorMsg('Mnemonic must be at least 12 words');
      return;
    }
    setErrorMsg('');
    setWizardState('TAP_RING');
    setStatusMsg('Tap your NFC ring to read the backup capsule.');
  }, [mnemonic]);

  // D-pad navigation for action buttons
  const actionCount = wizardState === 'MNEMONIC_ENTRY' ? 1 : wizardState === 'PREVIEW' ? 2 : 0;
  const { focusedIndex } = useDpadNav({
    itemCount: actionCount,
    onSelect: (idx) => {
      if (wizardState === 'MNEMONIC_ENTRY' && idx === 0) handleMnemonicSubmit();
      if (wizardState === 'PREVIEW' && idx === 0) handleConfirmRecovery();
    },
  });

  return (
    <main className="settings-shell settings-shell--dev" role="main">
      <h2 style={{ textAlign: 'center', marginBottom: 12 }}>RECOVER FROM RING</h2>

      {/* === MNEMONIC ENTRY === */}
      {wizardState === 'MNEMONIC_ENTRY' && (
        <div className="snd-card">
          <div className="snd-info-row">
            <span className="snd-info-label">Enter your 24-word recovery mnemonic</span>
          </div>
          <textarea
            value={mnemonic}
            onChange={(e) => setMnemonic(e.target.value)}
            placeholder="word1 word2 word3 ..."
            rows={4}
            style={{
              width: '100%',
              fontFamily: 'monospace',
              fontSize: 13,
              padding: 8,
              marginTop: 8,
              background: 'var(--gb-bg)',
              color: 'var(--gb-fg)',
              border: '2px solid var(--gb-border)',
              borderRadius: 4,
              resize: 'none',
            }}
            disabled={busy}
          />
          <div className="snd-actions">
            <button
              className={`snd-btn${focusedIndex === 0 ? ' focused' : ''}`}
              onClick={handleMnemonicSubmit}
              disabled={busy || mnemonic.trim().split(/\s+/).length < 12}
            >
              NEXT: TAP RING
            </button>
          </div>
        </div>
      )}

      {/* === TAP RING === */}
      {wizardState === 'TAP_RING' && (
        <div className="snd-card">
          <div className="snd-info-row">
            <span className="snd-info-label">Tap your NFC ring to the phone</span>
          </div>
          <div style={{ textAlign: 'center', padding: 24, fontSize: 32 }}>
            {busy ? 'DECRYPTING...' : 'WAITING FOR RING...'}
          </div>
          <div className="snd-info-note">
            Hold the ring near the NFC antenna on the back of your phone.
          </div>
        </div>
      )}

      {/* === PREVIEW === */}
      {wizardState === 'PREVIEW' && previewData && (
        <div className="snd-card">
          <div className="snd-stat-grid-2">
            <div className="snd-stat-cell">
              <div className="snd-stat-val">{previewData.counterpartyCount}</div>
              <div className="snd-stat-label">Contacts</div>
            </div>
            <div className="snd-stat-cell">
              <div className="snd-stat-val">#{previewData.capsuleIndex}</div>
              <div className="snd-stat-label">Capsule</div>
            </div>
          </div>
          <div className="snd-info-row">
            <span className="snd-info-label">SMT Root</span>
            <span className="snd-info-val" style={{ fontFamily: 'monospace', fontSize: 11 }}>
              {previewData.smtRoot.slice(0, 16)}...
            </span>
          </div>
          <div className="snd-info-row">
            <span className="snd-info-label">Rollup</span>
            <span className="snd-info-val" style={{ fontFamily: 'monospace', fontSize: 11 }}>
              {previewData.rollupHash.slice(0, 16)}...
            </span>
          </div>
          <div className="snd-actions">
            <button
              className={`snd-btn${focusedIndex === 0 ? ' focused' : ''}`}
              onClick={handleConfirmRecovery}
              disabled={busy}
            >
              {busy ? 'RECOVERING...' : 'CONFIRM RECOVERY'}
            </button>
          </div>
        </div>
      )}

      {/* === TOMBSTONE === */}
      {wizardState === 'TOMBSTONE' && (
        <div className="snd-card">
          <div style={{ textAlign: 'center', padding: 24 }}>
            <div style={{ fontSize: 18, marginBottom: 8 }}>TOMBSTONING OLD DEVICE</div>
            <div className="snd-info-note">Marking previous device identity as revoked...</div>
          </div>
        </div>
      )}

      {/* === SUCCESSION === */}
      {wizardState === 'SUCCESSION' && (
        <div className="snd-card">
          <div style={{ textAlign: 'center', padding: 24 }}>
            <div style={{ fontSize: 18, marginBottom: 8 }}>CREATING SUCCESSION</div>
            <div className="snd-info-note">Binding new device identity to your state...</div>
          </div>
        </div>
      )}

      {/* === RESUMING (sync gate) === */}
      {wizardState === 'RESUMING' && (
        <div className="snd-card">
          <div className="snd-stat-grid-2">
            <div className="snd-stat-cell">
              <div className="snd-stat-val">{syncProgress.synced}/{syncProgress.total}</div>
              <div className="snd-stat-label">Contacts Synced</div>
            </div>
            <div className="snd-stat-cell">
              <div className="snd-stat-val">{syncProgress.total - syncProgress.synced}</div>
              <div className="snd-stat-label">Waiting</div>
            </div>
          </div>
          <div className="snd-info-note">
            All counterparties must acknowledge the tombstone before recovery can complete.
            Waiting for {syncProgress.total - syncProgress.synced} contact(s) to come online.
          </div>
        </div>
      )}

      {/* === COMPLETE === */}
      {wizardState === 'COMPLETE' && (
        <div className="snd-card">
          <div style={{ textAlign: 'center', padding: 24 }}>
            <div style={{ fontSize: 18, marginBottom: 8 }}>RECOVERY COMPLETE</div>
            <div className="snd-info-note">
              All contacts synced. Your wallet state has been restored.
            </div>
          </div>
        </div>
      )}

      {/* Status / Error messages */}
      {statusMsg && !errorMsg && (
        <div className="settings-shell__status">{statusMsg}</div>
      )}
      {errorMsg && (
        <div className="settings-shell__status" style={{ color: 'var(--gb-error, #c00)' }}>
          {errorMsg}
        </div>
      )}
    </main>
  );
}
