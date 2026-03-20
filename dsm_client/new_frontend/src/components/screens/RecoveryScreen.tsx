// SPDX-License-Identifier: Apache-2.0

import React, { memo, useCallback, useEffect, useRef, useState } from 'react';
import * as EventBridge from '../../dsm/EventBridge';
import {
  capsuleBytesToBase32,
  capsulePreviewFromBase32,
  decryptCapsuleBytes,
  type DecryptedCapsulePreview,
} from '../../services/recovery/nfcRecoveryService';
import './StorageScreen.css';

type Step = 'mnemonic' | 'tap' | 'preview';

interface RecoveryScreenProps {
  onNavigate?: (screen: string) => void;
}

const RecoveryScreen: React.FC<RecoveryScreenProps> = ({ onNavigate }) => {
  const [step, setStep] = useState<Step>('mnemonic');
  const [mnemonic, setMnemonic] = useState('');
  const [busy, setBusy] = useState(false);
  const [statusMsg, setStatusMsg] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const [capsulePreview, setCapsulePreview] = useState<DecryptedCapsulePreview | null>(null);
  const [capsuleBase32, setCapsuleBase32] = useState('');
  const mountedRef = useRef(true);
  const importInFlightRef = useRef(false);

  const formatError = useCallback((error: unknown): string => {
    if (error instanceof Error && error.message) return error.message;
    return String(error);
  }, []);

  const reset = useCallback(() => {
    setStep('mnemonic');
    setBusy(false);
    setStatusMsg('');
    setErrorMsg('');
    setCapsulePreview(null);
    setCapsuleBase32('');
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    try {
      EventBridge.initializeEventBridge();
    } catch {
      /* safe */
    }

    const unsub = EventBridge.on('nfc-recovery-capsule', (bytes) => {
      if (step !== 'tap' || importInFlightRef.current) return;

      const payload = bytes as Uint8Array;
      if (!(payload instanceof Uint8Array) || payload.length === 0) {
        setErrorMsg('Recovery capsule read was empty. Tap the ring again.');
        return;
      }

      importInFlightRef.current = true;
      setBusy(true);
      setErrorMsg('');
      setCapsuleBase32(capsuleBytesToBase32(payload));
      setStatusMsg(`Capsule read (${payload.length} bytes). Decrypting in Rust...`);

      void decryptCapsuleBytes(payload, mnemonic.trim())
        .then((preview) => {
          if (!mountedRef.current) return;
          setCapsulePreview(preview);
          setStep('preview');
          setStatusMsg('Capsule imported. The saved bilateral tips are now staged on this device for tombstone handoff and resume.');
        })
        .catch((error: unknown) => {
          if (!mountedRef.current) return;
          setErrorMsg(`Capsule import failed: ${formatError(error)}`);
          setStatusMsg('Tap the ring again with the correct mnemonic to retry.');
        })
        .finally(() => {
          importInFlightRef.current = false;
          if (!mountedRef.current) return;
          setBusy(false);
        });
    });

    return () => {
      mountedRef.current = false;
      importInFlightRef.current = false;
      try {
        unsub();
      } catch {
        /* safe */
      }
    };
  }, [formatError, mnemonic, step]);

  const onBeginRead = useCallback(() => {
    if (mnemonic.trim().split(/\s+/).length < 12) {
      setErrorMsg('Enter your mnemonic first.');
      return;
    }

    setErrorMsg('');
    setStatusMsg('Touch the ring to the phone. The capsule will decrypt after it is read.');
    setStep('tap');
  }, [mnemonic]);

  return (
    <main className="settings-shell settings-shell--dev" role="main">
      <h2 style={{ textAlign: 'center', marginBottom: 12 }}>RECOVER FROM RING</h2>

      <div className="snd-card">
        <div className="snd-info-note">
          The ring carries the latest saved chain tips. Read it, decrypt it, and this device gets
          the last backed-up bilateral view needed for the tombstone handoff.
        </div>
      </div>

      {step === 'mnemonic' && (
        <div className="snd-card">
          <div className="snd-info-row">
            <span className="snd-info-label">ENTER YOUR RECOVERY MNEMONIC</span>
          </div>
          <textarea
            value={mnemonic}
            onChange={(e) => setMnemonic(e.target.value)}
            placeholder="word1 word2 word3 ..."
            rows={4}
            style={{
              width: '100%',
              boxSizing: 'border-box',
              padding: '10px 12px',
              marginTop: 8,
              fontFamily: "'Martian Mono', monospace",
              fontSize: 12,
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
              className="snd-btn"
              onClick={onBeginRead}
              disabled={busy || mnemonic.trim().split(/\s+/).length < 12}
            >
              READ THE RING
            </button>
          </div>
        </div>
      )}

      {step === 'tap' && (
        <div className="snd-card">
          <div className="snd-info-row">
            <span className="snd-info-label">TAP THE RING TO THE PHONE</span>
          </div>
          <div style={{ textAlign: 'center', padding: 24, fontSize: 28 }}>
            {busy ? 'DECRYPTING...' : 'WAITING FOR RING...'}
          </div>
          <div className="snd-info-note">
            Hold the ring near the NFC antenna. Once the tag is read, the capsule decrypts in Rust.
          </div>
        </div>
      )}

      {step === 'preview' && capsulePreview && (
        <div className="snd-card">
          <div className="snd-stat-grid-2">
            <div className="snd-stat-cell">
              <div className="snd-stat-val">{capsulePreview.counterpartyCount}</div>
              <div className="snd-stat-label">Recovered Peers</div>
            </div>
            <div className="snd-stat-cell">
              <div className="snd-stat-val">
                {capsuleBase32 ? capsulePreviewFromBase32(capsuleBase32, 10) : '--'}
              </div>
              <div className="snd-stat-label">Capsule</div>
            </div>
          </div>
          <div className="snd-info-row">
            <span className="snd-info-label">SMT Root</span>
            <span className="snd-info-val" style={{ fontFamily: 'monospace', fontSize: 11 }}>
              {capsulePreview.smtRoot.slice(0, 20)}...
            </span>
          </div>
          <div className="snd-info-row">
            <span className="snd-info-label">Rollup</span>
            <span className="snd-info-val" style={{ fontFamily: 'monospace', fontSize: 11 }}>
              {capsulePreview.rollupHash.slice(0, 20)}...
            </span>
          </div>
          {capsulePreview.counterparties.length > 0 && (
            <div className="snd-info-note">
              {capsulePreview.counterparties
                .slice(0, 3)
                .map((id) => id.slice(0, 16))
                .join(', ')}
              {capsulePreview.counterparties.length > 3 ? '…' : ''}
            </div>
          )}
          <div className="snd-info-note">
            The last backed-up bilateral tips are staged on this device so the tombstone flow can
            advance from saved state instead of re-harvesting those tips from peers.
          </div>
          <div className="snd-actions">
            <button className="snd-btn" onClick={reset}>
              READ AGAIN
            </button>
            <button
              className="snd-btn"
              onClick={() => onNavigate?.('nfc_recovery')}
              style={{ marginTop: 4 }}
            >
              BACK TO BACKUP
            </button>
          </div>
        </div>
      )}

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
};

export default memo(RecoveryScreen);
