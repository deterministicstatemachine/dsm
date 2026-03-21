// SPDX-License-Identifier: Apache-2.0

import React, { memo, useCallback, useEffect, useRef, useState } from 'react';
import * as EventBridge from '../../dsm/EventBridge';
import {
  capsuleBytesToBase32,
  capsulePreviewFromBase32,
  decryptCapsuleBytes,
  getCapsulePreview,
  inspectCapsuleBytes,
  type CapsulePreview,
  type DecryptedCapsulePreview,
} from '../../services/recovery/nfcRecoveryService';
import './StorageScreen.css';

type Step = 'mnemonic' | 'tap' | 'preview';

interface RecoveryScreenProps {
  onNavigate?: (screen: string) => void;
}

function shortenValue(value: string, size = 20): string {
  if (!value) return '--';
  if (value === 'UNKNOWN') return value;
  return value.length > size ? `${value.slice(0, size)}...` : value;
}

function describeComparison(
  ringPreview: DecryptedCapsulePreview | null,
  localPreview: CapsulePreview,
): { label: string; note: string } {
  if (!ringPreview) {
    return {
      label: '--',
      note: 'Read the ring first to compare it against local capsule metadata.',
    };
  }

  if (!localPreview) {
    return {
      label: 'NO LOCAL',
      note: 'No local capsule metadata is available on this device for comparison.',
    };
  }

  const sameIndex = ringPreview.capsuleIndex === localPreview.capsuleIndex;
  const sameRoot = ringPreview.smtRoot === localPreview.smtRoot;
  const samePeers = ringPreview.counterpartyCount === localPreview.counterpartyCount;

  if (sameIndex && sameRoot && samePeers) {
    return {
      label: 'MATCH',
      note: 'Ring contents match the latest local capsule metadata on this device.',
    };
  }

  const reasons: string[] = [];
  if (!sameIndex) {
    reasons.push(`index ring #${ringPreview.capsuleIndex} vs local #${localPreview.capsuleIndex}`);
  }
  if (!sameRoot) {
    reasons.push('SMT root differs');
  }
  if (!samePeers) {
    reasons.push(`peer count ring ${ringPreview.counterpartyCount} vs local ${localPreview.counterpartyCount}`);
  }

  return {
    label: 'DIFFERS',
    note: `Ring contents differ from the latest local capsule metadata. This can be expected if device state changed after the last successful ring write. ${reasons.join('; ')}.`,
  };
}

const RecoveryScreen: React.FC<RecoveryScreenProps> = ({ onNavigate }) => {
  const [step, setStep] = useState<Step>('mnemonic');
  const [mnemonic, setMnemonic] = useState('');
  const [busy, setBusy] = useState(false);
  const [statusMsg, setStatusMsg] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const [capsulePreview, setCapsulePreview] = useState<DecryptedCapsulePreview | null>(null);
  const [localPreview, setLocalPreview] = useState<CapsulePreview>(null);
  const [capsuleBase32, setCapsuleBase32] = useState('');
  const [capsuleBytes, setCapsuleBytes] = useState<Uint8Array | null>(null);
  const [staged, setStaged] = useState(false);
  const mountedRef = useRef(true);
  const inspectInFlightRef = useRef(false);

  const formatError = useCallback((error: unknown): string => {
    if (error instanceof Error && error.message) return error.message;
    return String(error);
  }, []);

  const refreshLocalPreview = useCallback(async () => {
    try {
      const nextPreview = await getCapsulePreview();
      if (!mountedRef.current) return;
      setLocalPreview(nextPreview);
    } catch {
      if (!mountedRef.current) return;
      setLocalPreview(null);
    }
  }, []);

  const reset = useCallback(() => {
    setStep('mnemonic');
    setBusy(false);
    setStatusMsg('');
    setErrorMsg('');
    setCapsulePreview(null);
    setCapsuleBase32('');
    setCapsuleBytes(null);
    setStaged(false);
  }, []);

  const backToMnemonic = useCallback(() => {
    setStep('mnemonic');
    setBusy(false);
    setStatusMsg('');
    setErrorMsg('');
    setCapsulePreview(null);
    setCapsuleBase32('');
    setCapsuleBytes(null);
    setStaged(false);
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    try {
      EventBridge.initializeEventBridge();
    } catch {
      /* safe */
    }

    void refreshLocalPreview();

    const unsub = EventBridge.on('nfc-recovery-capsule', (bytes) => {
      if (step !== 'tap' || inspectInFlightRef.current) return;

      const payload = bytes as Uint8Array;
      if (!(payload instanceof Uint8Array) || payload.length === 0) {
        setErrorMsg('Recovery capsule read was empty. Tap the ring again.');
        return;
      }

      inspectInFlightRef.current = true;
      setBusy(true);
      setErrorMsg('');
      setStaged(false);
      setCapsuleBytes(payload);
      setCapsuleBase32(capsuleBytesToBase32(payload));
      setStatusMsg(`Capsule read (${payload.length} bytes). Inspecting in Rust...`);

      void inspectCapsuleBytes(payload, mnemonic.trim())
        .then((preview) => {
          if (!mountedRef.current) return;
          setCapsulePreview(preview);
          setStep('preview');
          setStatusMsg(
            'Ring backup inspected in Rust. Review the decrypted contents below and stage it only if it is the capsule you expect.',
          );
        })
        .catch((error: unknown) => {
          if (!mountedRef.current) return;
          setStep('mnemonic');
          setErrorMsg(`Ring inspection failed: ${formatError(error)} Check the mnemonic, then read the ring again.`);
          setStatusMsg('');
          setCapsuleBytes(null);
          setCapsuleBase32('');
          setStaged(false);
        })
        .finally(() => {
          inspectInFlightRef.current = false;
          if (!mountedRef.current) return;
          setBusy(false);
        });
    });

    return () => {
      mountedRef.current = false;
      inspectInFlightRef.current = false;
      try {
        unsub();
      } catch {
        /* safe */
      }
    };
  }, [formatError, mnemonic, refreshLocalPreview, step]);

  const onBeginRead = useCallback(() => {
    if (mnemonic.trim().split(/\s+/).length < 12) {
      setErrorMsg('Enter your mnemonic first.');
      return;
    }

    setErrorMsg('');
    setStatusMsg('Touch the ring to the phone. Rust will inspect the capsule after it is read.');
    setStep('tap');
  }, [mnemonic]);

  const onStageCapsule = useCallback(async () => {
    if (busy || !capsuleBytes) return;

    setBusy(true);
    setErrorMsg('');
    setStatusMsg('Staging the inspected capsule on this device in Rust...');
    try {
      const preview = await decryptCapsuleBytes(capsuleBytes, mnemonic.trim());
      if (!mountedRef.current) return;
      setCapsulePreview(preview);
      setStaged(true);
      setStatusMsg(
        'Capsule staged on this device. The saved bilateral tips are now available for tombstone handoff and resume.',
      );
    } catch (error: unknown) {
      if (!mountedRef.current) return;
      setErrorMsg(`Capsule staging failed: ${formatError(error)}`);
      setStatusMsg('');
    } finally {
      if (mountedRef.current) {
        setBusy(false);
      }
    }
  }, [busy, capsuleBytes, formatError, mnemonic]);

  const comparison = describeComparison(capsulePreview, localPreview);

  return (
    <main className="settings-shell settings-shell--dev" role="main">
      <h2 style={{ textAlign: 'center', marginBottom: 12 }}>INSPECT OR RECOVER FROM RING</h2>

      <div className="snd-card">
        <div className="snd-info-note">
          1. Enter the recovery mnemonic that encrypted the ring capsule. 2. Hold the ring to the
          phone when prompted. 3. Rust inspects and decrypts the ring contents for review. 4.
          Stage the backup on this device only if it matches what you expect.
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
          <div className="snd-info-note" style={{ marginTop: 8 }}>
            The mnemonic stays in the Rust-authoritative path. Android only transports the raw ring
            bytes to Rust for inspection or staging.
          </div>
          <div className="snd-actions">
            <button
              className="snd-btn"
              onClick={onBeginRead}
              disabled={busy || mnemonic.trim().split(/\s+/).length < 12}
            >
              INSPECT THE RING
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
            {busy ? 'INSPECTING...' : 'WAITING FOR RING...'}
          </div>
          <div className="snd-info-note">
            Hold the ring near the NFC antenna. Once the tag is read, Rust decrypts the capsule and
            returns a preview through the protobuf envelope path.
          </div>
          <div className="snd-actions">
            <button className="snd-btn" onClick={backToMnemonic} disabled={busy}>
              BACK TO MNEMONIC
            </button>
          </div>
        </div>
      )}

      {step === 'preview' && capsulePreview && (
        <>
          <div className="snd-card">
            <div className="snd-stat-grid-2">
              <div className="snd-stat-cell">
                <div className="snd-stat-val">#{capsulePreview.capsuleIndex}</div>
                <div className="snd-stat-label">Ring Capsule</div>
              </div>
              <div className="snd-stat-cell">
                <div className="snd-stat-val">{capsulePreview.counterpartyCount}</div>
                <div className="snd-stat-label">Peers</div>
              </div>
              <div className="snd-stat-cell">
                <div className="snd-stat-val-sm">{comparison.label}</div>
                <div className="snd-stat-label">Vs Local</div>
              </div>
              <div className="snd-stat-cell">
                <div className="snd-stat-val-sm">{staged ? 'STAGED' : 'INSPECTED'}</div>
                <div className="snd-stat-label">State</div>
              </div>
            </div>
            <div className="snd-info-note" style={{ marginTop: 8 }}>
              {comparison.note}
            </div>
            <div className="snd-info-note" style={{ marginTop: 8 }}>
              {staged
                ? 'This backup is already staged on this device.'
                : 'Inspection does not mutate recovery state. Use the stage action only if this ring contains the backup you want to recover from.'}
            </div>
          </div>

          <div className="snd-card">
            <div className="snd-info-row">
              <span className="snd-info-label">SMT Root</span>
              <span className="snd-info-val" style={{ fontFamily: 'monospace', fontSize: 11 }}>
                {shortenValue(capsulePreview.smtRoot)}
              </span>
            </div>
            <div className="snd-info-row">
              <span className="snd-info-label">Rollup</span>
              <span className="snd-info-val" style={{ fontFamily: 'monospace', fontSize: 11 }}>
                {shortenValue(capsulePreview.rollupHash)}
              </span>
            </div>
            <div className="snd-info-row">
              <span className="snd-info-label">Version / Flags</span>
              <span className="snd-info-val">
                {capsulePreview.capsuleVersion} / {capsulePreview.capsuleFlags}
              </span>
            </div>
            <div className="snd-info-row">
              <span className="snd-info-label">Logical Time</span>
              <span className="snd-info-val">{capsulePreview.logicalTime}</span>
            </div>
            <div className="snd-info-row">
              <span className="snd-info-label">Payload</span>
              <span className="snd-info-val">
                {capsuleBytes ? `${capsuleBytes.length} bytes` : '--'}
              </span>
            </div>
          </div>

          {capsulePreview.chainTips.length > 0 && (
            <div className="snd-card">
              <div className="snd-info-row">
                <span className="snd-info-label">CHAIN TIPS ON THE RING</span>
              </div>
              <div className="snd-info-note">
                {capsulePreview.chainTips.map((tip) => (
                  <div key={`${tip.counterpartyId}:${tip.height}`}>
                    {tip.counterpartyId.slice(0, 16)}... h={tip.height} {shortenValue(tip.headHash, 16)}
                  </div>
                ))}
              </div>
            </div>
          )}

          {capsuleBase32 && (
            <div className="snd-card">
              <div className="snd-info-row">
                <span className="snd-info-label">ENCRYPTED PAYLOAD (BASE32)</span>
                <span className="snd-info-val">{capsulePreviewFromBase32(capsuleBase32, 10)}</span>
              </div>
              <textarea
                value={capsuleBase32}
                readOnly
                rows={5}
                style={{
                  width: '100%',
                  boxSizing: 'border-box',
                  padding: '10px 12px',
                  marginTop: 8,
                  fontFamily: "'Martian Mono', monospace",
                  fontSize: 9,
                  background: 'var(--gb-bg)',
                  color: 'var(--gb-fg)',
                  border: '2px solid var(--gb-border)',
                  borderRadius: 4,
                  resize: 'vertical',
                }}
              />
            </div>
          )}

          <div className="snd-card">
            <div className="snd-actions">
              <button className="snd-btn" onClick={onStageCapsule} disabled={busy || staged || !capsuleBytes}>
                {busy ? 'WORKING...' : staged ? 'ALREADY STAGED' : 'STAGE ON THIS DEVICE'}
              </button>
              <button className="snd-btn" onClick={reset} style={{ marginTop: 4 }}>
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
        </>
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
