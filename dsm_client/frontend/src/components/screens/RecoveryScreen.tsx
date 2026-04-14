// SPDX-License-Identifier: Apache-2.0

import React, { memo, useCallback, useEffect, useRef, useState } from 'react';
import * as EventBridge from '../../dsm/EventBridge';
import {
  capsuleBytesToBase32,
  capsulePreviewFromBase32,
  decryptCapsuleBytes,
  getCapsulePreview,
  inspectCapsuleBytes,
  readNfcRing,
  stopNfcRead,
  type CapsulePreview,
  type DecryptedCapsulePreview,
} from '../../services/recovery/nfcRecoveryService';
import './NfcRecoveryScreen.css';

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
    void stopNfcRead();
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
    void stopNfcRead();
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

    // Auto-refresh when screen becomes visible
    const onVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        void refreshLocalPreview();
      }
    };
    document.addEventListener('visibilitychange', onVisibilityChange);

    return () => {
      mountedRef.current = false;
      inspectInFlightRef.current = false;
      void stopNfcRead();
      document.removeEventListener('visibilitychange', onVisibilityChange);
      try {
        unsub();
      } catch {
        /* safe */
      }
    };
  }, [formatError, mnemonic, refreshLocalPreview, step]);

  const onBeginRead = useCallback(async () => {
    if (mnemonic.trim().split(/\s+/).length < 12) {
      setErrorMsg('Enter your mnemonic first.');
      return;
    }

    setErrorMsg('');
    setStatusMsg('Touch the ring to the phone. Rust will inspect the capsule after it is read.');
    setStep('tap');

    try {
      await readNfcRing();
    } catch (error: unknown) {
      setErrorMsg(`NFC read launch failed: ${formatError(error)}`);
      setStep('mnemonic');
      setStatusMsg('');
    }
  }, [formatError, mnemonic]);

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
    <div className="nfc-shell" role="main">
      <div className="nfc-header">
        <h2>INSPECT OR RECOVER FROM RING</h2>
      </div>

      <div className="nfc-stage">
        {/* Instructions card */}
        <div className="nfc-card">
          <div className="nfc-note">
            1. Enter the recovery mnemonic that encrypted the ring capsule. 2. Hold the ring to the
            phone when prompted. 3. Rust inspects and decrypts the ring contents for review. 4.
            Stage the backup on this device only if it matches what you expect.
          </div>
        </div>

        {step === 'mnemonic' && (
          <div className="nfc-card">
            <div className="nfc-info-row">
              <span className="nfc-info-label">ENTER YOUR RECOVERY MNEMONIC</span>
            </div>
            <div style={{ padding: '0 10px 8px' }}>
              <textarea
                className="nfc-input"
                value={mnemonic}
                onChange={(e) => setMnemonic(e.target.value)}
                placeholder="word1 word2 word3 ..."
                rows={4}
                style={{ marginTop: 8 }}
                disabled={busy}
              />
            </div>
            <div className="nfc-note">
              The mnemonic stays in the Rust-authoritative path. Android only transports the raw ring
              bytes to Rust for inspection or staging.
            </div>
            <div className="nfc-actions">
              <button
                className="nfc-btn"
                onClick={onBeginRead}
                disabled={busy || mnemonic.trim().split(/\s+/).length < 12}
              >
                INSPECT THE RING
              </button>
            </div>
          </div>
        )}

        {step === 'tap' && (
          <div className="nfc-card">
            <div className="nfc-info-row">
              <span className="nfc-info-label">TAP THE RING TO THE PHONE</span>
            </div>
            <div className="nfc-tap-prompt">
              {busy ? 'INSPECTING...' : 'WAITING FOR RING...'}
            </div>
            <div className="nfc-note">
              Hold the ring near the NFC antenna. Once the tag is read, Rust decrypts the capsule and
              returns a preview through the protobuf envelope path.
            </div>
            <div className="nfc-actions">
              <button className="nfc-btn" onClick={backToMnemonic} disabled={busy}>
                BACK TO MNEMONIC
              </button>
            </div>
          </div>
        )}

        {step === 'preview' && capsulePreview && (
          <>
            {/* Ring capsule stats */}
            <div className="nfc-card">
              <div className="nfc-stat-grid">
                <div className="nfc-stat-cell">
                  <div className="nfc-stat-val">#{capsulePreview.capsuleIndex}</div>
                  <div className="nfc-stat-label">Ring Capsule</div>
                </div>
                <div className="nfc-stat-cell">
                  <div className="nfc-stat-val">{capsulePreview.counterpartyCount}</div>
                  <div className="nfc-stat-label">Peers</div>
                </div>
                <div className="nfc-stat-cell">
                  <div className="nfc-stat-val-sm">{comparison.label}</div>
                  <div className="nfc-stat-label">Vs Local</div>
                </div>
                <div className="nfc-stat-cell">
                  <div className="nfc-stat-val-sm">{staged ? 'STAGED' : 'INSPECTED'}</div>
                  <div className="nfc-stat-label">State</div>
                </div>
              </div>
              <div className="nfc-note">
                {comparison.note}
              </div>
              <div className="nfc-note">
                {staged
                  ? 'This backup is already staged on this device.'
                  : 'Inspection does not mutate recovery state. Use the stage action only if this ring contains the backup you want to recover from.'}
              </div>
            </div>

            {/* Detailed fields */}
            <div className="nfc-card">
              <div className="nfc-info-row">
                <span className="nfc-info-label">SMT Root</span>
                <span className="nfc-info-val" style={{ fontFamily: 'monospace', fontSize: 11 }}>
                  {shortenValue(capsulePreview.smtRoot)}
                </span>
              </div>
              <div className="nfc-info-row">
                <span className="nfc-info-label">Rollup</span>
                <span className="nfc-info-val" style={{ fontFamily: 'monospace', fontSize: 11 }}>
                  {shortenValue(capsulePreview.rollupHash)}
                </span>
              </div>
              <div className="nfc-info-row">
                <span className="nfc-info-label">Version / Flags</span>
                <span className="nfc-info-val">
                  {capsulePreview.capsuleVersion} / {capsulePreview.capsuleFlags}
                </span>
              </div>
              <div className="nfc-info-row">
                <span className="nfc-info-label">Logical Time</span>
                <span className="nfc-info-val">{capsulePreview.logicalTime}</span>
              </div>
              <div className="nfc-info-row">
                <span className="nfc-info-label">Payload</span>
                <span className="nfc-info-val">
                  {capsuleBytes ? `${capsuleBytes.length} bytes` : '--'}
                </span>
              </div>
            </div>

            {/* Chain tips */}
            {capsulePreview.chainTips.length > 0 && (
              <div className="nfc-card">
                <div className="nfc-info-row">
                  <span className="nfc-info-label">CHAIN TIPS ON THE RING</span>
                </div>
                <div className="nfc-note" style={{ opacity: 0.6 }}>
                  {capsulePreview.chainTips.map((tip) => (
                    <div key={`${tip.counterpartyId}:${tip.height}`}>
                      {tip.counterpartyId.slice(0, 16)}... h={tip.height} {shortenValue(tip.headHash, 16)}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Encrypted payload base32 */}
            {capsuleBase32 && (
              <div className="nfc-card">
                <div className="nfc-info-row">
                  <span className="nfc-info-label">ENCRYPTED PAYLOAD (BASE32)</span>
                  <span className="nfc-info-val">{capsulePreviewFromBase32(capsuleBase32, 10)}</span>
                </div>
                <div style={{ padding: '0 10px 8px' }}>
                  <textarea
                    className="nfc-input"
                    value={capsuleBase32}
                    readOnly
                    rows={5}
                    style={{ resize: 'vertical', marginTop: 8, fontSize: 7 }}
                  />
                </div>
              </div>
            )}

            {/* Action buttons */}
            <div className="nfc-card">
              <div className="nfc-actions">
                <button className="nfc-btn" onClick={onStageCapsule} disabled={busy || staged || !capsuleBytes}>
                  {busy ? 'WORKING...' : staged ? 'ALREADY STAGED' : 'STAGE ON THIS DEVICE'}
                </button>
              </div>
              {staged && (
                <div className="nfc-actions">
                  <button
                    className="nfc-btn"
                    onClick={() => onNavigate?.('recovery_pipeline')}
                    style={{ fontWeight: 900, letterSpacing: '1px' }}
                  >
                    PROCEED TO RECOVERY
                  </button>
                </div>
              )}
              <div className="nfc-actions">
                <button className="nfc-btn" onClick={reset}>
                  READ AGAIN
                </button>
              </div>
              <div className="nfc-actions">
                <button
                  className="nfc-btn"
                  onClick={() => onNavigate?.('nfc_recovery')}
                >
                  BACK TO BACKUP
                </button>
              </div>
            </div>
          </>
        )}

        {/* Status / error messages */}
        {statusMsg && !errorMsg && (
          <div className="nfc-card">
            <div className="nfc-note nfc-note--strong">{statusMsg}</div>
          </div>
        )}
        {errorMsg && (
          <div className="nfc-card">
            <div className="nfc-note nfc-note--strong" style={{ color: 'var(--gb-error, #c00)' }}>
              {errorMsg}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default memo(RecoveryScreen);
