// SPDX-License-Identifier: Apache-2.0
// Inspect or recover from a ring, on the StateBoy frame: the mnemonic, the
// tap, and the decrypted capsule as Rust inspected it, staged only on request.

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
import { Disclosure, Notice, ScreenFrame, middleTruncate } from '../common/ScreenFrame';
import { InfoTip } from '../common/InfoTip';

type Step = 'mnemonic' | 'tap' | 'preview';

interface RecoveryScreenProps {
  onNavigate?: (screen: string) => void;
}

function shortenValue(value: string, size = 20): string {
  if (!value) return '--';
  if (value === 'UNKNOWN') return value;
  return middleTruncate(value, Math.ceil(size / 2), Math.floor(size / 2));
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

  const onBack = step === 'mnemonic'
    ? () => onNavigate?.('nfc_recovery')
    : reset;

  return (
    <ScreenFrame
      title="Inspect or Recover"
      onBack={onBack}
      className="recovery-screen"
      info={(
        <InfoTip title="Recovering from a ring">
          <p>1. Enter the recovery mnemonic that encrypted the ring capsule. 2. Hold the ring to the phone when prompted. 3. Rust inspects and decrypts the ring contents for review. 4. Stage the backup on this device only if it matches what you expect.</p>
          <p>The mnemonic stays in the Rust-authoritative path. Android only transports the raw ring bytes to Rust for inspection or staging.</p>
          <p>Inspection does not change recovery state. Staging does.</p>
        </InfoTip>
      )}
      banner={(
        <>
          {errorMsg && <Notice banner kind="error" onClose={() => setErrorMsg('')}>{errorMsg}</Notice>}
          {statusMsg && !errorMsg && <Notice banner onClose={() => setStatusMsg('')}>{statusMsg}</Notice>}
        </>
      )}
    >
      {step === 'mnemonic' && (
        <section className="sb-card">
          <div className="sb-card__title">Your recovery mnemonic</div>
          <div className="sb-field">
            <label htmlFor="recovery-mnemonic">The words that encrypted the ring capsule</label>
            <textarea
              id="recovery-mnemonic"
              className="sb-input sb-input--mono"
              value={mnemonic}
              onChange={(e) => setMnemonic(e.target.value)}
              placeholder="word1 word2 word3 ..."
              rows={4}
              disabled={busy}
              spellCheck={false}
            />
          </div>
          <button
            type="button"
            className="sb-btn sb-btn--primary sb-btn--block"
            onClick={onBeginRead}
            disabled={busy || mnemonic.trim().split(/\s+/).length < 12}
          >
            Inspect the ring
          </button>
        </section>
      )}

      {step === 'tap' && (
        <section className="sb-card sb-card--dark sb-card--hero" aria-live="polite">
          <div className="sb-hero__label">Tap the ring to the phone</div>
          <div className="sb-hero__value" style={{ fontSize: 14 }}>
            {busy ? 'Inspecting…' : 'Waiting for ring…'}
          </div>
          <div className="sb-hero__sub">
            Hold the ring near the NFC antenna. Once the tag is read, Rust decrypts the capsule and returns a preview.
          </div>
          <div className="sb-actions" style={{ marginBottom: 0 }}>
            <button type="button" className="sb-btn sb-btn--block" onClick={reset} disabled={busy}>
              Back to mnemonic
            </button>
          </div>
        </section>
      )}

      {step === 'preview' && capsulePreview && (
        <>
          <section className="sb-card sb-card--dark" aria-label="Ring capsule">
            <div className="sb-stats sb-stats--4">
              <div className="sb-stats__cell">
                <div className="sb-stats__val">#{capsulePreview.capsuleIndex}</div>
                <div className="sb-stats__label">Ring capsule</div>
              </div>
              <div className="sb-stats__cell">
                <div className="sb-stats__val">{capsulePreview.counterpartyCount}</div>
                <div className="sb-stats__label">Peers</div>
              </div>
              <div className="sb-stats__cell">
                <div className="sb-stats__val sb-stats__val--sm">{comparison.label}</div>
                <div className="sb-stats__label">Vs local</div>
              </div>
              <div className="sb-stats__cell">
                <div className="sb-stats__val sb-stats__val--sm">{staged ? 'STAGED' : 'INSPECTED'}</div>
                <div className="sb-stats__label">State</div>
              </div>
            </div>
            <p className="sb-hint sb-hint--tight" style={{ marginTop: 8 }}>{comparison.note}</p>
            <p className="sb-hint sb-hint--tight">
              {staged
                ? 'This backup is already staged on this device.'
                : 'Inspection does not mutate recovery state. Stage it only if this ring holds the backup you want to recover from.'}
            </p>
          </section>

          <section className="sb-card">
            <div className="sb-kv">
              <span className="sb-kv__k">SMT root</span>
              <span className="sb-kv__v sb-kv__v--mono">{shortenValue(capsulePreview.smtRoot)}</span>
            </div>
            <div className="sb-kv">
              <span className="sb-kv__k">Rollup</span>
              <span className="sb-kv__v sb-kv__v--mono">{shortenValue(capsulePreview.rollupHash)}</span>
            </div>
            <div className="sb-kv">
              <span className="sb-kv__k">Version / flags</span>
              <span className="sb-kv__v">{capsulePreview.capsuleVersion} / {capsulePreview.capsuleFlags}</span>
            </div>
            <div className="sb-kv">
              <span className="sb-kv__k">Logical time</span>
              <span className="sb-kv__v">{capsulePreview.logicalTime}</span>
            </div>
            <div className="sb-kv">
              <span className="sb-kv__k">Payload</span>
              <span className="sb-kv__v">{capsuleBytes ? `${capsuleBytes.length} bytes` : '--'}</span>
            </div>
          </section>

          {capsulePreview.chainTips.length > 0 && (
            <Disclosure summary={`Chain tips on the ring (${capsulePreview.chainTips.length})`}>
              {capsulePreview.chainTips.map((tip) => (
                <div className="sb-kv" key={`${tip.counterpartyId}:${tip.height}`}>
                  <span className="sb-kv__k sb-mono">{tip.counterpartyId.slice(0, 12)}…</span>
                  <span className="sb-kv__v sb-kv__v--mono">h={tip.height} · {shortenValue(tip.headHash, 16)}</span>
                </div>
              ))}
            </Disclosure>
          )}

          {capsuleBase32 && (
            <Disclosure summary={`Encrypted payload · ${capsulePreviewFromBase32(capsuleBase32, 10)}`}>
              <textarea
                className="sb-input sb-input--mono"
                aria-label="Encrypted payload, Base32"
                value={capsuleBase32}
                readOnly
                rows={5}
                style={{ fontSize: 8 }}
              />
            </Disclosure>
          )}

          <div className="sb-actions">
            <button type="button" className="sb-btn" onClick={reset}>Read again</button>
            <button
              type="button"
              className="sb-btn sb-btn--primary"
              onClick={onStageCapsule}
              disabled={busy || staged || !capsuleBytes}
            >
              {busy ? 'Working…' : staged ? 'Already staged' : 'Stage on this device'}
            </button>
          </div>
          {staged && (
            <div className="sb-actions">
              <button
                type="button"
                className="sb-btn sb-btn--primary sb-btn--block"
                onClick={() => onNavigate?.('recovery_pipeline')}
              >
                Proceed to recovery
              </button>
            </div>
          )}
        </>
      )}
    </ScreenFrame>
  );
};

export default memo(RecoveryScreen);
