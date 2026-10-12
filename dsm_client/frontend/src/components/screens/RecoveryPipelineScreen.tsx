// SPDX-License-Identifier: Apache-2.0
// The recovery pipeline on the StateBoy frame: tombstone, succession,
// propagate, then the wait for counterparties, then resume.

import React, { memo, useCallback, useEffect, useRef, useState } from 'react';
import {
  activateRecovery,
  completeRecovery,
  executePipeline,
  getRecoveryPhase,
  getSyncProgress,
  pollAcks,
  reconcileDbtc,
  resumeAll,
  type AckStatus,
  type PipelineResult,
  type SyncProgress,
} from '../../services/recovery/nfcRecoveryService';
import { Notice, ScreenFrame } from '../common/ScreenFrame';
import { InfoTip } from '../common/InfoTip';

type Phase = 'staged' | 'polling' | 'complete' | 'error' | 'none';

const PHASE_STEPS = ['Tombstone', 'Succession', 'Propagate', 'Synced'] as const;

function phaseIndex(phase: Phase): number {
  switch (phase) {
    case 'staged':
      return 0;
    case 'polling':
      return 3;
    case 'complete':
      return 4;
    default:
      return -1;
  }
}

interface RecoveryPipelineScreenProps {
  onNavigate?: (screen: string) => void;
}

const RecoveryPipelineScreen: React.FC<RecoveryPipelineScreenProps> = ({ onNavigate }) => {
  const [phase, setPhase] = useState<Phase>('none');
  const [busy, setBusy] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [statusMsg, setStatusMsg] = useState('');
  const [pipelineResult, setPipelineResult] = useState<PipelineResult | null>(null);
  const [syncProgress, setSyncProgress] = useState<SyncProgress | null>(null);
  const [lastAckStatus, setLastAckStatus] = useState<AckStatus | null>(null);
  const [resumeCount, setResumeCount] = useState(0);
  const mountedRef = useRef(true);
  const pollTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const clearPollTimer = useCallback(() => {
    if (pollTimerRef.current) {
      clearTimeout(pollTimerRef.current);
      pollTimerRef.current = null;
    }
  }, []);

  // Load current phase on mount
  useEffect(() => {
    mountedRef.current = true;

    void (async () => {
      try {
        const currentPhase = await getRecoveryPhase();
        if (!mountedRef.current) return;
        const p = (['staged', 'polling', 'complete'].includes(currentPhase)
          ? currentPhase
          : 'none') as Phase;
        setPhase(p);

        if (p === 'polling') {
          const progress = await getSyncProgress();
          if (mountedRef.current) setSyncProgress(progress);
        }
      } catch {
        if (mountedRef.current) setPhase('none');
      }
    })();

    return () => {
      mountedRef.current = false;
      clearPollTimer();
    };
  }, [clearPollTimer]);

  // Auto-poll for ACKs when in polling phase
  useEffect(() => {
    if (phase !== 'polling') {
      clearPollTimer();
      return;
    }

    const doPoll = async () => {
      try {
        const acks = await pollAcks();
        if (!mountedRef.current) return;
        setLastAckStatus(acks);
        setSyncProgress({
          synced: acks.synced,
          total: acks.total,
          pending: [],
        });

        if (acks.allSynced) {
          setPhase('complete');
          setStatusMsg('All counterparties have acknowledged the tombstone.');
          clearPollTimer();
          return;
        }
      } catch {
        // Poll failed — retry on next tick
      }

      if (mountedRef.current) {
        pollTimerRef.current = setTimeout(() => void doPoll(), 30_000);
      }
    };

    void doPoll();

    const onVisibility = () => {
      if (document.visibilityState === 'visible' && phase === 'polling') {
        clearPollTimer();
        void doPoll();
      }
    };
    document.addEventListener('visibilitychange', onVisibility);

    return () => {
      clearPollTimer();
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [phase, clearPollTimer]);

  const onExecutePipeline = useCallback(async () => {
    if (busy) return;
    setBusy(true);
    setErrorMsg('');
    setStatusMsg('Executing recovery pipeline: tombstone, succession, propagate...');

    try {
      const result = await executePipeline();
      if (!mountedRef.current) return;
      setPipelineResult(result);

      if (result.phase === 'polling') {
        setPhase('polling');
        setStatusMsg(
          `Pipeline complete. Tombstone propagated to ${result.pushed}/${result.total} storage nodes. Polling for counterparty ACKs.`,
        );
      } else {
        setPhase(result.phase as Phase);
        setStatusMsg(`Pipeline finished with phase: ${result.phase}`);
      }
    } catch (error: unknown) {
      if (!mountedRef.current) return;
      setPhase('error');
      setErrorMsg(error instanceof Error ? error.message : String(error));
      setStatusMsg('');
    } finally {
      if (mountedRef.current) setBusy(false);
    }
  }, [busy]);

  const onResumeAll = useCallback(async () => {
    if (busy) return;
    setBusy(true);
    setErrorMsg('');
    setStatusMsg('Resuming bilateral relationships...');

    try {
      const result = await resumeAll();
      if (!mountedRef.current) return;
      setResumeCount(result.resumed);

      // Re-establish across counterparties: gather each counterparty's already-posted,
      // genesis-authenticated evidence and assemble the cross-relationship succession. Activation
      // RECORDING is fail-closed until go-live, so "assembled;awaiting-go-live:..." is success.
      setStatusMsg('Re-establishing with counterparties (assembling succession)...');
      const activation = await activateRecovery();
      if (!mountedRef.current) return;

      // Reconcile recovered dBTC bearer state (fail-closed; stays locked if evidence incomplete).
      setStatusMsg('Reconciling recovered assets...');
      const dbtc = await reconcileDbtc();
      if (!mountedRef.current) return;

      const pendingGoLive = activation.startsWith('assembled;awaiting-go-live');
      setPhase('complete');
      const activationNote = pendingGoLive
        ? 'Identity succession assembled — activation pends go-live.'
        : `Activation: ${activation}.`;
      setStatusMsg(
        `Recovery complete. ${result.resumed} relationship(s) restored. ${activationNote} dBTC: ${dbtc}.`,
      );
    } catch (error: unknown) {
      if (!mountedRef.current) return;
      setErrorMsg(error instanceof Error ? error.message : String(error));
      setStatusMsg('');
    } finally {
      if (mountedRef.current) setBusy(false);
    }
  }, [busy]);

  const onRetry = useCallback(() => {
    setErrorMsg('');
    setPhase('staged');
  }, []);

  // Final cleanup on DONE: run the backend's completeResume terminator, then leave. Best-effort —
  // navigation proceeds even if cleanup reports an issue (the recovered state is already restored).
  const onDone = useCallback(async () => {
    if (resumeCount > 0) {
      try {
        await completeRecovery();
      } catch {
        // non-fatal; recovery state already restored. Proceed to wallet.
      }
    }
    onNavigate?.('wallet');
  }, [resumeCount, onNavigate]);

  const progressIdx = phaseIndex(phase);

  return (
    <ScreenFrame
      title="Recovery Pipeline"
      onBack={() => onNavigate?.('recovery')}
      className="recovery-pipeline-screen"
      info={(
        <InfoTip title="Recovery pipeline">
          <p>With a capsule staged, RECOVER creates a tombstone receipt for the old device, binds this device as its successor, and propagates that to the storage nodes.</p>
          <p>Counterparties acknowledge the tombstone in their own time; this screen polls for them every 30 seconds and when it comes back into view.</p>
          <p>Once all have, RESUME restores the bilateral relationships, assembles the succession and reconciles recovered assets.</p>
        </InfoTip>
      )}
      banner={(
        <>
          {errorMsg && <Notice banner kind="error" onClose={() => setErrorMsg('')}>{errorMsg}</Notice>}
          {statusMsg && !errorMsg && <Notice banner onClose={() => setStatusMsg('')}>{statusMsg}</Notice>}
        </>
      )}
    >
      {/* Phase progress indicator */}
      <section className="sb-card sb-card--dark" aria-label="Recovery phase">
        <div className="sb-steps">
          {PHASE_STEPS.map((label, i) => {
            const done = i < progressIdx;
            const active = i === progressIdx;
            return (
              <div
                key={label}
                className={`sb-steps__step${done ? ' is-done' : ''}${active ? ' is-active' : ''}`}
                aria-current={active ? 'step' : undefined}
              >
                <span className="sb-steps__mark" aria-hidden="true">{done ? '✓' : active ? '…' : '·'}</span>
                {label}
              </div>
            );
          })}
        </div>
      </section>

      {/* Phase: none — no capsule staged */}
      {phase === 'none' && (
        <>
          <div className="sb-empty">
            No recovery capsule has been staged on this device. Go back and stage a capsule from the NFC ring first.
          </div>
          <div className="sb-actions">
            <button type="button" className="sb-btn sb-btn--primary sb-btn--block" onClick={() => onNavigate?.('recovery')}>
              Back to recovery
            </button>
          </div>
        </>
      )}

      {/* Phase: staged — ready to execute */}
      {phase === 'staged' && (
        <section className="sb-card">
          <div className="sb-card__title">Capsule staged</div>
          <p className="sb-hint">
            Tap RECOVER to execute the full pipeline: create a tombstone receipt for the old device, bind this device as the successor, and propagate to counterparties.
          </p>
          <button
            type="button"
            className="sb-btn sb-btn--primary sb-btn--block"
            onClick={onExecutePipeline}
            disabled={busy}
          >
            {busy ? 'Executing…' : 'Recover'}
          </button>
        </section>
      )}

      {/* Phase: polling — waiting for counterparty ACKs */}
      {phase === 'polling' && (
        <>
          <section className="sb-card">
            <div className="sb-card__title">Waiting for counterparties</div>
            {syncProgress && (
              <div className="sb-stats sb-stats--2" style={{ marginBottom: 8 }}>
                <div className="sb-stats__cell">
                  <div className="sb-stats__val">{syncProgress.synced}</div>
                  <div className="sb-stats__label">Synced</div>
                </div>
                <div className="sb-stats__cell">
                  <div className="sb-stats__val">{syncProgress.total}</div>
                  <div className="sb-stats__label">Total</div>
                </div>
              </div>
            )}
            <p className="sb-hint sb-hint--tight">Tombstone propagated. Waiting for counterparty acknowledgements.</p>
            {lastAckStatus && (
              <p className="sb-hint sb-hint--tight">
                Last poll: {lastAckStatus.newAcks} new ACK(s). {lastAckStatus.synced}/{lastAckStatus.total} synced.
              </p>
            )}
            <p className="sb-hint sb-hint--tight">Polling every 30 s, and whenever this screen comes back into view.</p>
          </section>

          {pipelineResult && pipelineResult.failed > 0 && (
            <Notice kind="error">
              {pipelineResult.failed}/{pipelineResult.total} storage node(s) failed propagation. Those counterparties may need manual re-sync.
            </Notice>
          )}
        </>
      )}

      {/* Phase: complete — all ACKs received, resume relationships */}
      {phase === 'complete' && (
        <section className="sb-card sb-card--dark sb-card--hero">
          <div className="sb-hero__label">{resumeCount > 0 ? 'Recovery complete' : 'All counterparties synced'}</div>
          <div className="sb-hero__value" style={{ fontSize: 14 }}>
            {resumeCount > 0
              ? `${resumeCount} relationship${resumeCount === 1 ? '' : 's'} restored`
              : 'Ready to resume'}
          </div>
          {resumeCount === 0 && (
            <div className="sb-hero__sub">Resume restores the bilateral relationships, assembles the succession and reconciles recovered assets.</div>
          )}
          <div className="sb-actions" style={{ marginBottom: 0 }}>
            {resumeCount === 0 && (
              <button type="button" className="sb-btn sb-btn--primary" onClick={onResumeAll} disabled={busy}>
                {busy ? 'Resuming…' : 'Resume all'}
              </button>
            )}
            <button type="button" className="sb-btn" onClick={() => void onDone()}>
              {resumeCount > 0 ? 'Done' : 'Back to wallet'}
            </button>
          </div>
        </section>
      )}

      {/* Phase: error */}
      {phase === 'error' && (
        <div className="sb-actions">
          <button type="button" className="sb-btn sb-btn--primary sb-btn--block" onClick={onRetry}>
            Retry
          </button>
        </div>
      )}

      <div className="sb-actions">
        <button type="button" className="sb-btn sb-btn--block" onClick={() => onNavigate?.('settings')}>
          Settings
        </button>
      </div>
    </ScreenFrame>
  );
};

export default memo(RecoveryPipelineScreen);
