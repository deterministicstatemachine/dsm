// SPDX-License-Identifier: Apache-2.0

import React, { memo, useCallback, useEffect, useRef, useState } from 'react';
import {
  executePipeline,
  getRecoveryPhase,
  getSyncProgress,
  pollAcks,
  resumeAll,
  type AckStatus,
  type PipelineResult,
  type SyncProgress,
} from '../../services/recovery/nfcRecoveryService';
import './NfcRecoveryScreen.css';

type Phase = 'staged' | 'polling' | 'complete' | 'error' | 'none';

const PHASE_STEPS = ['TOMBSTONE', 'SUCCESSION', 'PROPAGATE', 'SYNCED'] as const;

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
      setPhase('complete');
      setStatusMsg(`Recovery complete. ${result.resumed} relationship(s) restored.`);
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

  const progressIdx = phaseIndex(phase);

  return (
    <div className="nfc-shell" role="main">
      <div className="nfc-header">
        <h2>RECOVERY PIPELINE</h2>
      </div>

      <div className="nfc-stage">
        {/* Phase progress indicator */}
        <div className="nfc-card">
          <div className="nfc-stat-grid">
            {PHASE_STEPS.map((label, i) => {
              const done = i < progressIdx;
              const active = i === progressIdx;
              return (
                <div className="nfc-stat-cell" key={label}>
                  <div
                    className="nfc-stat-val-sm"
                    style={{
                      opacity: done ? 1 : active ? 1 : 0.3,
                      color: done
                        ? 'var(--nfc-panel-text)'
                        : active
                          ? 'var(--nfc-panel-text)'
                          : undefined,
                    }}
                  >
                    {done ? 'DONE' : active ? '...' : '--'}
                  </div>
                  <div className="nfc-stat-label">{label}</div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Phase: none — no capsule staged */}
        {phase === 'none' && (
          <div className="nfc-card">
            <div className="nfc-note nfc-note--strong">
              No recovery capsule has been staged on this device. Go back and stage a capsule from
              the NFC ring first.
            </div>
            <div className="nfc-actions">
              <button className="nfc-btn" onClick={() => onNavigate?.('recovery')}>
                BACK TO RECOVERY
              </button>
            </div>
          </div>
        )}

        {/* Phase: staged — ready to execute */}
        {phase === 'staged' && (
          <div className="nfc-card">
            <div className="nfc-note nfc-note--strong">
              Recovery capsule is staged. Tap RECOVER to execute the full pipeline: create a
              tombstone receipt for the old device, bind this device as the successor, and propagate
              to counterparties.
            </div>
            <div className="nfc-actions">
              <button
                className="nfc-btn"
                onClick={onExecutePipeline}
                disabled={busy}
                style={{ fontWeight: 900, letterSpacing: '1px' }}
              >
                {busy ? 'EXECUTING...' : 'RECOVER'}
              </button>
            </div>
          </div>
        )}

        {/* Phase: polling — waiting for counterparty ACKs */}
        {phase === 'polling' && (
          <>
            <div className="nfc-card">
              <div className="nfc-note nfc-note--strong">
                Tombstone propagated. Waiting for counterparty acknowledgements.
              </div>
              {syncProgress && (
                <div className="nfc-stat-grid">
                  <div className="nfc-stat-cell">
                    <div className="nfc-stat-val">{syncProgress.synced}</div>
                    <div className="nfc-stat-label">Synced</div>
                  </div>
                  <div className="nfc-stat-cell">
                    <div className="nfc-stat-val">{syncProgress.total}</div>
                    <div className="nfc-stat-label">Total</div>
                  </div>
                </div>
              )}
              {lastAckStatus && (
                <div className="nfc-note">
                  Last poll: {lastAckStatus.newAcks} new ACK(s). {lastAckStatus.synced}/
                  {lastAckStatus.total} synced.
                </div>
              )}
              <div className="nfc-note" style={{ opacity: 0.5 }}>
                Auto-polling every 30s. Also polls on screen visibility change.
              </div>
            </div>

            {pipelineResult && pipelineResult.failed > 0 && (
              <div className="nfc-card">
                <div className="nfc-note" style={{ color: 'var(--gb-error, #c00)' }}>
                  {pipelineResult.failed}/{pipelineResult.total} storage node(s) failed propagation.
                  Those counterparties may need manual re-sync.
                </div>
              </div>
            )}
          </>
        )}

        {/* Phase: complete — all ACKs received, resume relationships */}
        {phase === 'complete' && (
          <div className="nfc-card">
            <div className="nfc-note nfc-note--strong">
              {resumeCount > 0
                ? `Recovery complete. ${resumeCount} relationship(s) restored.`
                : 'All counterparties synced. Tap RESUME to restore bilateral relationships.'}
            </div>
            {resumeCount === 0 && (
              <div className="nfc-actions">
                <button
                  className="nfc-btn"
                  onClick={onResumeAll}
                  disabled={busy}
                  style={{ fontWeight: 900, letterSpacing: '1px' }}
                >
                  {busy ? 'RESUMING...' : 'RESUME ALL'}
                </button>
              </div>
            )}
            <div className="nfc-actions">
              <button className="nfc-btn" onClick={() => onNavigate?.('wallet')}>
                {resumeCount > 0 ? 'DONE' : 'BACK TO WALLET'}
              </button>
            </div>
          </div>
        )}

        {/* Phase: error */}
        {phase === 'error' && (
          <div className="nfc-card">
            <div className="nfc-note nfc-note--strong" style={{ color: 'var(--gb-error, #c00)' }}>
              {errorMsg}
            </div>
            <div className="nfc-actions">
              <button className="nfc-btn" onClick={onRetry}>
                RETRY
              </button>
            </div>
          </div>
        )}

        {/* Status message */}
        {statusMsg && phase !== 'error' && (
          <div className="nfc-card">
            <div className="nfc-note nfc-note--strong">{statusMsg}</div>
          </div>
        )}

        {/* Error overlay for non-error phases */}
        {errorMsg && phase !== 'error' && (
          <div className="nfc-card">
            <div className="nfc-note nfc-note--strong" style={{ color: 'var(--gb-error, #c00)' }}>
              {errorMsg}
            </div>
          </div>
        )}

        {/* Navigation */}
        <div className="nfc-card">
          <div className="nfc-actions">
            <button className="nfc-btn" onClick={() => onNavigate?.('recovery')}>
              BACK TO INSPECT
            </button>
            <button className="nfc-btn" onClick={() => onNavigate?.('settings')}>
              SETTINGS
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default memo(RecoveryPipelineScreen);
