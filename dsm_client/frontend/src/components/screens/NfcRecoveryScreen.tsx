// SPDX-License-Identifier: Apache-2.0
// NFC ring backup on the StateBoy frame: the backup status as Rust reports
// it, first-time setup, arming a capsule, and writing it to the ring. The
// mnemonic is shown and typed here, so while the screen is up the phone takes
// no screenshot of it and the keyboard learns nothing from it (useScreenGuard),
// and the words are never offered to the clipboard.

import React, { useCallback, useEffect, useRef, useState, memo } from 'react';
import * as EventBridge from '../../dsm/EventBridge';
import {
  createCapsule,
  disableNfcBackup,
  enableNfcBackup,
  getCapsulePreview,
  getNfcBackupStatus,
  writeToNfcRing,
  type CapsulePreview,
  type NfcBackupStatus,
} from '../../services/recovery/nfcRecoveryService';
import { getNfcBackupUiModel } from '../../services/recovery/nfcBackupUi';
import { Notice, ScreenFrame, middleTruncate } from '../common/ScreenFrame';
import { InfoTip } from '../common/InfoTip';
import { useScreenGuard } from '../../hooks/useScreenGuard';

type SetupMode = 'idle' | 'enable' | 'refresh' | 'writing';

/** The backup status as Rust reported it, the failure of asking, or not asked yet. */
type StatusRead = { status: NfcBackupStatus } | { error: string } | undefined;

interface NfcRecoveryScreenProps {
  onNavigate?: (screen: string) => void;
}

function formatError(error: unknown): string {
  if (error instanceof Error && error.message) return error.message;
  return String(error);
}

const NfcRecoveryScreen: React.FC<NfcRecoveryScreenProps> = ({ onNavigate }) => {
  // No status is shown until Rust has answered: a struct of defaults reads as
  // "not set", the status of a device with no backup at all.
  const [read, setRead] = useState<StatusRead>(undefined);
  const [preview, setPreview] = useState<CapsulePreview>(null);
  const [setupMode, setSetupMode] = useState<SetupMode>('idle');
  const [mnemonicInput, setMnemonicInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [statusMsg, setStatusMsg] = useState('');
  const mountedRef = useRef(true);
  useScreenGuard('secret');

  const status = read && 'status' in read ? read.status : null;

  const refresh = useCallback(async () => {
    try {
      const [nextStatus, nextPreview] = await Promise.all([
        getNfcBackupStatus(),
        getCapsulePreview(),
      ]);
      if (!mountedRef.current) return;
      setRead({ status: nextStatus });
      setPreview(nextPreview);
    } catch (error: unknown) {
      if (!mountedRef.current) return;
      setRead({ error: formatError(error) });
    }
  }, []);

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
        setMnemonicInput('');
        setSetupMode('idle');
        await refresh();
      } catch (error: unknown) {
        setStatusMsg(`Recovery backup failed: ${formatError(error)}`);
      } finally {
        setBusy(false);
      }
    },
    [refresh],
  );

  const onToggleBackup = useCallback(async () => {
    if (busy || !status) return;

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

    setSetupMode('enable');
    setStatusMsg('');
  }, [busy, refresh, status]);


  const onWriteNow = useCallback(async () => {
    if (busy || !status) return;
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
  }, [busy, refresh, status]);

  const nfcUi = status ? getNfcBackupUiModel(status) : null;
  const latestCapsuleLabel = status && status.capsuleCount > 0
    ? `#${status.lastCapsuleIndex}`
    : '--';
  const writeButtonLabel = !status || !status.enabled
    ? 'Write latest capsule'
    : status.pendingCapsule
      ? 'Write to ring'
      : 'Rebuild & write';

  return (
    <ScreenFrame
      title="NFC Ring Backup"
      onBack={() => onNavigate?.('settings')}
      className="nfc-recovery-screen"
      info={(
        <InfoTip title="How it works">
          <p>1. Enter or confirm your recovery mnemonic. 2. Arm a capsule. 3. Press write and hold the ring to the phone. A vibration means the write committed.</p>
          <p>After a successful write the ring keeps that capsule; this phone re-arms only after the next accepted state change or a manual rebuild.</p>
          <p>Rebuilding arms a fresh capsule in Rust. It does not write to the ring until you press the write action.</p>
        </InfoTip>
      )}
      banner={statusMsg ? (
        <Notice banner onClose={() => setStatusMsg('')}>{statusMsg}</Notice>
      ) : null}
    >
      {/* Status dashboard: as Rust reported it, or why it could not */}
      {read === undefined ? (
        <div className="sb-empty">Reading the backup status{'…'}</div>
      ) : 'error' in read ? (
        <>
          <Notice kind="error">Status not read: {read.error}</Notice>
          <div className="sb-actions">
            <button type="button" className="sb-btn sb-btn--primary" onClick={() => { setRead(undefined); void refresh(); }}>
              Try Again
            </button>
          </div>
        </>
      ) : nfcUi && (
        <section className="sb-card sb-card--dark" aria-label="Backup status">
          <div className="sb-stats sb-stats--4">
            <div className="sb-stats__cell">
              <div className="sb-stats__val sb-stats__val--sm">{nfcUi.backupLabel}</div>
              <div className="sb-stats__label">Backup</div>
            </div>
            <div className="sb-stats__cell">
              <div className="sb-stats__val sb-stats__val--sm">{nfcUi.writeStateLabel}</div>
              <div className="sb-stats__label">Write</div>
            </div>
            <div className="sb-stats__cell">
              <div className="sb-stats__val">{latestCapsuleLabel}</div>
              <div className="sb-stats__label">Capsule</div>
            </div>
            <div className="sb-stats__cell">
              <div className="sb-stats__val sb-stats__val--sm">{nfcUi.nextActionLabel}</div>
              <div className="sb-stats__label">Next</div>
            </div>
          </div>
          <p className="sb-hint sb-hint--tight" style={{ marginTop: 8 }}>{nfcUi.detailSummary}</p>
        </section>
      )}

      {/* Mnemonic input (enable or refresh) */}
      {(setupMode === 'enable' || setupMode === 'refresh') && (
        <section className="sb-card">
          <div className="sb-card__title">
            {setupMode === 'refresh' ? 'Rebuild the latest capsule' : "Enter this wallet's recovery phrase"}
          </div>
          <p className="sb-hint">The 24 words written down when this wallet was made. Backup is armed only with this wallet's own phrase.</p>
          <div className="sb-field">
            <label htmlFor="nfc-mnemonic">Recovery mnemonic</label>
            <textarea
              id="nfc-mnemonic"
              className="sb-input sb-input--mono"
              value={mnemonicInput}
              onChange={(e) => setMnemonicInput(e.target.value)}
              placeholder="word1 word2 word3 ..."
              rows={4}
              autoComplete="off"
              autoCorrect="off"
              autoCapitalize="none"
              spellCheck={false}
            />
          </div>
          <div className="sb-actions" style={{ margin: 0 }}>
            <button type="button" className="sb-btn" onClick={() => { setSetupMode('idle'); setMnemonicInput(''); }} disabled={busy}>
              Cancel
            </button>
            <button
              type="button"
              className="sb-btn sb-btn--primary"
              onClick={() => void submitMnemonic(setupMode === 'refresh' ? 'refresh' : 'enable', mnemonicInput)}
              disabled={busy || mnemonicInput.trim().split(/\s+/).length < 12}
            >
              {busy ? 'Working…' : setupMode === 'refresh' ? 'Rebuild capsule' : 'Enable backup'}
            </button>
          </div>
        </section>
      )}

      {/* Writing mode — "ready to write" prompt */}
      {setupMode === 'writing' && (
        <section className="sb-card sb-card--dark sb-card--hero" aria-live="polite">
          <div className="sb-hero__label">Ready to write</div>
          <div className="sb-hero__value" style={{ fontSize: 14 }}>Hold the ring to the back of the phone</div>
          <div className="sb-hero__sub">A vibration means the write committed. Do not move the ring until then.</div>
          <div className="sb-actions" style={{ marginBottom: 0 }}>
            <button type="button" className="sb-btn sb-btn--block" onClick={() => { setSetupMode('idle'); setStatusMsg('Write cancelled.'); }}>
              Cancel
            </button>
          </div>
        </section>
      )}

      {/* Main actions — only when idle and the status is known */}
      {setupMode === 'idle' && status && (
        <div className="sb-actions">
          <button type="button" className={`sb-btn${status.enabled ? '' : ' sb-btn--primary'}`} onClick={onToggleBackup} disabled={busy}>
            {busy ? '…' : status.enabled ? 'Disable backup' : status.configured ? 'Re-enable' : 'Set up'}
          </button>
          {status.enabled && (
            <button type="button" className="sb-btn sb-btn--primary" onClick={onWriteNow} disabled={busy}>
              {writeButtonLabel}
            </button>
          )}
        </div>
      )}

      {/* Local capsule snapshot — only when idle */}
      {setupMode === 'idle' && preview && (
        <section className="sb-card">
          <div className="sb-card__title">Local capsule snapshot</div>
          <div className="sb-kv">
            <span className="sb-kv__k">Capsule</span>
            <span className="sb-kv__v">#{preview.capsuleIndex}</span>
          </div>
          <div className="sb-kv">
            <span className="sb-kv__k">Peers</span>
            <span className="sb-kv__v">{preview.counterpartyCount}</span>
          </div>
          <div className="sb-kv">
            <span className="sb-kv__k">SMT root</span>
            <span className="sb-kv__v sb-kv__v--mono">{middleTruncate(preview.smtRoot || 'UNKNOWN', 10, 8)}</span>
          </div>
        </section>
      )}

      {setupMode === 'idle' && (
        <div className="sb-actions">
          <button type="button" className="sb-btn sb-btn--block" onClick={() => onNavigate?.('recovery')}>
            Inspect or recover a ring
          </button>
        </div>
      )}
    </ScreenFrame>
  );
};

export default memo(NfcRecoveryScreen);
