// SPDX-License-Identifier: Apache-2.0
// The small Back up button on the send screen (owner, 2026-11-24): shown only
// to a wallet set to back up by hand. Rust takes and writes the backup; the
// button shows what it answers.
import React, { useEffect, useState } from 'react';
import { useAppRuntimeStore } from '../../runtime/appRuntimeStore';
import { backUpNow } from '../../dsm/backup';
import { loadBackupMode } from '../../runtime/skinPreferences';

type Pressed = { phase: 'idle'; said: string } | { phase: 'backing_up' };

export function BackupNowButton({ className }: { className?: string }): React.JSX.Element | null {
  const runtime = useAppRuntimeStore();
  const [pressed, setPressed] = useState<Pressed>({ phase: 'idle', said: '' });
  const [unread, setUnread] = useState<string>('');
  useEffect(() => {
    loadBackupMode().then(
      () => setUnread(''),
      (e: unknown) => setUnread(e instanceof Error ? e.message : String(e)),
    );
  }, []);
  if (unread !== '') {
    return (
      <div className={className} data-testid="backup-now">
        <span className="sb-hint sb-hint--tight" role="status">The backup setting was not read: {unread}</span>
      </div>
    );
  }
  if (runtime.backupMode !== 'manual') return null;
  const press = () => {
    setPressed({ phase: 'backing_up' });
    backUpNow().then(
      (words) => setPressed({ phase: 'idle', said: words }),
      (e: unknown) => setPressed({ phase: 'idle', said: e instanceof Error ? e.message : String(e) }),
    );
  };
  return (
    <div className={className} data-testid="backup-now">
      <button
        type="button"
        className="sb-btn sb-btn--small"
        onClick={press}
        disabled={pressed.phase === 'backing_up'}
        aria-label="Back up this wallet now"
      >
        {pressed.phase === 'backing_up' ? 'Backing up…' : 'Back up'}
      </button>
      {pressed.phase === 'idle' && pressed.said !== '' ? (
        <span className="sb-hint sb-hint--tight" role="status"> {pressed.said}</span>
      ) : null}
    </div>
  );
}
