// SPDX-License-Identifier: Apache-2.0
/**
 * LockPromptModal — first-launch prompt to set up wallet lock.
 * Shown once on the home screen if lock is not configured and not dismissed.
 * Options: SECURE NOW, LATER (this session), NEVER ASK (persists).
 */

import React, { memo, useEffect, useRef } from 'react';
import type { ScreenType } from '../../types/app';
import { saveLockPrefs } from '../../services/lock/lockService';
import { useBackButton } from '../../hooks/useBackButton';

interface Props {
  onNavigate: (s: ScreenType) => void;
  onDismiss: () => void;
}

function LockPromptModal({ onNavigate, onDismiss }: Props) {
  const dialogRef = useRef<HTMLDivElement | null>(null);

  const handleNever = async () => {
    await saveLockPrefs({ promptDismissed: true }).catch(() => {});
    onDismiss();
  };

  const handleLater = () => {
    onDismiss();
  };

  const handleNow = () => {
    onNavigate('lock_setup');
    onDismiss();
  };

  // B puts the prompt away for this session, as tapping outside does.
  useBackButton(true, handleLater);

  useEffect(() => {
    dialogRef.current?.focus({ preventScroll: true });
  }, []);

  return (
    <div
      className="sb-popover-backdrop"
      // A layer of its own over the whole screen: above the screen host's
      // content (the home screen's chameleon is z 1000), below the tour, which
      // portals above the screen.
      style={{ zIndex: 8000 }}
      onClick={(e) => { if (e.target === e.currentTarget) handleLater(); }}
    >
      <div
        ref={dialogRef}
        className="sb-popover"
        role="dialog"
        aria-modal="true"
        aria-labelledby="lock-prompt-title"
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="sb-popover__head">
          <h3 id="lock-prompt-title" className="sb-popover__title">PROTECT YOUR WALLET?</h3>
        </div>
        <div className="sb-popover__body">
          <p>Set up a PIN or a button combo to lock your wallet. It locks when you leave the app or the screen goes off.</p>
        </div>
        <button type="button" className="sb-btn sb-btn--primary sb-btn--block sb-popover__ok" onClick={handleNow}>
          SECURE NOW
        </button>
        <div className="sb-actions" style={{ margin: 0 }}>
          <button type="button" className="sb-btn" style={{ color: 'var(--bg)', borderColor: 'var(--bg)', background: 'transparent', boxShadow: 'none' }} onClick={handleLater}>
            LATER
          </button>
          <button type="button" className="sb-btn sb-btn--ghost" style={{ color: 'var(--bg)', borderColor: 'rgba(var(--bg-rgb), 0.5)' }} onClick={() => void handleNever()}>
            NEVER ASK
          </button>
        </div>
      </div>
    </div>
  );
}

export default memo(LockPromptModal);
