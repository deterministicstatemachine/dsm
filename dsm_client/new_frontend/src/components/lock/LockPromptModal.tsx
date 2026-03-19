// SPDX-License-Identifier: Apache-2.0
/**
 * LockPromptModal — first-launch prompt to set up wallet lock.
 * Shown once on the home screen if lock is not configured and not dismissed.
 * Options: SECURE NOW, LATER (this session), NEVER ASK (persists).
 */

import React, { memo } from 'react';
import type { ScreenType } from '../../types/app';
import { saveLockPrefs } from '../../services/lock/lockService';

interface Props {
  onNavigate: (s: ScreenType) => void;
  onDismiss: () => void;
}

function LockPromptModal({ onNavigate, onDismiss }: Props) {
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

  return (
    <div
      style={{
        position: 'absolute',
        inset: 0,
        zIndex: 8000,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'transparent',
      }}
      onClick={(e) => { if (e.target === e.currentTarget) handleLater(); }}
    >
      <div
        style={{
          background: 'var(--bg, #9bbc0f)',
          border: '2px solid var(--border, #306230)',
          borderRadius: '6px',
          padding: '20px 16px',
          width: '260px',
          display: 'flex',
          flexDirection: 'column',
          gap: '10px',
          fontFamily: "'Martian Mono', monospace",
          color: 'var(--text-dark, #0f380f)',
        }}
      >
        <div style={{ fontSize: '11px', fontWeight: 'bold', letterSpacing: '2px', textAlign: 'center' }}>
          PROTECT YOUR WALLET?
        </div>
        <div style={{ fontSize: '8px', letterSpacing: '1px', lineHeight: '1.5', textAlign: 'center', opacity: 0.8 }}>
          SET UP A PIN, BIOMETRIC, OR<br />
          BUTTON COMBO TO LOCK YOUR WALLET.<br />
          LOCKS IMMEDIATELY ON EXIT OR SCREEN OFF.
        </div>
        <button
          className="settings-action-btn"
          onClick={handleNow}
          style={{ fontSize: '10px', fontWeight: 'bold' }}
        >
          SECURE NOW
        </button>
        <button
          className="settings-action-btn"
          onClick={handleLater}
          style={{ fontSize: '9px' }}
        >
          LATER
        </button>
        <button
          className="settings-action-btn"
          onClick={() => void handleNever()}
          style={{ fontSize: '8px', opacity: 0.7 }}
        >
          NEVER ASK
        </button>
      </div>
    </div>
  );
}

export default memo(LockPromptModal);
