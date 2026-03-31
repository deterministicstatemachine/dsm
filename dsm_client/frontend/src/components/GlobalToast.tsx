import React, { useEffect } from 'react';
import { useUX } from '@/contexts/UXContext';

// Auto-dismiss duration in ms. Errors linger a bit longer.
const DISMISS_MS = 3000;
const DISMISS_MS_ERROR = 5000;

const GlobalToast: React.FC = () => {
  const { globalToast, clearToast } = useUX();

  useEffect(() => {
    if (!globalToast) return;
    const delay = (globalToast.type === 'error' || globalToast.type === 'warning') ? DISMISS_MS_ERROR : DISMISS_MS;
    const id = setTimeout(() => clearToast(), delay);
    return () => clearTimeout(id);
  }, [globalToast, clearToast]);

  if (!globalToast) return null;
  const { type, message } = globalToast;
  const label = message ?? (
    type === 'transfer_accepted' ? 'Transfer accepted' :
    type === 'transaction_sent' ? 'Transaction sent' :
    type === 'exit_completed' ? 'Withdrawal completed' :
    type === 'inbox_received' ? 'New inbox item received' :
    'Refreshed'
  );
  return (
    <div
      className="wallet-toast"
      role="status"
      style={{
        position: 'absolute',
        bottom: 'calc(var(--nav-bar-height, 60px) + env(safe-area-inset-bottom, 0px) + 12px)',
        left: 12,
        right: 12,
        maxWidth: 'calc(100vw - 24px)',
        boxSizing: 'border-box' as const,
        zIndex: 9999,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: 12,
        padding: '10px 12px',
        border: '2px solid var(--border)',
        background: 'rgba(var(--text-rgb), 0.92)',
        color: 'var(--bg)',
        fontSize: 12,
      }}
    >
      <span style={{ lineHeight: 1.3, overflow: 'hidden', textOverflow: 'ellipsis', minWidth: 0, flex: 1 }}>{label}</span>
      <button className="dismiss-feedback" onClick={() => clearToast()} aria-label="Dismiss" style={{ minWidth: 28, minHeight: 28, flexShrink: 0, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', fontSize: 16, background: 'transparent', border: 'none', color: 'inherit' }}>X</button>
    </div>
  );
};

export default GlobalToast;
