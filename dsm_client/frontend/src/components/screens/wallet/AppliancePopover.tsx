// SPDX-License-Identifier: Apache-2.0
// Appliance — the pop-up that connects the DSM Anchor appliance and shows what
// Rust read from it. The first connection needs the user: plug it in, tap
// Connect, and allow it when Android asks. After that Android keeps the
// permission while the appliance stays plugged in, and the send screen
// connects on its own whenever Offline is chosen.
import React, { useEffect, useRef } from 'react';
import { Notice } from '../../common/ScreenFrame';
import { useBackButton } from '../../../hooks/useBackButton';
import type { AnchorStatus } from '../../../dsm/anchor';

/** What the last read of the appliance said, or that none has happened. */
export type ApplianceRead =
  | { kind: 'unread' }
  | { kind: 'read'; status: AnchorStatus }
  | { kind: 'error'; message: string };

type Props = {
  read: ApplianceRead;
  busy: boolean;
  /** Reads the appliance through Rust, which attaches it. */
  onConnect: () => Promise<void>;
  onClose: () => void;
};

export function applianceConnected(read: ApplianceRead): boolean {
  return read.kind === 'read' && read.status.connected;
}

function stateText(read: ApplianceRead): string {
  switch (read.kind) {
    case 'unread':
      return 'Not checked yet';
    case 'read':
      return read.status.statusText || (read.status.connected ? 'Connected' : 'Not connected');
    case 'error':
      return 'Not connected';
  }
}

export function AppliancePopover({ read, busy, onConnect, onClose }: Props): React.JSX.Element {
  const dialogRef = useRef<HTMLDivElement | null>(null);
  useBackButton(true, onClose);
  useEffect(() => {
    dialogRef.current?.focus();
  }, []);
  const connected = applianceConnected(read);

  return (
    <div className="sb-popover-backdrop" onClick={(e) => { e.stopPropagation(); onClose(); }}>
      <div
        ref={dialogRef}
        className="sb-popover sb-card--dark"
        role="dialog"
        aria-modal="true"
        aria-labelledby="appliance-title"
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="sb-popover__head">
          <span className={`sb-dot${connected ? ' sb-dot--on' : ''}`} aria-hidden="true" />
          <h3 id="appliance-title" className="sb-popover__title">Appliance</h3>
          <button type="button" className="sb-popover__close" onClick={onClose} aria-label="Close">{'×'}</button>
        </div>
        <div className="sb-popover__body">
          <p>Offline sends need the <b>DSM Anchor</b> appliance plugged into this phone.</p>
          <ol>
            <li>Plug the appliance into the USB port.</li>
            <li>Tap Connect.</li>
            <li>When Android asks, allow DSM to use it.</li>
          </ol>
          <p>Android asks once. While the appliance stays plugged in, it connects on its own whenever you choose Offline.</p>
          <div className="sb-kv">
            <span className="sb-kv__k">State</span>
            <span className="sb-kv__v" data-testid="appliance-state">{stateText(read)}</span>
          </div>
          {read.kind === 'read' && read.status.connected && (
            <>
              <div className="sb-kv">
                <span className="sb-kv__k">Anchor</span>
                <span className="sb-kv__v sb-kv__v--mono">{read.status.anchorIdB32}</span>
              </div>
              <div className="sb-kv">
                <span className="sb-kv__k">Counter</span>
                <span className="sb-kv__v sb-kv__v--mono">{String(read.status.anchorCounter)}</span>
              </div>
              <div className="sb-kv">
                <span className="sb-kv__k">Frontier</span>
                <span className="sb-kv__v sb-kv__v--mono">{read.status.frontierRootB32}</span>
              </div>
            </>
          )}
          {read.kind === 'error' && <Notice kind="error">{read.message}</Notice>}
        </div>
        <div className="sb-actions" style={{ margin: 0 }}>
          <button type="button" className="sb-btn" onClick={onClose}>Close</button>
          <button type="button" className="sb-btn sb-btn--primary" disabled={busy} onClick={() => void onConnect()}>
            {busy ? 'Connecting…' : connected ? 'Check again' : 'Connect'}
          </button>
        </div>
      </div>
    </div>
  );
}
