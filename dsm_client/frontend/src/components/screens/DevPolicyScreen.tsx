/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars, security/detect-object-injection, security/detect-unsafe-regex, no-console, react-hooks/exhaustive-deps */
// SPDX-License-Identifier: Apache-2.0
import React, { useState, useMemo } from 'react';
import { dsmClient } from '../../services/dsmClient';
import { TokenCreationDialog } from '../TokenCreationDialog';
import { useDpadNav } from '../../hooks/useDpadNav';
import './SettingsScreen.css';

export default function DevPolicyScreen(): React.JSX.Element {
  const [policyBase32, setPolicyBase32] = useState('');
  const [status, setStatus] = useState<string>('');
  const [isCreationDialogOpen, setIsCreationDialogOpen] = useState(false);

  const pasteFromClipboard = async () => {
    try {
      if (!navigator?.clipboard?.readText) {
        setStatus('Clipboard API unavailable; paste manually.');
        return;
      }
      const txt = await navigator.clipboard.readText();
      if (!txt) {
        setStatus('Clipboard empty');
        return;
      }
      setPolicyBase32(txt.trim());
      setStatus('Pasted from clipboard');
    } catch (e: any) {
      setStatus(e?.message || 'Clipboard read failed');
    }
  };

  const handlePublish = async () => {
    setStatus('');
    try {
      const out = await dsmClient.publishTokenPolicy({ policyBase32 });
      setStatus(out.success ? `Policy published: ${out.id}` : `Publish failed: ${out.error}`);
    } catch (e: any) {
      setStatus(e?.message || 'Policy publish failed');
    }
  };

  // --- D-pad navigation ---
  // Items: Create Token Policy (0), Publish Policy (1), Paste from Clipboard (2)
  const navActions = useMemo(() => [
    () => setIsCreationDialogOpen(true),
    () => void handlePublish(),
    () => void pasteFromClipboard(),
  // eslint-disable-next-line react-hooks/exhaustive-deps
  ], [policyBase32]);

  const { focusedIndex } = useDpadNav({
    itemCount: navActions.length,
    onSelect: (idx) => navActions[idx]?.(),
  });

  const fc = (idx: number) => (idx === focusedIndex ? ' focused' : '');

  return (
    <div className="settings-shell settings-shell--dev">
      <div className="settings-shell__title">Policy Tools</div>

      <div className="settings-shell__panel">
         <button
           className={`settings-shell__button${fc(0)}`}
           onClick={() => setIsCreationDialogOpen(true)}
           style={{ width: '100%', marginBottom: 4 }}
         >
           Create Token (advanced)
         </button>
         <div style={{ fontSize: 10, color: 'var(--text-disabled)' }}>
          Same wizard as Tokens → + CREATE TOKEN. Defines the token&apos;s CPTA policy (supply, ticker, decimals, burn authority), anchors it, and creates the token bound to that anchor. A token&apos;s whole supply exists at creation: nothing mints more.
         </div>
      </div>

      <div className="settings-shell__stack">
        <div style={{ fontSize: 10, lineHeight: 1.4, color: 'var(--text-dark)', display: 'grid', gap: 4 }}>
          <div>
            Paste the Base32 (Crockford) encoding of serialized <strong>TokenPolicyV3</strong> bytes. They are published exactly as pasted: Rust refuses bytes Core&apos;s policy parser does not accept, and the anchor is the BLAKE3 hash of the bytes.
          </div>
        </div>
        <label style={{ fontSize: 10 }}>
          Token Policy (Base32 Crockford of TokenPolicyV3 bytes)
          <textarea className="settings-input" value={policyBase32} onChange={e => setPolicyBase32(e.target.value)} rows={8} style={{ width: '100%', padding: 6, fontFamily: 'monospace', fontSize: 10, background: 'var(--bg)', color: 'var(--text-dark)', border: '2px solid var(--border)', borderRadius: '4px', outline: 'none' }} />
        </label>
        <div className="settings-shell__button-row">
          <button className={`settings-shell__button${fc(1)}`} onClick={() => void handlePublish()} style={{ fontSize: '9px' }}>Publish Policy</button>
          <button className={`settings-shell__button${fc(2)}`} onClick={() => void pasteFromClipboard()} style={{ fontSize: '9px', background: 'var(--bg-secondary)', color: 'var(--text-dark)' }}>Paste from Clipboard</button>
        </div>
        {status && <div className="settings-shell__status">{status}</div>}
      </div>
      <div className="settings-shell__hint">Press B to go back</div>

      {isCreationDialogOpen && (
        <TokenCreationDialog
          onClose={() => setIsCreationDialogOpen(false)}
          onSuccess={() => {
            setStatus('Token created successfully via interactive dialog');
            setIsCreationDialogOpen(false);
          }}
        />
      )}
    </div>
  );
}
