/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars, security/detect-object-injection, security/detect-unsafe-regex, no-console, react-hooks/exhaustive-deps */
// SPDX-License-Identifier: Apache-2.0
import React, { useState, useMemo } from 'react';
import { dsmClient } from '../../services/dsmClient';
import { TokenCreationDialog } from '../TokenCreationDialog';
import { useDpadNav } from '../../hooks/useDpadNav';
import './SettingsScreen.css';

export default function DevPolicyScreen(): JSX.Element {
  const [policyBase32, setPolicyBase32] = useState('');
  const [status, setStatus] = useState<string>('');
  const [isCreationDialogOpen, setIsCreationDialogOpen] = useState(false);
  const examplePolicyBase32 =
    '189P8SBP81JQGRBDE1P6ABK9DSV62V39CG91J2GQ189P8SBP81JQGRBDE1P6ABK9DSV62V39CG8024GR38B0M13DD5Q782G4C9TQ4VGA11T74RBEEDK6AWGT3G50CTBKEDTPAWGJ0S4Q6WVNCNS1M13DD5Q786G4C9TQ4VGT3850CT3FDHJ6AWGJ0S46YV34CNS1M23ME9GPWWV6CNS0';

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
      setStatus(out?.success ? `Policy published: ${out?.id ?? 'ok'}` : `Publish failed: ${out?.error ?? 'unknown'}`);
    } catch (e: any) {
      setStatus(e?.message || 'Policy publish failed');
    }
  };

  // --- D-pad navigation ---
  // Items: Create Token Policy (0), Publish Policy (1), Load Example (2), Paste from Clipboard (3)
  const navActions = useMemo(() => [
    () => setIsCreationDialogOpen(true),
    () => void handlePublish(),
    () => setPolicyBase32(examplePolicyBase32),
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
           Create Token Policy + Token
         </button>
         <div style={{ fontSize: 10, color: 'var(--text-disabled)' }}>
          Define a CPTA token policy (supply, ticker, decimals, permissions), publish it, then mint a token bound to that policy.
         </div>
      </div>

      <div className="settings-shell__stack">
        <div style={{ fontSize: 10, lineHeight: 1.4, color: 'var(--text-dark)', display: 'grid', gap: 4 }}>
          <div>
            Paste the Base32 (Crockford) encoding of a <strong>CanonicalPolicy</strong> protobuf message. The bytes must already be serialized via the proto definition (no JSON/YAML). If the payload is not a valid CanonicalPolicy, publish will fail with a clear error.
          </div>
          <div style={{ display: 'grid', gap: 2, marginLeft: 8 }}>
            <div><strong>How to build a CanonicalPolicy</strong></div>
            <div>1) Set <code>author</code> to your canonical identity string.</div>
            <div>2) Define <code>roles</code> with stable <code>id</code>, human-readable <code>name</code>, and sorted <code>permissions</code> (e.g., mint, burn, transfer).</div>
            <div>3) Add <code>conditions</code> (choose oneof per entry): identity constraints, vault enforcement, operation restrictions, geographic or logical time constraints, emissions schedule, credit bundle policy, or custom constraints.</div>
            <div>4) Serialize the message via the protobuf schema (<code>proto/dsm_app.proto</code> &rarr; message <code>CanonicalPolicy</code>) and Base32-Crockford encode the resulting bytes.</div>
            <div style={{ marginTop: 2 }}>
              Termux/CLI helper (from <code>dsm_client/new_frontend</code>):
              <div style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                <code>{`npx ts-node -O '{"module":"commonjs","esModuleInterop":true}' scripts/examples/gen_canonical_policy.ts`}</code>
              </div>
              Create your own script by importing <code>CanonicalPolicy</code> and <code>encodeBase32Crockford</code> from <code>src/utils/textId</code>, then printing <code>encodeBase32Crockford(policy.toBinary())</code>.
            </div>
          </div>
        </div>
        <label style={{ fontSize: 10 }}>
          Token Policy (Base32 Crockford of CanonicalPolicy proto bytes)
          <textarea className="settings-input" value={policyBase32} onChange={e => setPolicyBase32(e.target.value)} rows={8} style={{ width: '100%', padding: 6, fontFamily: 'monospace', fontSize: 10, background: 'var(--bg)', color: 'var(--text-dark)', border: '2px solid var(--border)', borderRadius: '4px', outline: 'none' }} />
        </label>
        <div className="settings-shell__button-row">
          <button className={`settings-shell__button${fc(1)}`} onClick={() => void handlePublish()} style={{ fontSize: '9px' }}>Publish Policy</button>
          <button className={`settings-shell__button${fc(2)}`} onClick={() => setPolicyBase32(examplePolicyBase32)} style={{ fontSize: '9px', background: 'var(--bg-secondary)', color: 'var(--text-dark)' }}>Load Example CanonicalPolicy</button>
          <button className={`settings-shell__button${fc(3)}`} onClick={() => void pasteFromClipboard()} style={{ fontSize: '9px', background: 'var(--bg-secondary)', color: 'var(--text-dark)' }}>Paste from Clipboard</button>
        </div>
        <div className="settings-shell__info">
          <div style={{ fontWeight: 'bold', marginBottom: 4 }}>Example CanonicalPolicy (Base32)</div>
          <div className="settings-shell__mono">{examplePolicyBase32}</div>
          <div style={{ marginTop: 4 }}>
            Fields: author=<code>dev@example.invalid</code>, roles [issuer: mint/burn, holder: transfer], conditions [identity constraint allowing dev@example.invalid (and derived), operation restriction allowing mint/burn/transfer].
          </div>
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
