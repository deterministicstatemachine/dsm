// SPDX-License-Identifier: Apache-2.0
// Policy tools (developer options): the token-creation wizard, and publishing
// a TokenPolicyV3 exactly as pasted. Rust refuses bytes Core's policy parser
// does not accept; the anchor is the BLAKE3 hash of the bytes.
import React, { useState, useMemo, useCallback } from 'react';
import { dsmClient } from '../../services/dsmClient';
import { TokenCreationDialog } from '../TokenCreationDialog';
import { useDpadNav } from '../../hooks/useDpadNav';
import { Notice, ScreenFrame } from '../common/ScreenFrame';
import { InfoTip } from '../common/InfoTip';

function messageOf(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export default function DevPolicyScreen(): React.JSX.Element {
  const [policyBase32, setPolicyBase32] = useState('');
  const [status, setStatus] = useState<{ kind: 'info' | 'error' | 'success'; text: string } | null>(null);
  const [isCreationDialogOpen, setIsCreationDialogOpen] = useState(false);

  const pasteFromClipboard = useCallback(async () => {
    try {
      if (!navigator?.clipboard?.readText) {
        setStatus({ kind: 'error', text: 'Clipboard API unavailable; paste manually.' });
        return;
      }
      const txt = await navigator.clipboard.readText();
      if (!txt) {
        setStatus({ kind: 'info', text: 'Clipboard empty' });
        return;
      }
      setPolicyBase32(txt.trim());
      setStatus({ kind: 'success', text: 'Pasted from clipboard' });
    } catch (e) {
      setStatus({ kind: 'error', text: messageOf(e) || 'Clipboard read failed' });
    }
  }, []);

  const handlePublish = useCallback(async () => {
    setStatus(null);
    try {
      const out = await dsmClient.publishTokenPolicy({ policyBase32 });
      setStatus(out.success
        ? { kind: 'success', text: `Policy published: ${out.id}` }
        : { kind: 'error', text: `Publish failed: ${out.error}` });
    } catch (e) {
      setStatus({ kind: 'error', text: messageOf(e) || 'Policy publish failed' });
    }
  }, [policyBase32]);

  // --- D-pad navigation ---
  // Items: Create Token (0), Publish Policy (1), Paste from Clipboard (2)
  const navActions = useMemo(() => [
    () => setIsCreationDialogOpen(true),
    () => void handlePublish(),
    () => void pasteFromClipboard(),
  ], [handlePublish, pasteFromClipboard]);

  const { focusedIndex } = useDpadNav({
    itemCount: navActions.length,
    onSelect: (idx) => navActions[idx]?.(),
  });

  const fc = (idx: number) => (idx === focusedIndex ? ' focused' : '');

  return (
    <ScreenFrame
      title="Policy Tools"
      info={(
        <InfoTip title="Policy tools">
          <p><b>Create Token</b> is the same wizard as Tokens → Create Token: it defines the token&apos;s CPTA policy (supply, ticker, decimals, burn authority), anchors it, and creates the token bound to that anchor. A token&apos;s whole supply exists at creation; nothing mints more.</p>
          <p><b>Publish Policy</b> takes the Base32 (Crockford) encoding of serialized TokenPolicyV3 bytes and publishes them exactly as pasted. Rust refuses bytes Core&apos;s policy parser does not accept. The anchor is the BLAKE3 hash of the bytes.</p>
        </InfoTip>
      )}
      banner={status ? (
        <Notice banner kind={status.kind} onClose={() => setStatus(null)}>{status.text}</Notice>
      ) : null}
    >
      <section className="sb-card">
        <div className="sb-card__title">Create a token</div>
        <button
          type="button"
          className={`sb-btn sb-btn--primary sb-btn--block${fc(0)}`}
          onClick={() => setIsCreationDialogOpen(true)}
        >
          Create Token (advanced)
        </button>
      </section>

      <section className="sb-card">
        <div className="sb-card__title">Publish a policy</div>
        <div className="sb-field">
          <label htmlFor="policy-base32">TokenPolicyV3 bytes, Base32 Crockford</label>
          <textarea
            id="policy-base32"
            className="sb-input sb-input--mono"
            value={policyBase32}
            onChange={(e) => setPolicyBase32(e.target.value)}
            rows={6}
            spellCheck={false}
          />
        </div>
        <div className="sb-actions" style={{ margin: 0 }}>
          <button
            type="button"
            className={`sb-btn${fc(2)}`}
            onClick={() => void pasteFromClipboard()}
          >
            Paste
          </button>
          <button
            type="button"
            className={`sb-btn sb-btn--primary${fc(1)}`}
            onClick={() => void handlePublish()}
            disabled={!policyBase32.trim()}
          >
            Publish Policy
          </button>
        </div>
      </section>

      {isCreationDialogOpen && (
        <TokenCreationDialog
          onClose={() => setIsCreationDialogOpen(false)}
          onSuccess={() => {
            setStatus({ kind: 'success', text: 'Token created' });
            setIsCreationDialogOpen(false);
          }}
        />
      )}
    </ScreenFrame>
  );
}
