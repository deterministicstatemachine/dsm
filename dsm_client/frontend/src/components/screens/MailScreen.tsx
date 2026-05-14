// SPDX-License-Identifier: Apache-2.0
// Mail screen — posted-DLV inbox + compose, accessible from the home
// MAIL brick.  Replaces DevPostedInboxScreen + DevPostedSendScreen.
//
// Inbox sub-tab: list active advertisements addressed to this device's
// Kyber pk; per-row Claim button; bulk Refresh + Sync All.
//
// Compose sub-tab: paste recipient Kyber pk Base32, optional token + amount,
// content textarea, Send button → ConfirmModal → toast on success.
//
// All cryptographic work stays Rust-side (Track C.4 accept-or-stamp on
// dlv.create + claim).

import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  listPostedDlvs,
  syncPostedDlvs,
  claimPostedDlv,
  type PostedDlvSummary,
} from '../../dsm/posted_dlv';
import { createPostedDlv } from '../../dsm/dlv';
import { decodeBase32Crockford } from '../../utils/textId';
import ConfirmModal from '../ConfirmModal';
import '../../styles/EnhancedWallet.css';

type RowStatus = 'pending' | 'syncing' | 'mirrored' | 'claiming' | 'claimed' | 'error';
type RowState = { status: RowStatus; detail?: string };
type Tab = 'inbox' | 'compose';
type SendPhase = 'idle' | 'sending' | 'sent' | 'error';

interface Props {
  onNavigate?: (screen: string) => void;
}

function bigIntFromString(s: string): bigint {
  if (!/^[0-9]+$/.test(s)) throw new Error('amount must be a non-negative integer');
  return BigInt(s);
}

export default function MailScreen({ onNavigate }: Props): JSX.Element {
  const [tab, setTab] = useState<Tab>('inbox');

  // Inbox state
  const [pending, setPending] = useState<PostedDlvSummary[]>([]);
  const [rowState, setRowState] = useState<Record<string, RowState>>({});
  const [inboxBusy, setInboxBusy] = useState(false);
  const [inboxStatus, setInboxStatus] = useState<string>('');
  const [inboxError, setInboxError] = useState<string>('');

  // Compose state
  const [recipientPk, setRecipientPk] = useState('');
  const [tokenId, setTokenId] = useState('');
  const [amount, setAmount] = useState('');
  const [policyAnchor, setPolicyAnchor] = useState('');
  const [content, setContent] = useState('Hello');
  const [sendPhase, setSendPhase] = useState<SendPhase>('idle');
  const [sendStatus, setSendStatus] = useState<string>('');
  const [sendError, setSendError] = useState<string>('');
  const [showSendConfirm, setShowSendConfirm] = useState(false);

  const refreshInbox = useCallback(async () => {
    setInboxBusy(true);
    setInboxError('');
    setInboxStatus('');
    const r = await listPostedDlvs();
    if (r.success) {
      const list = r.vaults ?? [];
      setPending(list);
      setRowState((prev) => {
        const next: Record<string, RowState> = {};
        for (const v of list) {
          next[v.dlvIdBase32] = prev[v.dlvIdBase32] ?? { status: 'pending' };
        }
        return next;
      });
      setInboxStatus(`${list.length} pending DLV(s)`);
    } else {
      setInboxError(r.error || 'listPostedDlvs failed');
    }
    setInboxBusy(false);
  }, []);

  useEffect(() => {
    if (tab === 'inbox') {
      void refreshInbox();
    }
  }, [tab, refreshInbox]);

  const handleSyncAll = useCallback(async () => {
    setInboxBusy(true);
    setInboxError('');
    // Mark all currently-pending rows as syncing for visible feedback.
    setRowState((prev) => {
      const next = { ...prev };
      for (const v of pending) {
        if (next[v.dlvIdBase32]?.status === 'pending') {
          next[v.dlvIdBase32] = { status: 'syncing' };
        }
      }
      return next;
    });
    const r = await syncPostedDlvs();
    if (r.success) {
      const mirrored = new Set(r.newlyMirroredBase32 ?? []);
      setRowState((prev) => {
        const next = { ...prev };
        for (const v of pending) {
          if (mirrored.has(v.dlvIdBase32) || next[v.dlvIdBase32]?.status === 'syncing') {
            next[v.dlvIdBase32] = { status: 'mirrored' };
          }
        }
        return next;
      });
      setInboxStatus(`Synced ${r.newlyMirroredBase32?.length ?? 0} new vault(s)`);
    } else {
      setInboxError(r.error || 'syncPostedDlvs failed');
    }
    setInboxBusy(false);
  }, [pending]);

  const handleClaim = useCallback(async (vaultIdBase32: string) => {
    setRowState((prev) => ({ ...prev, [vaultIdBase32]: { status: 'claiming' } }));
    setInboxError('');
    try {
      const vaultBytes = decodeBase32Crockford(vaultIdBase32);
      if (vaultBytes.length !== 32) {
        throw new Error(`vault id wrong length: ${vaultBytes.length}`);
      }
      const r = await claimPostedDlv({ vaultId: vaultBytes });
      if (!r.success) throw new Error(r.error || 'claim failed');
      setRowState((prev) => ({ ...prev, [vaultIdBase32]: { status: 'claimed' } }));
      setInboxStatus(`Claimed ${vaultIdBase32.slice(0, 12)}…`);
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'claim failed';
      setRowState((prev) => ({ ...prev, [vaultIdBase32]: { status: 'error', detail: msg } }));
      setInboxError(msg);
    }
  }, []);

  const composeValid = useMemo(() => {
    return recipientPk.trim().length > 0 && policyAnchor.trim().length > 0 && content.trim().length > 0;
  }, [recipientPk, policyAnchor, content]);

  const handleSend = useCallback(async () => {
    setSendError('');
    setSendStatus('');
    try {
      setSendPhase('sending');
      const recipientBytes = decodeBase32Crockford(recipientPk.trim());
      if (recipientBytes.length === 0) {
        throw new Error('recipient public key did not decode');
      }
      const policyBytes = decodeBase32Crockford(policyAnchor.trim());
      if (policyBytes.length !== 32) {
        throw new Error(`policy anchor must decode to 32 bytes (got ${policyBytes.length})`);
      }
      let lockedAmount: bigint | undefined;
      if (amount.trim().length > 0) {
        lockedAmount = bigIntFromString(amount.trim());
      }
      const r = await createPostedDlv({
        recipientKyberPk: recipientBytes,
        policyDigest: policyBytes,
        tokenId: tokenId.trim() || undefined,
        lockedAmount,
        content: new TextEncoder().encode(content),
      });
      if (!r.success || !r.id) throw new Error(r.error || 'createPostedDlv failed');
      setSendPhase('sent');
      setSendStatus(`Sent. id=${r.id.slice(0, 12)}…`);
      // Reset compose state and switch to inbox so the user can see it land.
      setRecipientPk('');
      setTokenId('');
      setAmount('');
      setPolicyAnchor('');
      setContent('Hello');
      setTab('inbox');
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'send failed';
      setSendError(msg);
      setSendPhase('error');
    }
  }, [recipientPk, policyAnchor, content, tokenId, amount]);

  return (
    <div className="enhanced-wallet-screen" style={{ position: 'relative' }}>
      <div className="wallet-header">
        <h2>Mail</h2>
        <div className="header-buttons" style={{ display: 'flex', gap: 8 }}>
          <button
            type="button"
            onClick={() => onNavigate?.('home')}
            className="cancel-button"
            style={{ fontSize: 11, padding: '4px 10px' }}
          >
            Back
          </button>
          {tab === 'inbox' && (
            <button
              type="button"
              onClick={() => void refreshInbox()}
              disabled={inboxBusy}
              className="refresh-icon"
              aria-label="Refresh inbox"
              title="Refresh"
              style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', padding: 6, border: '1px solid var(--border)', borderRadius: 4, background: 'transparent' }}
            >
              <img src="images/icons/icon_refresh.svg" alt="Refresh" style={{ width: 16, height: 16, imageRendering: 'pixelated' }} />
            </button>
          )}
        </div>
      </div>

      {/* Cross-tab send banners — keep send feedback visible after the
       * post-send tab switch so the user always gets confirmation. */}
      {sendError && (
        <div className="error-banner" style={{ padding: '8px 12px', margin: '0 0 8px', background: 'rgba(255,0,0,0.08)', border: '2px dashed var(--border)', fontSize: 12 }}>
          {sendError}
        </div>
      )}
      {sendStatus && !sendError && (
        <div className="warning-banner" style={{ padding: '8px 12px', margin: '0 0 8px', background: 'rgba(var(--text-rgb),0.08)', border: '1px solid var(--border)', fontSize: 12 }} role="status" aria-live="polite">
          {sendStatus}
        </div>
      )}

      <div className="tab-navigation">
        {(['inbox', 'compose'] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`tab-button ${tab === t ? 'active' : ''}`}
          >
            {t === 'inbox' ? 'Inbox' : 'Compose'}
          </button>
        ))}
      </div>

      <div className="tab-content">
        {tab === 'inbox' && (
          <>
            {inboxError && (
              <div className="error-banner" style={{ padding: '8px 12px', marginBottom: 8, background: 'rgba(255,0,0,0.08)', border: '2px dashed var(--border)', fontSize: 12 }}>
                {inboxError}
              </div>
            )}
            {inboxStatus && !inboxError && (
              <div className="warning-banner" style={{ padding: '8px 12px', marginBottom: 8, background: 'rgba(var(--text-rgb),0.08)', border: '1px solid var(--border)', fontSize: 12 }} role="status" aria-live="polite">
                {inboxStatus}
              </div>
            )}
            <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
              <button type="button" className="send-button button-brick" onClick={() => void handleSyncAll()} disabled={inboxBusy || pending.length === 0}>
                {inboxBusy ? 'Syncing…' : 'Sync all'}
              </button>
            </div>
            {pending.length === 0 && !inboxBusy && (
              <div className="empty-state">
                <p>No pending posted DLVs.</p>
                <p style={{ fontSize: 10, opacity: 0.7 }}>Tap Refresh to check storage nodes.</p>
              </div>
            )}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {pending.map((v) => {
                const st = rowState[v.dlvIdBase32]?.status ?? 'pending';
                const detail = rowState[v.dlvIdBase32]?.detail;
                const claimable = st === 'mirrored';
                return (
                  <div key={v.dlvIdBase32} className="balance-card" style={{ padding: '8px 12px' }}>
                    <div className="balance-info">
                      <span className="token-symbol">{v.dlvIdBase32.slice(0, 16)}…</span>
                      <span className="balance-amount" data-row-status={st}>{st}</span>
                    </div>
                    <div style={{ fontSize: 10, opacity: 0.7, marginTop: 4 }}>
                      from {v.creatorPublicKeyBase32.slice(0, 16)}…
                    </div>
                    {detail && (
                      <div style={{ fontSize: 10, color: 'var(--error, #c00)', marginTop: 4 }}>{detail}</div>
                    )}
                    <div style={{ marginTop: 6 }}>
                      <button
                        type="button"
                        className="send-button button-brick"
                        disabled={!claimable}
                        onClick={() => void handleClaim(v.dlvIdBase32)}
                      >
                        {st === 'claiming' ? 'Claiming…' : st === 'claimed' ? 'Claimed ✓' : 'Claim'}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </>
        )}

        {tab === 'compose' && (
          <>
            <div className="form-group">
              <label htmlFor="mail-recipient">Recipient (Kyber-1024 pk, Base32 Crockford)</label>
              <textarea id="mail-recipient" className="form-input" rows={3} value={recipientPk} onChange={(e) => setRecipientPk(e.target.value)} placeholder="paste 2500-char Base32" />
            </div>
            <div className="form-group">
              <label htmlFor="mail-policy">Policy anchor (32 bytes Base32 Crockford)</label>
              <textarea id="mail-policy" className="form-input" rows={2} value={policyAnchor} onChange={(e) => setPolicyAnchor(e.target.value)} placeholder="paste 52-char Base32" />
            </div>
            <div className="form-group">
              <label htmlFor="mail-token">Token id (optional)</label>
              <input id="mail-token" type="text" className="form-input" value={tokenId} onChange={(e) => setTokenId(e.target.value)} placeholder="e.g. ERA — leave empty for content-only" />
            </div>
            <div className="form-group">
              <label htmlFor="mail-amount">Amount (optional)</label>
              <input id="mail-amount" type="number" min="0" className="form-input" value={amount} onChange={(e) => setAmount(e.target.value)} placeholder="0" />
            </div>
            <div className="form-group">
              <label htmlFor="mail-content">Content</label>
              <textarea id="mail-content" className="form-input" rows={3} value={content} onChange={(e) => setContent(e.target.value)} placeholder="Message" />
            </div>
            <div className="form-actions">
              <button type="button" className="cancel-button" onClick={() => setTab('inbox')} disabled={sendPhase === 'sending'}>Cancel</button>
              <button
                type="button"
                className="send-button button-brick"
                onClick={() => setShowSendConfirm(true)}
                disabled={!composeValid || sendPhase === 'sending'}
              >
                {sendPhase === 'sending' ? 'Sending…' : 'Send'}
              </button>
            </div>
          </>
        )}
      </div>

      <ConfirmModal
        visible={showSendConfirm}
        title="Send posted DLV"
        message={`Send to recipient pk ${recipientPk.trim().slice(0, 12)}…${tokenId ? ` with ${amount || 0} ${tokenId}` : ' (content only)'}?`}
        onConfirm={() => { setShowSendConfirm(false); void handleSend(); }}
        onCancel={() => setShowSendConfirm(false)}
      />
    </div>
  );
}
