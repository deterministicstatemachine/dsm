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
import { Notice, ScreenFrame, ScreenTabs } from '../common/ScreenFrame';
import { InfoTip } from '../common/InfoTip';
import { useFx } from '../fx/FxProvider';
import { useBackButton } from '../../hooks/useBackButton';

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
  const fx = useFx();
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

  // B (or Escape) while composing returns to the inbox, not to home.
  useBackButton(tab === 'compose', () => setTab('inbox'));

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
      fx.play({ anim: 'confirm', title: 'Claimed', caption: 'The mail is open and anything locked with it is yours' });
      setInboxStatus(`Claimed ${vaultIdBase32.slice(0, 12)}…`);
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'claim failed';
      setRowState((prev) => ({ ...prev, [vaultIdBase32]: { status: 'error', detail: msg } }));
      setInboxError(msg);
    }
  }, [fx]);

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
      fx.play({ anim: 'vault', title: 'Mail sealed', caption: 'Only your recipient can open it' });
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
  }, [recipientPk, policyAnchor, content, tokenId, amount, fx]);

  return (
    <ScreenFrame
      title="Mail"
      onBack={() => onNavigate?.('home')}
      info={(
        <InfoTip title="Mail" label="About mail">
          <p>Mail carries tokens or a note to someone&apos;s key. Neither of you needs to be online at the same time: it waits on the storage nodes until the recipient claims it.</p>
          <p><b>Inbox</b> lists what is waiting for you. <b>Sync all</b> fetches it; then <b>Claim</b> moves it into your wallet.</p>
          <p><b>Compose</b> needs the recipient&apos;s public key and the policy anchor the mail is locked under (copy it from the token&apos;s card under Tokens). Token and amount are optional: leave them empty to send only a note.</p>
        </InfoTip>
      )}
      actions={tab === 'inbox' ? (
        <button
          type="button"
          onClick={() => void refreshInbox()}
          disabled={inboxBusy}
          className="sb-icon-btn"
          aria-label="Refresh inbox"
          title="Refresh"
        >
          <img src="images/icons/icon_refresh.svg" alt="" />
        </button>
      ) : undefined}
      tabs={<ScreenTabs tabs={[{ id: 'inbox', label: 'Inbox' }, { id: 'compose', label: 'Compose' }] as const} active={tab} onChange={setTab} ariaLabel="Mail sections" />}
      banner={
        <>
          {/* Cross-tab send banners — keep send feedback visible after the
           * post-send tab switch so the user always gets confirmation. */}
          {sendError && <Notice kind="error" banner onClose={() => setSendError('')}>{sendError}</Notice>}
          {sendStatus && !sendError && <Notice kind="success" banner onClose={() => setSendStatus('')}>{sendStatus}</Notice>}
        </>
      }
    >
      {tab === 'inbox' && (
        <>
          {inboxError && <Notice kind="error" onClose={() => setInboxError('')}>{inboxError}</Notice>}
          {inboxStatus && !inboxError && <Notice>{inboxStatus}</Notice>}
          <div className="sb-actions" style={{ marginTop: 0 }}>
            <button type="button" className="sb-btn sb-btn--primary" onClick={() => void handleSyncAll()} disabled={inboxBusy || pending.length === 0}>
              {inboxBusy ? 'Syncing\u2026' : 'Sync all'}
            </button>
          </div>
          {pending.length === 0 && !inboxBusy && (
            <div className="sb-empty">
              No pending posted DLVs.
              <br />
              Tap refresh to check the storage nodes.
            </div>
          )}
          {pending.map((v) => {
            const st = rowState[v.dlvIdBase32]?.status ?? 'pending';
            const detail = rowState[v.dlvIdBase32]?.detail;
            const claimable = st === 'mirrored';
            return (
              <div key={v.dlvIdBase32} className="sb-card">
                <div className="sb-row" style={{ padding: 0, borderBottom: 0 }}>
                  <div className="sb-row__main">
                    <div className="sb-row__title sb-mono">{v.dlvIdBase32.slice(0, 16)}{'\u2026'}</div>
                    <div className="sb-row__sub">from {v.creatorPublicKeyBase32.slice(0, 16)}{'\u2026'}</div>
                  </div>
                  <span className={`sb-tag${st === 'claimed' ? ' sb-tag--solid' : st === 'error' ? ' sb-tag--dim' : ''}`} data-row-status={st}>{st}</span>
                </div>
                {detail && <p className="sb-hint sb-hint--tight">{detail}</p>}
                <div className="sb-actions" style={{ margin: '8px 0 0' }}>
                  <button
                    type="button"
                    className={`sb-btn sb-btn--small${claimable ? ' sb-btn--primary' : ''}`}
                    disabled={!claimable}
                    onClick={() => void handleClaim(v.dlvIdBase32)}
                  >
                    {st === 'claiming' ? 'Claiming\u2026' : st === 'claimed' ? 'Claimed \u2713' : st === 'pending' ? 'Sync to claim' : 'Claim'}
                  </button>
                </div>
              </div>
            );
          })}
        </>
      )}

      {tab === 'compose' && (
        <>
          <div className="sb-field">
            <label htmlFor="mail-recipient">Recipient public key</label>
            <textarea id="mail-recipient" className="sb-input sb-input--mono" rows={3} value={recipientPk} onChange={(e) => setRecipientPk(e.target.value)} placeholder="Paste their Kyber public key (Base32)" />
          </div>
          <div className="sb-field">
            <label htmlFor="mail-policy">Policy anchor</label>
            <textarea id="mail-policy" className="sb-input sb-input--mono" rows={2} value={policyAnchor} onChange={(e) => setPolicyAnchor(e.target.value)} placeholder="52-character Base32 anchor" />
          </div>
          <div className="sb-field">
            <label htmlFor="mail-token">Token (optional)</label>
            <input id="mail-token" type="text" className="sb-input" value={tokenId} onChange={(e) => setTokenId(e.target.value)} placeholder="e.g. ERA — leave empty for a note only" />
          </div>
          <div className="sb-field">
            <label htmlFor="mail-amount">Amount (optional)</label>
            <input id="mail-amount" type="number" min="0" className="sb-input sb-input--mono" value={amount} onChange={(e) => setAmount(e.target.value)} placeholder="0" />
          </div>
          <div className="sb-field">
            <label htmlFor="mail-content">Content</label>
            <textarea id="mail-content" className="sb-input" rows={3} value={content} onChange={(e) => setContent(e.target.value)} placeholder="Message" />
          </div>
          <div className="sb-actions">
            <button type="button" className="sb-btn" onClick={() => setTab('inbox')} disabled={sendPhase === 'sending'}>Cancel</button>
            <button
              type="button"
              className="sb-btn sb-btn--primary"
              onClick={() => setShowSendConfirm(true)}
              disabled={!composeValid || sendPhase === 'sending'}
            >
              {sendPhase === 'sending' ? 'Sending\u2026' : 'Send'}
            </button>
          </div>
        </>
      )}

      <ConfirmModal
        visible={showSendConfirm}
        title="Send posted DLV"
        message={`Send to recipient pk ${recipientPk.trim().slice(0, 12)}…${tokenId ? ` with ${amount || 0} ${tokenId}` : ' (content only)'}?`}
        onConfirm={() => { setShowSendConfirm(false); void handleSend(); }}
        onCancel={() => setShowSendConfirm(false)}
      />
    </ScreenFrame>
  );
}
