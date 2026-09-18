// SPDX-License-Identifier: Apache-2.0
// Send tab — transaction form with online/offline mode toggle.
import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { dsmClient } from '../../../services/dsmClient';
import { failureReasonMessage } from '../../../domain/bilateral';
import ConfirmModal from '../../ConfirmModal';
import { TokenCoin } from '../../TokenCoin';
import { Notice } from '../../common/ScreenFrame';
import { InfoTip } from '../../common/InfoTip';
import { useFx } from '../../fx/FxProvider';
import { fxAmountLabel } from '../../fx/fxEngine';
import type { Balance } from './helpers';
import type { DomainContact } from '../../../domain/types';

type Props = {
  contacts: DomainContact[];
  balances: Balance[];
  eraGif: string;
  btcGif: string;
  onCancel: () => void;
  onSendComplete: () => void;
  loadWalletData: () => Promise<void>;
  setError: (err: string | null) => void;
};

function SendTabInner({
  contacts,
  balances,
  eraGif,
  btcGif,
  onCancel,
  onSendComplete,
  loadWalletData,
  setError,
}: Props): JSX.Element {
  const fx = useFx();
  const [sendForm, setSendForm] = useState<{ selectedContactKey: string; amount: string; token: string; note: string }>({
    // No default recipient. A money form that pre-selects whoever happens to
    // be first sends to the wrong person the moment the list reorders — and it
    // reorders on its own. The user picks, explicitly, every time.
    selectedContactKey: '',
    amount: '',
    token: 'ERA',
    note: '',
  });
  const [txMode, setTxMode] = useState<'online' | 'offline'>('online');
  const [sendingTx, setSendingTx] = useState(false);
  const [showSendConfirm, setShowSendConfirm] = useState(false);

  const tokenOptions = useMemo(() => {
    if (!Array.isArray(balances) || balances.length === 0) {
      return [{ tokenId: 'ERA', symbol: 'ERA', balance: '0' } as Balance];
    }
    return balances;
  }, [balances]);

  const selectedSendBalance = useMemo(() => {
    if (tokenOptions.length === 0) return null;
    return tokenOptions.find((b) => b.tokenId === sendForm.token) ?? tokenOptions[0];
  }, [tokenOptions, sendForm.token]);

  // The selected token's decimals, as the wire reported them. They come from
  // the registry in Rust, so a token created with 2 decimals accepts cents
  // here. A hardcoded table used to answer this and knew only dBTC, which made
  // every custom token look like it took whole units only.
  const selectedDecimals = selectedSendBalance?.decimals ?? 0;

  const selectedContact = useMemo(
    () => contacts.find((c) => c.deviceId === sendForm.selectedContactKey) ?? null,
    [contacts, sendForm.selectedContactKey],
  );

  useEffect(() => {
    if (tokenOptions.length === 0) return;
    if (!tokenOptions.some((b) => b.tokenId === sendForm.token)) {
      setSendForm((prev) => ({ ...prev, token: tokenOptions[0].tokenId }));
    }
  }, [tokenOptions, sendForm.token]);

  useEffect(() => {
    if (contacts.length === 0) {
      setSendForm((prev) => ({ ...prev, selectedContactKey: '' }));
      return;
    }
    // If the chosen contact is gone, CLEAR the selection. Substituting
    // contacts[0] silently retargets a transfer at a different device, which
    // is the one failure mode a send form must never have. Selection is keyed
    // by deviceId, so reordering alone never disturbs it.
    if (
      sendForm.selectedContactKey &&
      !contacts.some((c) => c.deviceId === sendForm.selectedContactKey)
    ) {
      setSendForm((prev) => ({ ...prev, selectedContactKey: '' }));
    }
  }, [contacts, sendForm.selectedContactKey]);

  const handleSendTransaction = useCallback(async () => {
    if (!sendForm.selectedContactKey || !sendForm.amount) {
      setError('Please fill in all required fields');
      return;
    }
    try {
      setSendingTx(true);
      setError(null);

      const contact = selectedContact;
      if (!contact) {
        throw new Error('Selected contact not found');
      }

      const tokenId = sendForm.token || 'ERA';

      if (txMode === 'offline') {
        const bleAddr = await dsmClient.resolveBleAddressForContact(contact);
        if (!bleAddr || typeof bleAddr !== 'string' || bleAddr.length === 0) {
          throw new Error('Offline transfer requires a BLE address for the recipient');
        }

        const res = await dsmClient.sendOfflineTransfer({
          tokenId,
          to: sendForm.selectedContactKey,
          amount: sendForm.amount.trim(),
          memo: sendForm.note || undefined,
          bleAddress: bleAddr,
        });
        const success = res && typeof res === 'object'
          ? ('success' in res
              ? Boolean((res as { success?: boolean }).success)
              : ('accepted' in res ? Boolean((res as { accepted?: boolean }).accepted) : false))
          : false;
        if (!success) {
          // GenericTxResponse carries the SDK's reason in `result` (sometimes `message`
          // for legacy callers). Read both so we surface the real failure cause to the
          // user instead of the generic fallback.
          const resultText = res && typeof res === 'object' && 'result' in res
            ? String((res as { result?: string }).result || '')
            : '';
          const messageText = res && typeof res === 'object' && 'message' in res
            ? String((res as { message?: string }).message || '')
            : '';
          let msg = resultText || messageText || 'Offline transfer failed';
          const failureReason = res && typeof res === 'object' && 'failureReason' in res ? (res as { failureReason?: unknown }).failureReason : undefined;
          const failureReasonNum = typeof failureReason === 'number'
            ? failureReason
            : typeof failureReason === 'string'
              ? Number(failureReason)
              : undefined;
          const fm = failureReasonMessage(Number.isFinite(failureReasonNum) ? failureReasonNum : undefined);
          if (fm) msg = fm;
          throw new Error(msg);
        }
      } else {
        const res = await dsmClient.sendOnlineTransferSmart(
          contact.alias,
          sendForm.amount.trim(),
          sendForm.note || undefined,
          tokenId,
        );
        if (!res?.success) {
          throw new Error(res?.message || 'Online transfer failed');
        }
      }

      const sent = `${sendForm.amount.trim()} ${tokenId}`;
      fx.play({
        anim: txMode === 'offline' ? 'seal' : 'confirm',
        title: txMode === 'offline' ? 'Signed and sealed' : 'Sent',
        caption: `${sent} to ${contact.alias}`,
        amount: fxAmountLabel(sent, '-'),
      });
      onSendComplete();
      await loadWalletData();
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Transaction failed';
      setError(msg);
      fx.play({ anim: 'fail', title: 'Not sent', caption: msg, tone: 'bad', okLabel: 'Back' });
    } finally {
      setSendingTx(false);
    }
  }, [sendForm, selectedContact, txMode, loadWalletData, setError, onSendComplete, fx]);

  const handleSubmit = useCallback((event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setShowSendConfirm(true);
  }, []);

  const coin = (() => {
    const sym = (selectedSendBalance?.symbol || selectedSendBalance?.tokenId || sendForm.token || '').toLowerCase();
    const isBtc = sym.includes('btc') || sym.includes('dbtc');
    if (isBtc || sym === 'era' || !selectedSendBalance) {
      return <img src={isBtc ? btcGif : eraGif} alt={isBtc ? 'BTC' : 'ERA'} className={isBtc ? 'btc-gif small' : 'era-gif small'} />;
    }
    return <TokenCoin iconUrl={selectedSendBalance.iconUrl} ticker={selectedSendBalance.symbol || selectedSendBalance.tokenId} className="era-gif small" fallbackSrc={eraGif} />;
  })();

  return (
    <div className="send-tab">
      <h3 className="sb-section-title">Send Transaction</h3>

      <div className="sb-card" style={{ padding: '6px 10px' }}>
        <div className="sb-kv" style={{ alignItems: 'center' }}>
          <span className="sb-kv__k">Available</span>
          <span className="sb-kv__v" style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 13, fontWeight: 700 }}>
            {coin}
            {selectedSendBalance ? String(selectedSendBalance.balance ?? '0') : '0'} {selectedSendBalance?.symbol || selectedSendBalance?.tokenId || 'ERA'}
          </span>
        </div>
      </div>

      <div className="sb-field">
        <span className="sb-label">
          How to send
          <InfoTip title="How to send" label="About sending modes">
            <p><b>Online</b> goes through the storage nodes. The recipient does not need to be nearby or awake; it lands in their inbox.</p>
            <p><b>Offline</b> goes phone to phone over Bluetooth. Both phones must be next to each other with Bluetooth on, and both must be on the wallet screen.</p>
          </InfoTip>
        </span>
        <div className="sb-seg sb-seg--block" role="group" aria-label="Transaction mode">
          <button type="button" className={`sb-seg__opt${txMode === 'online' ? ' active' : ''}`} onClick={() => setTxMode('online')}>Online</button>
          <button type="button" className={`sb-seg__opt${txMode === 'offline' ? ' active' : ''}`} onClick={() => setTxMode('offline')}>Offline</button>
        </div>
        {txMode === 'offline' && (
          <Notice>
            <strong>Offline needs Bluetooth.</strong> Both phones next to each other, Bluetooth on.
          </Notice>
        )}
      </div>

      <form onSubmit={handleSubmit}>
        <div className="sb-field">
          <label htmlFor="recipient">Recipient Contact</label>
          {contacts.length === 0 ? (
            <div className="sb-empty">No contacts yet. Add one on the Contacts screen to send.</div>
          ) : (
            <select id="recipient" value={sendForm.selectedContactKey} onChange={(e) => setSendForm((p) => ({ ...p, selectedContactKey: e.target.value }))} className="sb-input" required>
              {/* An explicit empty option. Without it the select DISPLAYS the
                  first contact while the form holds no selection at all, which
                  on a send form reads as "this person is selected" when nobody
                  is. */}
              <option value="">— select recipient —</option>
              {contacts.map((c) => (
                <option key={c.deviceId} value={c.deviceId}>{c.alias}</option>
              ))}
            </select>
          )}
        </div>

        <div className="sb-field">
          <label htmlFor="amount">Amount</label>
          <div className="sb-input-row">
            <input
              id="amount"
              type="number"
              step={selectedDecimals > 0 ? `0.${'0'.repeat(selectedDecimals - 1)}1` : '1'}
              min="0"
              value={sendForm.amount}
              onChange={(e) => setSendForm((p) => ({ ...p, amount: e.target.value }))}
              placeholder={selectedDecimals > 0 ? `0.${'0'.repeat(selectedDecimals)}` : '0'}
              className="sb-input sb-input--mono"
              required
            />
            <select
              value={sendForm.token}
              onChange={(e) => setSendForm((p) => ({ ...p, token: e.target.value }))}
              className="sb-input"
              style={{ flex: '0 0 auto', width: 'auto', maxWidth: 110 }}
              aria-label="Token"
            >
              {tokenOptions.map((b) => (
                <option key={b.tokenId} value={b.tokenId}>{b.symbol || b.tokenId}</option>
              ))}
            </select>
          </div>
        </div>

        <div className="sb-field">
          <label htmlFor="note">Note (optional)</label>
          <input id="note" type="text" value={sendForm.note} onChange={(e) => setSendForm((p) => ({ ...p, note: e.target.value }))} placeholder="What is this for?" className="sb-input" />
        </div>

        {/* The recipient, spelled out immediately above the action that
            commits it. A device id is the only unambiguous name for who is
            about to receive this, and it belongs where the decision is made
            rather than several fields further up. */}
        <div className="send-recipient-confirm sb-hint sb-hint--tight sb-mono" data-testid="send-recipient-confirm">
          {selectedContact
            ? `To: ${selectedContact.deviceId.slice(0, 8)}`
            : 'Select a recipient'}
        </div>

        <div className="sb-actions">
          <button type="button" onClick={onCancel} className="sb-btn">Cancel</button>
          <button
            type="submit"
            className="sb-btn sb-btn--primary"
            disabled={!sendForm.selectedContactKey || contacts.length === 0 || sendingTx}
          >
            {sendingTx ? 'Sending…' : 'Send'}
          </button>
        </div>
      </form>
      <ConfirmModal
        visible={showSendConfirm}
        title="Send"
        message={`Send ${sendForm.amount} ${sendForm.token || 'ERA'} to ${selectedContact?.alias || 'recipient'}?${txMode === 'offline' ? ' (Bluetooth)' : ''}`}
        onConfirm={() => { setShowSendConfirm(false); void handleSendTransaction(); }}
        onCancel={() => setShowSendConfirm(false)}
      />
    </div>
  );
}

const SendTab = React.memo(SendTabInner);
export default SendTab;
