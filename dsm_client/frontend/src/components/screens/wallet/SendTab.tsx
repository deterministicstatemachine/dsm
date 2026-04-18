// SPDX-License-Identifier: Apache-2.0
// Send tab — transaction form with online/offline mode toggle.
import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { dsmClient } from '../../../services/dsmClient';
import { failureReasonMessage } from '../../../domain/bilateral';
import { getTokenDecimals } from '../../../utils/tokenMeta';
import ConfirmModal from '../../ConfirmModal';
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
  const [sendForm, setSendForm] = useState<{ selectedContactKey: string; amount: string; token: string; note: string }>({
    selectedContactKey: contacts.length > 0 ? contacts[0].deviceId : '',
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
    if (!contacts.some((c) => c.deviceId === sendForm.selectedContactKey)) {
      setSendForm((prev) => ({ ...prev, selectedContactKey: contacts[0].deviceId }));
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

      onSendComplete();
      await loadWalletData();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Transaction failed');
    } finally {
      setSendingTx(false);
    }
  }, [sendForm, selectedContact, txMode, loadWalletData, setError, onSendComplete]);

  const handleSubmit = useCallback((event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setShowSendConfirm(true);
  }, []);

  return (
    <div className="send-tab">
      <h3>Send Transaction</h3>
      <div className="balance-section" style={{ marginBottom: 16 }}>
        <h4 style={{ fontSize: 12, marginBottom: 8 }}>Available Balance</h4>
        {!selectedSendBalance ? (
          <div className="balance-card" style={{ padding: '8px 12px' }}>
            <div className="balance-info">
              <span className="token-symbol" style={{ display: 'flex', alignItems: 'center' }}>
                <img src={eraGif} alt="ERA" className="era-gif small"/>
                ERA
              </span>
              <span className="balance-amount">0</span>
            </div>
          </div>
        ) : (
          <div className="balance-card" style={{ padding: '8px 12px' }}>
            <div className="balance-info">
              <span className="token-symbol" style={{ display: 'flex', alignItems: 'center' }}>
                {(() => {
                  const sym = (selectedSendBalance.symbol || selectedSendBalance.tokenId || '').toLowerCase();
                  const isBtc = sym.includes('btc') || sym.includes('dbtc');
                  return <img src={isBtc ? btcGif : eraGif} alt={isBtc ? 'BTC' : 'ERA'} className={isBtc ? 'btc-gif small' : 'era-gif small'}/>;
                })()}
                {selectedSendBalance.symbol || selectedSendBalance.tokenId}
              </span>
              <span className="balance-amount">{String(selectedSendBalance.balance ?? '0')}</span>
            </div>
            {selectedSendBalance.usdValue && <div className="balance-usd">{selectedSendBalance.usdValue}</div>}
          </div>
        )}
      </div>
      <div className="mode-toggle" role="group" aria-label="Transaction mode">
        <button type="button" className={`mode-button ${txMode === 'online' ? 'active' : ''}`} onClick={() => setTxMode('online')}>Online</button>
        <button type="button" className={`mode-button ${txMode === 'offline' ? 'active' : ''}`} onClick={() => setTxMode('offline')}>Offline</button>
      </div>
      {txMode === 'offline' && (
        <div className="bluetooth-warning" style={{ padding: '8px 12px', marginBottom: 12, fontSize: 10, border: '2px solid var(--border)' }}>
          <strong>OFFLINE MODE REQUIRES BLUETOOTH</strong><br/>Both devices must be present and have Bluetooth enabled.
        </div>
      )}
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="recipient">Recipient Contact</label>
          {contacts.length === 0 ? (
            <div className="empty-state"><p>No contacts found.</p><p>Add a contact on the Contacts screen to enable sending.</p></div>
          ) : (
            <select id="recipient" value={sendForm.selectedContactKey} onChange={(e) => setSendForm((p) => ({ ...p, selectedContactKey: e.target.value }))} className="form-input" required>
              {contacts.map((c) => (
                <option key={c.deviceId} value={c.deviceId}>{c.alias}</option>
              ))}
            </select>
          )}
        </div>
        <div className="form-group">
          <label htmlFor="amount">{(() => {
            const sym = (sendForm.token || '').toLowerCase();
            const isBtc = sym.includes('btc') || sym.includes('dbtc');
            return <img src={isBtc ? btcGif : eraGif} alt={isBtc ? 'BTC' : 'ERA'} className={isBtc ? 'btc-gif small' : 'era-gif small'}/>;
          })()} Amount</label>
          <div className="amount-input-group">
            <input id="amount" type="number" step={(() => { const d = getTokenDecimals(sendForm.token); return d > 0 ? `0.${'0'.repeat(d - 1)}1` : '1'; })()} min="0" value={sendForm.amount} onChange={(e) => setSendForm((p) => ({ ...p, amount: e.target.value }))} placeholder={(() => { const d = getTokenDecimals(sendForm.token); return d > 0 ? `0.${'0'.repeat(d)}` : '0'; })()} className="form-input" required />
            <select value={sendForm.token} onChange={(e) => setSendForm((p) => ({ ...p, token: e.target.value }))} className="token-selector">
              {tokenOptions.map((b) => (
                <option key={b.tokenId} value={b.tokenId}>{b.symbol || b.tokenId}</option>
              ))}
            </select>
          </div>
        </div>
        <div className="form-group"><label htmlFor="note">Note (Optional)</label><input id="note" type="text" value={sendForm.note} onChange={(e) => setSendForm((p) => ({ ...p, note: e.target.value }))} placeholder="Transaction note" className="form-input" /></div>
        <div className="form-actions">
          <button type="button" onClick={onCancel} className="cancel-button">Cancel</button>
          <button type="submit" className="send-button button-brick" disabled={contacts.length === 0 || sendingTx}>{sendingTx ? 'Sending…' : 'Send'}</button>
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
