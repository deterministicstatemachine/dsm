// SPDX-License-Identifier: Apache-2.0
// Send tab — transaction form with online/offline mode toggle.
import React, { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { dsmClient } from '../../../services/dsmClient';
import { failureReasonMessage } from '../../../domain/bilateral';
import ConfirmModal from '../../ConfirmModal';
import { TokenMark } from '../../TokenMark';
import { TokenSelect } from '../../common/TokenSelect';
import { Notice } from '../../common/ScreenFrame';
import { InfoTip } from '../../common/InfoTip';
import BluetoothIcon from '../../icons/BluetoothIcon';
import { getAnchorStatus } from '../../../dsm/anchor';
import { OfflineFundingPopover } from './OfflineFundingPopover';
import { AppliancePopover, applianceConnected } from './AppliancePopover';
import type { ApplianceRead } from './AppliancePopover';
import { useFx } from '../../fx/FxProvider';
import { fxAmountLabel } from '../../fx/fxEngine';
import type { TokenBalanceView } from '../../../dsm/types';
import type { DomainContact } from '../../../domain/types';

type Props = {
  contacts: DomainContact[];
  balances: TokenBalanceView[];
  onCancel: () => void;
  onSendComplete: () => void;
  loadWalletData: () => Promise<void>;
  setError: (err: string | null) => void;
};

function SendTabInner({
  contacts,
  balances,
  onCancel,
  onSendComplete,
  loadWalletData,
  setError,
}: Props): React.JSX.Element {
  const fx = useFx();
  const [sendForm, setSendForm] = useState<{ selectedContactKey: string; amount: string; token: string; note: string }>({
    // No default recipient. A money form that pre-selects whoever happens to
    // be first sends to the wrong person the moment the list reorders — and it
    // reorders on its own. The user picks, explicitly, every time.
    selectedContactKey: '',
    amount: '',
    // Chosen from the balances Rust listed; until they arrive there is none.
    token: '',
    note: '',
  });
  const [txMode, setTxMode] = useState<'online' | 'offline'>('online');
  const [sendingTx, setSendingTx] = useState(false);
  const [showSendConfirm, setShowSendConfirm] = useState(false);
  const [fundingOpen, setFundingOpen] = useState(false);
  const [applianceOpen, setApplianceOpen] = useState(false);
  const [appliance, setAppliance] = useState<ApplianceRead>({ kind: 'unread' });
  const [applianceBusy, setApplianceBusy] = useState(false);
  const loadWalletDataRef = useRef(loadWalletData);
  loadWalletDataRef.current = loadWalletData;

  // Rust attaches the appliance on this read. The first time, Android asks the
  // user to allow it; from then on, while it stays plugged in, it connects on
  // its own, so choosing Offline is enough. Once it is connected the balances
  // can name their offline allocations, so they are read again.
  const connectAppliance = useCallback(async () => {
    setApplianceBusy(true);
    try {
      const status = await getAnchorStatus();
      setAppliance({ kind: 'read', status });
      if (status.connected) await loadWalletDataRef.current();
    } catch (e) {
      setAppliance({ kind: 'error', message: e instanceof Error ? e.message : String(e) });
    } finally {
      setApplianceBusy(false);
    }
  }, []);

  useEffect(() => {
    if (txMode === 'offline') void connectAppliance();
  }, [txMode, connectAppliance]);

  // Only what Rust listed. With no balances there is nothing to send, and the
  // form says so rather than offering a token the wallet does not hold.
  const tokenOptions: TokenBalanceView[] = balances;

  const selectedSendBalance = useMemo(
    () => tokenOptions.find((b) => b.tokenId === sendForm.token) ?? null,
    [tokenOptions, sendForm.token],
  );


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

      if (!selectedSendBalance) {
        throw new Error('Choose a token to send');
      }
      const tokenId = selectedSendBalance.tokenId;

      if (txMode === 'offline') {
        // Where the recipient's appliance is over BLE is Rust's to know; an appliance
        // it has not met is its refusal, in its words.
        const res = await dsmClient.sendOfflineTransfer({
          tokenId,
          to: sendForm.selectedContactKey,
          amount: sendForm.amount.trim(),
          memo: sendForm.note || undefined,
        });
        if (res.open) {
          // Not finished and not failed: the step is open on both appliances and
          // completes when they are together again. The form is done with it.
          fx.play({
            anim: 'trace',
            title: 'Not finished yet',
            caption: res.result ?? '',
            tone: 'neutral',
            okLabel: 'OK',
            coin: { ticker: selectedSendBalance.symbol, iconUrl: selectedSendBalance.iconUrl },
          });
          onSendComplete();
          await loadWalletData();
          return;
        }
        if (!res.accepted) {
          // The failure reason's message when the SDK named one, else its own words.
          throw new Error(failureReasonMessage(res.failureReason) ?? res.result ?? 'Offline transfer failed');
        }
      } else {
        const res = await dsmClient.sendOnlineTransferSmart(
          sendForm.selectedContactKey,
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
        coin: { ticker: selectedSendBalance.symbol, iconUrl: selectedSendBalance.iconUrl },
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
  }, [sendForm, selectedContact, txMode, selectedSendBalance, loadWalletData, setError, onSendComplete, fx]);

  const handleSubmit = useCallback((event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setShowSendConfirm(true);
  }, []);


  return (
    <div className="send-tab">
      <h3 className="sb-section-title">Send Transaction</h3>

      {/* The coin, the balance and the unit all read from the selected token, so
          picking another one in the Amount row changes all three together.
          The coin and its ticker are pinned to the left edge so they hold still
          while the number beside them changes length. */}
      {selectedSendBalance ? (
        <div className="sb-card" style={{ padding: '6px 10px' }}>
          <div className="sb-kv" style={{ alignItems: 'center' }}>
            <span className="sb-kv__k" style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12, textTransform: 'none', letterSpacing: 0 }}>
              <TokenMark ticker={selectedSendBalance.symbol} iconUrl={selectedSendBalance.iconUrl} className="sb-coin sb-coin--lg" />
              {selectedSendBalance.symbol}
            </span>
            {/* An offline send spends the offline allocation, so in offline
                mode the number is that pot: unknown until the appliance has
                stated its bundle, and shown as unknown rather than as 0. */}
            <span className="sb-kv__v" style={{ fontSize: 15, fontWeight: 700, display: 'inline-flex', alignItems: 'center', gap: 6 }}>
              {txMode === 'offline' && <BluetoothIcon size={13} title="Offline allocation" />}
              {txMode === 'offline'
                ? (selectedSendBalance.offline ? selectedSendBalance.offline.displayAmount : '—')
                : selectedSendBalance.displayAmount}
            </span>
          </div>
          {txMode === 'offline' && !selectedSendBalance.offline && (
            <div className="sb-hint sb-hint--tight">Offline allocation unknown until the appliance connects.</div>
          )}
        </div>
      ) : (
        <div className="sb-empty">No balances to send yet.</div>
      )}

      <div className="sb-field">
        <span className="sb-label">
          How to send
          <InfoTip title="How to send" label="About sending modes">
            <p><b>Online</b> goes through the storage nodes. The recipient does not need to be nearby or awake; it lands in their inbox.</p>
            <p><b>Offline</b> goes appliance to appliance over Bluetooth. Both appliances must be next to each other with Bluetooth on, and the recipient accepts it in the app.</p>
          </InfoTip>
        </span>
        <div className="sb-seg sb-seg--block" role="group" aria-label="Transaction mode">
          <button type="button" className={`sb-seg__opt${txMode === 'online' ? ' active' : ''}`} onClick={() => setTxMode('online')}>Online</button>
          <button type="button" className={`sb-seg__opt${txMode === 'offline' ? ' active' : ''}`} onClick={() => setTxMode('offline')}>Offline</button>
        </div>
        {txMode === 'offline' && (
          <>
            <Notice>
              <strong>Offline needs Bluetooth.</strong> Both appliances next to each other, Bluetooth on.
            </Notice>
            {/* The two things an offline send needs besides Bluetooth: tokens
                in the offline allocation, and the appliance that spends them. */}
            <div className="sb-actions" style={{ marginTop: 6 }}>
              <button type="button" className="sb-btn sb-btn--small" data-tour="offline-funding" onClick={() => setFundingOpen(true)}>
                Offline Funding
              </button>
              <InfoTip title="Offline Funding" label="About offline funding">
                <p>Your wallet keeps two balances of each token. The <b>online account</b> spends through the storage nodes. The <b>offline allocation</b> is cash in hand: it spends appliance to appliance over Bluetooth, guarded by the anchor appliance, and an offline send draws from it.</p>
                <p><b>Load</b> moves tokens from the online account into the offline allocation. <b>Unload</b> moves them back. Both need the appliance connected, and both change only which of your two balances holds the tokens.</p>
              </InfoTip>
              <button
                type="button"
                className="sb-btn sb-btn--small"
                data-tour="appliance-setup"
                style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: 6 }}
                onClick={() => setApplianceOpen(true)}
              >
                <span className={`sb-dot${applianceConnected(appliance) ? ' sb-dot--on' : ''}`} aria-hidden="true" />
                {applianceBusy ? 'Appliance…' : 'Appliance'}
              </button>
            </div>
          </>
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

        {selectedSendBalance && (
        <div className="sb-field">
          <label htmlFor="amount">Amount</label>
          <div className="sb-input-row">
            {/* The selected token's decimals, as the wire reported them. They
                come from the registry in Rust, so a token created with 2
                decimals accepts cents here. A hardcoded table used to answer
                this and knew only dBTC, which made every custom token look
                like it took whole units only. */}
            <input
              id="amount"
              type="number"
              step={selectedSendBalance.decimals > 0 ? `0.${'0'.repeat(selectedSendBalance.decimals - 1)}1` : '1'}
              min="0"
              value={sendForm.amount}
              onChange={(e) => setSendForm((p) => ({ ...p, amount: e.target.value }))}
              placeholder={selectedSendBalance.decimals > 0 ? `0.${'0'.repeat(selectedSendBalance.decimals)}` : '0'}
              className="sb-input sb-input--mono"
              required
            />
            <TokenSelect
              label="Token"
              className="sb-tokensel--inline"
              value={sendForm.token}
              options={tokenOptions.map((b) => ({ value: b.tokenId, ticker: b.symbol, iconUrl: b.iconUrl }))}
              onChange={(next) => setSendForm((p) => ({ ...p, token: next }))}
            />
          </div>
        </div>
        )}

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
            disabled={!sendForm.selectedContactKey || contacts.length === 0 || !selectedSendBalance || sendingTx}
          >
            {sendingTx ? 'Sending…' : 'Send'}
          </button>
        </div>
      </form>
      <ConfirmModal
        visible={showSendConfirm}
        title="Send"
        message={selectedContact && selectedSendBalance
          ? `Send ${sendForm.amount} ${selectedSendBalance.symbol} to ${selectedContact.alias}?${txMode === 'offline' ? ' (Bluetooth)' : ''}`
          : ''}
        onConfirm={() => { setShowSendConfirm(false); void handleSendTransaction(); }}
        onCancel={() => setShowSendConfirm(false)}
      />
      {fundingOpen && (
        <OfflineFundingPopover
          balances={balances}
          initialTokenId={sendForm.token}
          onMoved={loadWalletData}
          onClose={() => setFundingOpen(false)}
        />
      )}
      {applianceOpen && (
        <AppliancePopover
          read={appliance}
          busy={applianceBusy}
          onConnect={connectAppliance}
          onClose={() => setApplianceOpen(false)}
        />
      )}
    </div>
  );
}

const SendTab = React.memo(SendTabInner);
export default SendTab;
