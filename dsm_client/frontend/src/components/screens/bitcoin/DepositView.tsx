// SPDX-License-Identifier: Apache-2.0
import React, { useState, useCallback } from 'react';
import { initiateDeposit, fundAndBroadcast, formatBtc, parseBtcToSats, mempoolExplorerUrl } from '../../../services/bitcoinTap';
import { bridgeEvents } from '../../../bridge/bridgeEvents';
import ConfirmModal from '../../ConfirmModal';
import type { DbtcBalance, NativeBtcBalance } from '../../../services/bitcoinTap';

type Props = {
  balance: DbtcBalance | null;
  nativeBalance: NativeBtcBalance | null;
  network: number;
  onBack: () => void;
  onRefresh: () => Promise<void>;
};

export default function DepositView({ balance, nativeBalance, network, onBack, onRefresh }: Props): JSX.Element {
  const [depositAmount, setDepositAmount] = useState('');
  const [depositLoading, setDepositLoading] = useState(false);
  const [depositResult, setDepositResult] = useState<string | null>(null);
  const [showDepositConfirm, setShowDepositConfirm] = useState(false);
  const [pendingDepositSats, setPendingDepositSats] = useState<bigint>(0n);
  const [fundingTxid, setFundingTxid] = useState<string | null>(null);

  const handleDepositClick = useCallback(() => {
    if (!depositAmount || depositLoading) return;
    try {
      const sats = parseBtcToSats(depositAmount);
      setPendingDepositSats(sats);
      setShowDepositConfirm(true);
    } catch (e) {
      setDepositResult(`Error: ${e instanceof Error ? e.message : 'Invalid amount'}`);
    }
  }, [depositAmount, depositLoading]);

  const handleDepositConfirm = useCallback(async () => {
    setShowDepositConfirm(false);
    setDepositLoading(true);
    setDepositResult(null);
    setFundingTxid(null);
    try {
      const res = await initiateDeposit(pendingDepositSats, 144n);
      setDepositResult(`Deposit initiated: ${res.vaultOpId}\nFunding transaction...`);
      try {
        const txid = await fundAndBroadcast(res.vaultOpId);
        setFundingTxid(txid);
        setDepositResult(`Deposit broadcast!\nDeposit: ${res.vaultOpId.slice(0, 12)}…\nFunding txid: ${txid.slice(0, 16)}…`);
      } catch (fundErr) {
        setDepositResult(`Deposit initiated (${res.vaultOpId.slice(0, 12)}…) but funding failed: ${fundErr instanceof Error ? fundErr.message : 'Fund failed'}`);
      }
      setDepositAmount('');
      await onRefresh();
      bridgeEvents.emit('wallet.refresh', { source: 'bitcoin.tap' });
    } catch (e) {
      setDepositResult(`Error: ${e instanceof Error ? e.message : 'Deposit failed'}`);
    } finally {
      setDepositLoading(false);
    }
  }, [pendingDepositSats, onRefresh]);

  return (
    <div className="bitcoin-tap-tab" style={{ padding: '0 4px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
        <button onClick={() => { onBack(); }} className="button-brick" style={{ padding: '4px 8px', background: 'transparent', border: '1px solid var(--border)', borderRadius: 8, color: 'var(--text-dark)', fontSize: 11, cursor: 'pointer' }}>Back</button>
        <h3 style={{ margin: 0, fontSize: 14, fontWeight: 500 }}>Deposit BTC</h3>
      </div>

      <div style={{ fontSize: 11, marginBottom: 12, color: 'var(--text-disabled)' }}>
        Lock BTC in an HTLC to receive dBTC in your DSM wallet.
      </div>

      <div className="balance-card btc-tap-summary-card">
        <div className="balance-info btc-tap-summary-col">
          <span className="token-symbol">Current dBTC</span>
          <span className="balance-amount btc-tap-summary-amount">{balance ? formatBtc(balance.available) : '0.00000000'}</span>
        </div>
        <div className="balance-info btc-tap-summary-col btc-tap-summary-col-right">
          <span className="token-symbol">Current BTC</span>
          <span className="balance-amount btc-tap-summary-amount">{nativeBalance ? formatBtc(nativeBalance.available) : '0.00000000'}</span>
        </div>
      </div>

      <div className="form-group">
        <label htmlFor="deposit-amount" style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-dark)', display: 'block', marginBottom: 6 }}>Amount (BTC)</label>
        <input id="deposit-amount" type="text" inputMode="decimal" value={depositAmount} onChange={(e) => setDepositAmount(e.target.value)} placeholder="0.00100000" className="form-input" style={{ width: '100%', boxSizing: 'border-box' }} />
        <div className="btc-tap-preset-row">
          {['0.00100000', '0.01000000', '0.10000000'].map((preset) => (
            <button key={preset} type="button" onClick={() => setDepositAmount(preset)} className="button-brick btc-tap-preset-btn" style={{ opacity: depositAmount === preset ? 1 : 0.8 }}>{preset}</button>
          ))}
        </div>
      </div>

      <div className="form-actions" style={{ marginTop: 16 }}>
        <button type="button" onClick={onBack} className="cancel-button" style={{ flex: 1 }}>Cancel</button>
        <button type="button" onClick={handleDepositClick} className="send-button button-brick" disabled={!depositAmount || depositLoading} style={{ flex: 1 }}>
          {depositLoading ? 'Depositing...' : 'Deposit'}
        </button>
      </div>

      <ConfirmModal visible={showDepositConfirm} title="Deposit" message={`Deposit ${formatBtc(pendingDepositSats)} BTC?`} onConfirm={() => void handleDepositConfirm()} onCancel={() => setShowDepositConfirm(false)} />

      {depositResult && (
        <div style={{ marginTop: 12, padding: '8px 10px', border: '1px solid var(--border)', borderRadius: 6, fontSize: 11, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', whiteSpace: 'pre-wrap', wordBreak: 'break-all', color: 'var(--text-dark)', background: depositResult.startsWith('Error') ? 'var(--bg-secondary)' : 'var(--bg)', borderStyle: depositResult.startsWith('Error') ? 'dashed' : 'solid' }}>
          {depositResult}
        </div>
      )}

      {fundingTxid && (
        <div style={{ marginTop: 8 }}>
          {(() => {
            const url = mempoolExplorerUrl(fundingTxid, network);
            return (
              <div
                role="button"
                tabIndex={0}
                onClick={() => navigator.clipboard.writeText(url).then(
                  () => setDepositResult((prev) => prev ? `${prev}\nExplorer link copied!` : 'Explorer link copied!'),
                  () => setDepositResult((prev) => prev ? `${prev}\nURL: ${url}` : `URL: ${url}`),
                )}
                onKeyDown={(e) => e.key === 'Enter' && navigator.clipboard.writeText(url).then(
                  () => setDepositResult((prev) => prev ? `${prev}\nExplorer link copied!` : 'Explorer link copied!'),
                  () => setDepositResult((prev) => prev ? `${prev}\nURL: ${url}` : `URL: ${url}`),
                )}
                style={{ fontSize: 10, color: 'var(--text-dark)', textDecoration: 'underline', wordBreak: 'break-all', cursor: 'copy', fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', padding: '2px 0' }}
                title="Click to copy explorer link"
              >
                {url}
              </div>
            );
          })()}
        </div>
      )}
    </div>
  );
}
