// SPDX-License-Identifier: Apache-2.0
import React, { useState, useCallback } from 'react';
import { initiateDeposit, fundAndBroadcast, formatBtc, parseBtcToSats, mempoolExplorerUrl } from '../../../services/bitcoinTap';
import { bridgeEvents } from '../../../bridge/bridgeEvents';
import ConfirmModal from '../../ConfirmModal';
import ExplorerLink from './ExplorerLink';
import type { DbtcBalance, NativeBtcBalance } from '../../../services/bitcoinTap';

type Props = {
  balance: DbtcBalance | null;
  nativeBalance: NativeBtcBalance | null;
  network: number;
  onBack: () => void;
  onRefresh: () => Promise<void>;
};

const PRESETS = ['0.001', '0.01', '0.1'];

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
      setDepositResult(`Deposit started (${res.vaultOpId.slice(0, 12)}…). Funding it from your on-chain balance…`);
      try {
        const txid = await fundAndBroadcast(res.vaultOpId);
        setFundingTxid(txid);
        setDepositResult(
          `Deposit sent. It shows under Activity while the Bitcoin network confirms it.\nDeposit: ${res.vaultOpId.slice(0, 12)}…\nFunding txid: ${txid.slice(0, 16)}…`,
        );
      } catch (fundErr) {
        setDepositResult(`Deposit started (${res.vaultOpId.slice(0, 12)}…) but funding failed: ${fundErr instanceof Error ? fundErr.message : 'Fund failed'}`);
      }
      setDepositAmount('');
      try { await onRefresh(); } catch { /* balance refresh failure must not override deposit success */ }
      bridgeEvents.emit('wallet.refresh', { source: 'bitcoin.tap' });
    } catch (e) {
      setDepositResult(`Error: ${e instanceof Error ? e.message : 'Deposit failed'}`);
    } finally {
      setDepositLoading(false);
    }
  }, [pendingDepositSats, onRefresh]);

  const isError = depositResult?.startsWith('Error') || depositResult?.includes('failed');

  return (
    <div className="bitcoin-tap-tab">
      <div className="sb-subhead">
        <button type="button" className="sb-icon-btn" onClick={onBack} aria-label="Back" title="Back">{'‹'}</button>
        <h3>Deposit BTC</h3>
      </div>

      <p className="sb-hint">
        Moves BTC from your on-chain balance into this wallet as dBTC. It arrives once the Bitcoin network has confirmed it.
      </p>

      <div className="sb-card">
        <div className="sb-kv">
          <span className="sb-kv__k">On-chain BTC</span>
          <span className="sb-kv__v">{nativeBalance ? formatBtc(nativeBalance.available) : '0.00000000'} BTC</span>
        </div>
        <div className="sb-kv">
          <span className="sb-kv__k">dBTC now</span>
          <span className="sb-kv__v">{balance ? formatBtc(balance.available) : '0.00000000'} dBTC</span>
        </div>
      </div>

      <div className="sb-field">
        <label htmlFor="deposit-amount">Amount (BTC)</label>
        <input
          id="deposit-amount"
          type="text"
          inputMode="decimal"
          value={depositAmount}
          onChange={(e) => setDepositAmount(e.target.value)}
          placeholder="0.00100000"
          className="sb-input sb-input--mono"
        />
        <div className="sb-presets">
          {PRESETS.map((preset) => (
            <button
              key={preset}
              type="button"
              onClick={() => setDepositAmount(preset)}
              className={`sb-btn${depositAmount === preset ? ' sb-btn--primary' : ''}`}
            >
              {preset} BTC
            </button>
          ))}
        </div>
      </div>

      <div className="sb-actions">
        <button type="button" onClick={onBack} className="sb-btn">Cancel</button>
        <button type="button" onClick={handleDepositClick} className="sb-btn sb-btn--primary" disabled={!depositAmount || depositLoading}>
          {depositLoading ? 'Depositing…' : 'Deposit'}
        </button>
      </div>

      <ConfirmModal
        visible={showDepositConfirm}
        title="Deposit"
        message={`Deposit ${formatBtc(pendingDepositSats)} BTC?`}
        onConfirm={() => void handleDepositConfirm()}
        onCancel={() => setShowDepositConfirm(false)}
      />

      {depositResult && (
        <div className={`sb-notice${isError ? ' sb-notice--error' : ''}`} role="status">
          <span className="sb-mono" style={{ whiteSpace: 'pre-wrap' }}>{depositResult}</span>
        </div>
      )}

      {fundingTxid && (
        <ExplorerLink
          url={mempoolExplorerUrl(fundingTxid, network)}
          onCopied={() => setDepositResult((prev) => (prev ? `${prev}\nExplorer link copied.` : 'Explorer link copied.'))}
          onCopyFailed={(url) => setDepositResult((prev) => (prev ? `${prev}\nURL: ${url}` : `URL: ${url}`))}
        />
      )}
    </div>
  );
}
