// SPDX-License-Identifier: Apache-2.0
// Offline Funding — the pop-up that moves a token between this device's two
// balances: the online account, spent through the storage nodes, and the
// offline allocation, the cash in hand the anchor appliance spends over
// Bluetooth. Rust makes the move and scales the amount; this shows both
// balances as Rust rendered them and carries the user's text in.
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { dsmClient } from '../../../services/dsmClient';
import { TokenSelect } from '../../common/TokenSelect';
import { Notice } from '../../common/ScreenFrame';
import { useBackButton } from '../../../hooks/useBackButton';
import BluetoothIcon from '../../icons/BluetoothIcon';
import type { TokenBalanceView } from '../../../dsm/types';

type Direction = 'load' | 'unload';

type Props = {
  balances: TokenBalanceView[];
  /** The token the send form has selected; the pop-up starts on it. */
  initialTokenId: string;
  /** Re-reads the wallet after a move, so both balances shown are the store's. */
  onMoved: () => Promise<void>;
  onClose: () => void;
};

export function OfflineFundingPopover({ balances, initialTokenId, onMoved, onClose }: Props): React.JSX.Element {
  const [tokenId, setTokenId] = useState(initialTokenId);
  const [direction, setDirection] = useState<Direction>('load');
  const [amount, setAmount] = useState('');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<{ kind: 'success' | 'error'; text: string } | null>(null);
  const dialogRef = useRef<HTMLDivElement | null>(null);

  useBackButton(true, onClose);
  useEffect(() => {
    dialogRef.current?.focus();
  }, []);

  const selected = useMemo(() => balances.find((b) => b.tokenId === tokenId) ?? null, [balances, tokenId]);

  const move = useCallback(async () => {
    if (!selected || !amount.trim()) return;
    setBusy(true);
    setNotice(null);
    try {
      const res = direction === 'load'
        ? await dsmClient.loadOfflineCash(selected.tokenId, amount)
        : await dsmClient.unloadOfflineCash(selected.tokenId, amount);
      setNotice({ kind: 'success', text: res.message });
      setAmount('');
      await onMoved();
    } catch (e) {
      setNotice({ kind: 'error', text: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  }, [selected, amount, direction, onMoved]);

  const decimals = selected?.decimals ?? 0;

  return (
    <div className="sb-popover-backdrop" onClick={(e) => { e.stopPropagation(); onClose(); }}>
      <div
        ref={dialogRef}
        className="sb-popover sb-card--dark"
        role="dialog"
        aria-modal="true"
        aria-labelledby="offline-funding-title"
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="sb-popover__head">
          <BluetoothIcon size={14} title="" />
          <h3 id="offline-funding-title" className="sb-popover__title">Offline Funding</h3>
          <button type="button" className="sb-popover__close" onClick={onClose} aria-label="Close">{'×'}</button>
        </div>
        <div className="sb-popover__body">
          {selected ? (
            <>
              <div className="sb-kv">
                <span className="sb-kv__k">Online account</span>
                <span className="sb-kv__v">{`${selected.displayAmount} ${selected.symbol}`}</span>
              </div>
              <div className="sb-kv">
                <span className="sb-kv__k">Offline allocation</span>
                <span className="sb-kv__v">
                  {selected.offline
                    ? `${selected.offline.displayAmount} ${selected.symbol}`
                    : 'unknown until the appliance connects'}
                </span>
              </div>
            </>
          ) : (
            <div className="sb-empty">No balances to move yet.</div>
          )}
          <div className="sb-field">
            <span className="sb-label">Direction</span>
            <div className="sb-seg sb-seg--block" role="group" aria-label="Funding direction">
              <button type="button" className={`sb-seg__opt${direction === 'load' ? ' active' : ''}`} onClick={() => setDirection('load')}>Load offline</button>
              <button type="button" className={`sb-seg__opt${direction === 'unload' ? ' active' : ''}`} onClick={() => setDirection('unload')}>Unload to online</button>
            </div>
          </div>
          <div className="sb-field">
            <label htmlFor="offline-funding-amount">Amount</label>
            <div className="sb-input-row">
              <input
                id="offline-funding-amount"
                type="number"
                step={decimals > 0 ? `0.${'0'.repeat(decimals - 1)}1` : '1'}
                min="0"
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
                placeholder={decimals > 0 ? `0.${'0'.repeat(decimals)}` : '0'}
                className="sb-input sb-input--mono"
              />
              <TokenSelect
                label="Token"
                className="sb-tokensel--inline"
                value={tokenId}
                options={balances.map((b) => ({ value: b.tokenId, ticker: b.symbol, iconUrl: b.iconUrl }))}
                onChange={setTokenId}
              />
            </div>
          </div>
          {notice && <Notice kind={notice.kind}>{notice.text}</Notice>}
        </div>
        <div className="sb-actions" style={{ margin: 0 }}>
          <button type="button" className="sb-btn" onClick={onClose}>Close</button>
          <button
            type="button"
            className="sb-btn sb-btn--primary"
            disabled={busy || !selected || !amount.trim()}
            onClick={() => void move()}
          >
            {busy ? 'Moving…' : direction === 'load' ? 'Load' : 'Unload'}
          </button>
        </div>
      </div>
    </div>
  );
}
