// SPDX-License-Identifier: Apache-2.0
// BitcoinTapTab — the Bitcoin tab of the wallet (dBTC <-> BTC via HTLC deposits).
//
// Simple by default: one balance, two actions, the receive address and a
// plain-language activity list. Everything a first-time user does not need —
// accounts, network, address index, node status, vault internals — sits under
// a single Advanced fold. Data loading and the sub-views are unchanged.
import React, { useEffect, useMemo, useRef, useState } from 'react';
import { bitcoinNetworkLabel, formatBtc, normalizeBitcoinUiNetwork } from '../../../services/bitcoinTap';
import { useBitcoinTapData } from './hooks/useBitcoinTapData';
import { useBitcoinWallet } from './hooks/useBitcoinWallet';
import DepositView from './DepositView';
import WithdrawView from './WithdrawView';
import WalletAccountsPanel from './WalletAccountsPanel';
import DepositCard from './DepositCard';
import VaultCard from './VaultCard';
import { Disclosure, Notice, scrollToTop } from '../../common/ScreenFrame';
import { useBackButton } from '../../../hooks/useBackButton';
import { InfoTip } from '../../common/InfoTip';
import { isSettledDeposit } from './labels';

export default function BitcoinTapTab({ btcLogoSrc = 'images/logos/btc-logo.gif' }: { btcLogoSrc?: string }): JSX.Element {
  const data = useBitcoinTapData();
  const wallet = useBitcoinWallet(data.loadData, data.setWalletMessage);
  const rootRef = useRef<HTMLDivElement | null>(null);
  const [showSettled, setShowSettled] = useState(false);

  // A sub-view is a new page. It must not open scrolled to wherever the
  // button that opened it happened to sit.
  useEffect(() => {
    scrollToTop(rootRef.current);
  }, [data.subView]);

  // B (or Escape) inside Deposit / Withdraw returns to this tab, not to home.
  useBackButton(data.subView !== 'main', () => data.setSubView('main'));

  const activeAccount = data.walletAccounts.find((a) => a.active || a.accountId === data.walletActiveId);
  const displayAddr = data.addressCache.get(data.selectedIndex) ?? data.address;
  const isPendingIndexChange = data.selectedIndex !== (data.address?.index ?? 0);
  const isWif = activeAccount?.importKind === 'wif';
  const activeNetwork = normalizeBitcoinUiNetwork(activeAccount?.network ?? wallet.globalNetwork);
  const networkLabel = bitcoinNetworkLabel(activeNetwork);
  const pendingSats = data.balance?.locked ?? 0n;
  const nativeUnavailable = data.nativeBalance?.source === 'UNAVAILABLE';

  const { inFlight, settled } = useMemo(() => ({
    inFlight: data.deposits.filter((d) => !isSettledDeposit(d.status)),
    settled: data.deposits.filter((d) => isSettledDeposit(d.status)),
  }), [data.deposits]);

  const accountsPanel = (
    <WalletAccountsPanel
      walletAccounts={data.walletAccounts}
      walletActiveId={data.walletActiveId}
      walletLoading={data.walletLoading}
      walletMessage={data.walletMessage}
      globalNetwork={wallet.globalNetwork}
      setGlobalNetwork={wallet.setGlobalNetwork}
      walletTab={wallet.walletTab}
      setWalletTab={wallet.setWalletTab}
      createLabel={wallet.createLabel}
      setCreateLabel={wallet.setCreateLabel}
      createWordCount={wallet.createWordCount}
      setCreateWordCount={wallet.setCreateWordCount}
      createLoading={wallet.createLoading}
      generatedMnemonic={wallet.generatedMnemonic}
      mnemonicCopied={wallet.mnemonicCopied}
      mnemonicConfirmed={wallet.mnemonicConfirmed}
      setMnemonicConfirmed={wallet.setMnemonicConfirmed}
      importKind={wallet.importKind}
      setImportKind={wallet.setImportKind}
      importSecret={wallet.importSecret}
      setImportSecret={wallet.setImportSecret}
      importLabel={wallet.importLabel}
      setImportLabel={wallet.setImportLabel}
      importStartIndex={wallet.importStartIndex}
      setImportStartIndex={wallet.setImportStartIndex}
      handleCreateWallet={wallet.handleCreateWallet}
      handleImportWallet={wallet.handleImportWallet}
      handleMnemonicCopy={wallet.handleMnemonicCopy}
      handleMnemonicDone={wallet.handleMnemonicDone}
      handleSelectWallet={data.handleSelectWallet}
    />
  );

  if (data.loading) {
    return <div className="sb-empty">Loading Bitcoin{'…'}</div>;
  }

  if (data.subView === 'deposit') {
    return (
      <div ref={rootRef}>
        <DepositView
          balance={data.balance}
          nativeBalance={data.nativeBalance}
          network={activeNetwork}
          onBack={() => data.setSubView('main')}
          onRefresh={data.loadData}
        />
      </div>
    );
  }

  if (data.subView === 'withdraw') {
    return (
      <div ref={rootRef}>
        <WithdrawView
          balance={data.balance}
          nativeBalance={data.nativeBalance}
          vaults={data.vaults}
          network={activeNetwork}
          onBack={() => data.setSubView('main')}
          onRefresh={data.loadData}
        />
      </div>
    );
  }

  return (
    <div className="bitcoin-tap-tab" ref={rootRef}>
      {data.error && (
        <Notice kind="error" onClose={() => data.setError(null)}>{data.error}</Notice>
      )}
      {nativeUnavailable && !data.error && (
        <Notice>
          Bitcoin balance unavailable. Check your connection.{' '}
          <button type="button" className="sb-btn sb-btn--small" onClick={() => void data.loadData()}>Retry</button>
        </Notice>
      )}

      {/* The one number that matters, and the on-chain balance it came from. */}
      <section className="sb-card sb-card--hero" aria-label="dBTC balance">
        <div className="sb-hero__label">
          <img src={btcLogoSrc} alt="" />
          dBTC balance
        </div>
        <div className="sb-hero__value">
          {data.balance ? formatBtc(data.balance.available) : '0.00000000'}
          <span className="sb-hero__unit">dBTC</span>
        </div>
        {pendingSats > 0n && (
          <div className="sb-hero__sub">{formatBtc(pendingSats)} held for a withdrawal</div>
        )}
        <div className="sb-hero__row">
          <span>On-chain BTC</span>
          <b>{data.nativeBalance && !nativeUnavailable ? `${formatBtc(data.nativeBalance.available)} BTC` : '—'}</b>
        </div>
        {data.nativeBalance && data.nativeBalance.locked > 0n && (
          <div className="sb-hero__sub">{formatBtc(data.nativeBalance.locked)} BTC leaving</div>
        )}
      </section>

      <div className="sb-actions">
        <button
          type="button"
          className="sb-btn sb-btn--primary"
          onClick={() => data.setSubView('deposit')}
          disabled={!activeAccount}
        >
          Deposit BTC
        </button>
        <button
          type="button"
          className="sb-btn"
          onClick={() => data.setSubView('withdraw')}
          disabled={!activeAccount || !displayAddr}
        >
          Withdraw
        </button>
      </div>

      {!activeAccount ? (
        <section className="sb-card">
          <div className="sb-card__title">
            <span>Set up Bitcoin</span>
            <InfoTip title="Set up Bitcoin" label="About Bitcoin setup">
              <p>Deposits and withdrawals need a Bitcoin account on this device: it holds the on-chain BTC that becomes dBTC, and the keys that pay a withdrawal out. You type the address each withdrawal goes to.</p>
              <p><b>New wallet</b> creates one and shows its recovery phrase once. <b>Import</b> takes a recovery phrase, an extended private key or a single key you already have.</p>
            </InfoTip>
          </div>
          <p className="sb-hint">Create a new wallet, or import one you already have.</p>
          {accountsPanel}
        </section>
      ) : (
        <section className="sb-card">
          <div className="sb-card__title">
            <span>Your Bitcoin address</span>
            <span className="sb-tag">{networkLabel}</span>
          </div>
          <div className="btc-address">
            <div className="sb-mono">{displayAddr ? displayAddr.address : '—'}</div>
            <button type="button" className="sb-btn sb-btn--small" onClick={data.handleCopy} disabled={!displayAddr}>
              {data.copied ? 'Copied' : 'Copy'}
            </button>
          </div>
          {isPendingIndexChange && (
            <p className="sb-hint sb-hint--tight">
              Previewing address #{data.selectedIndex}. Choose &ldquo;Use this&rdquo; under Advanced before withdrawing to it.
            </p>
          )}
        </section>
      )}

      {data.walletMessage && activeAccount && (
        <Notice kind={data.walletMessage.startsWith('Error') ? 'error' : 'info'} onClose={() => data.setWalletMessage(null)}>
          {data.walletMessage}
        </Notice>
      )}

      {(inFlight.length > 0 || settled.length > 0) && (
        <section>
          <div className="sb-section-title">Activity</div>
          {inFlight.map((deposit) => (
            <DepositCard key={deposit.vaultOpId} deposit={deposit} onRefresh={data.loadData} network={activeNetwork} />
          ))}
          {settled.length > 0 && !showSettled && (
            <button type="button" className="sb-btn sb-btn--ghost sb-btn--small sb-btn--block" onClick={() => setShowSettled(true)}>
              Show {settled.length} completed
            </button>
          )}
          {showSettled && settled.map((deposit) => (
            <DepositCard key={deposit.vaultOpId} deposit={deposit} onRefresh={data.loadData} network={activeNetwork} />
          ))}
        </section>
      )}

      <Disclosure summary="Advanced" className="btc-advanced">
        <div className="sb-kv">
          <span className="sb-kv__k">Network</span>
          <span className="sb-kv__v">{networkLabel}</span>
        </div>
        {data.walletHealth && (
          <>
            <div className="sb-kv">
              <span className="sb-kv__k">Node</span>
              <span className="sb-kv__v">
                {data.walletHealth.source === 'MEMPOOL' ? 'mempool.space' : 'RPC'} {'·'} {data.walletHealth.reachable ? 'connected' : 'unreachable'}
              </span>
            </div>
            {data.walletHealth.rpcUrl && (
              <div className="sb-kv">
                <span className="sb-kv__k">Endpoint</span>
                <span className="sb-kv__v sb-kv__v--mono">{data.walletHealth.rpcUrl}</span>
              </div>
            )}
            {data.walletHealth.reason && <p className="sb-hint sb-hint--tight">{data.walletHealth.reason}</p>}
          </>
        )}
        {pendingSats > 0n && (
          <div className="sb-kv">
            <span className="sb-kv__k">Held for withdrawal</span>
            <span className="sb-kv__v">{formatBtc(pendingSats)} BTC</span>
          </div>
        )}

        {activeAccount && !isWif && (
          <>
            <div className="sb-titlebar">
              <div className="sb-section-title">Receive address</div>
              <InfoTip title="Receive address" label="About receive addresses">
                <p>Every index is a different address from the same wallet. Funds sent to any of them belong to you; the active one is what this tab shows and copies.</p>
                <p>Withdrawals go to the address you type in the Withdraw form. Pick an index to preview it, then <b>Use this</b> to make it active.</p>
              </InfoTip>
            </div>
            <div className="sb-input-row">
              <select
                className="sb-input sb-input--small"
                value={data.selectedIndex}
                onChange={(e) => void data.handleAddressSelect(Number(e.target.value))}
                aria-label="Receive address index"
              >
                {Array.from({ length: 10 }, (_, i) => {
                  const cached = data.addressCache.get(i);
                  const preview = cached ? ` (${cached.address.slice(0, 10)}…)` : '';
                  return <option key={i} value={i}>Address #{i}{preview}</option>;
                })}
              </select>
              <button
                type="button"
                className="sb-btn sb-btn--small"
                onClick={() => void data.handleAddressUse()}
                disabled={data.addressSelectLoading || !isPendingIndexChange}
              >
                {data.addressSelectLoading ? '…' : 'Use this'}
              </button>
            </div>
            <p className="sb-hint sb-hint--tight">Active: #{data.address?.index ?? 0}.</p>
          </>
        )}
        {activeAccount && isWif && (
          <p className="sb-hint">Single-key account: it has one address.</p>
        )}

        {activeAccount && (
          <>
            <div className="sb-section-title">Bitcoin accounts</div>
            {accountsPanel}
          </>
        )}

        {data.vaults.length > 0 && (
          <>
            <div className="sb-titlebar">
              <div className="sb-section-title">Vaults ({data.vaults.length})</div>
              <InfoTip title="Vaults" label="About vaults">
                <p>The on-chain vaults behind your dBTC: each holds BTC locked for a deposit. This list is status only.</p>
                <p><b>Active</b> vaults back your balance. <b>Pending</b> ones are still confirming. <b>Spent</b> and <b>Void</b> are history. A withdrawal plans itself across the active ones; you never pick one.</p>
              </InfoTip>
            </div>
            {data.vaults.map((v) => (
              <VaultCard key={v.vaultId} vault={v} />
            ))}
          </>
        )}
      </Disclosure>
    </div>
  );
}
