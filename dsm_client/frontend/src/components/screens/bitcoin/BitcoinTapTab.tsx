// SPDX-License-Identifier: Apache-2.0
// BitcoinTapTab — Bitcoin Tap wallet tab (dBTC <-> BTC via HTLC deposits)
// Orchestrator component delegating to sub-views and hooks.
import React from 'react';
import { bitcoinNetworkLabel, formatBtc, normalizeBitcoinUiNetwork } from '../../../services/bitcoinTap';
import { useBitcoinTapData } from './hooks/useBitcoinTapData';
import { useBitcoinWallet } from './hooks/useBitcoinWallet';
import DepositView from './DepositView';
import WithdrawView from './WithdrawView';
import WalletAccountsPanel from './WalletAccountsPanel';
import DepositCard from './DepositCard';
import VaultCard from './VaultCard';

export default function BitcoinTapTab({ btcLogoSrc = 'images/logos/btc-logo.gif' }: { btcLogoSrc?: string }): JSX.Element {
  const data = useBitcoinTapData();
  const wallet = useBitcoinWallet(data.loadData, data.setWalletMessage);

  const activeAccount = data.walletAccounts.find(a => a.active || a.accountId === data.walletActiveId);
  const activeVaultCount = data.vaults.filter((vault) => vault.state === 'active').length;
  const displayAddr = data.addressCache.get(data.selectedIndex) ?? data.address;
  const isPendingIndexChange = data.selectedIndex !== (data.address?.index ?? 0);
  const isWif = activeAccount?.importKind === 'wif';
  const activeNetwork = normalizeBitcoinUiNetwork(activeAccount?.network ?? wallet.globalNetwork);
  const networkLabel = activeAccount ? bitcoinNetworkLabel(activeAccount.network) : null;

  if (data.loading) {
    return <div style={{ padding: 20, textAlign: 'center', fontSize: 12 }}>Loading Bitcoin Tap...</div>;
  }

  if (data.subView === 'deposit') {
    return <DepositView balance={data.balance} nativeBalance={data.nativeBalance} network={activeNetwork} onBack={() => data.setSubView('main')} onRefresh={data.loadData} />;
  }

  if (data.subView === 'withdraw') {
    return <WithdrawView balance={data.balance} nativeBalance={data.nativeBalance} vaults={data.vaults} network={activeNetwork} onBack={() => data.setSubView('main')} onRefresh={data.loadData} />;
  }

  return (
    <div className="bitcoin-tap-tab" style={{ padding: '0 4px' }}>
      {data.error && (
        <div style={{ padding: '8px 12px', marginBottom: 8, background: 'var(--bg-secondary)', border: '2px dashed var(--border)', fontSize: 12, display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--text-dark)' }}>
          <span>{data.error}</span>
          <button onClick={() => data.setError(null)} style={{ background: 'transparent', border: 'none', color: 'inherit', cursor: 'pointer', fontSize: 14 }}>x</button>
        </div>
      )}

      {/* Tap Overview */}
      <div className="balance-section" style={{ marginBottom: 12 }}>
        <h3 style={{ margin: '0 0 8px 0', fontSize: 14, fontWeight: 500 }}>Tap Overview</h3>
        <div className="balance-card btc-tap-summary-card btc-tap-overview-card">
          <div className="balance-info btc-tap-summary-col">
            <span className="token-symbol">Wallet</span>
            <span className="balance-amount btc-tap-summary-amount-sm">{activeAccount ? activeAccount.label : 'Not configured'}</span>
          </div>
          <div className="balance-info btc-tap-summary-col btc-tap-summary-col-right">
            <span className="token-symbol">Tap</span>
            <span className="balance-amount btc-tap-summary-amount-sm">{activeVaultCount > 0 ? `${activeVaultCount} active` : 'Idle'}</span>
          </div>
        </div>
        {isPendingIndexChange && (
          <div className="btc-tap-hint">Address index {data.selectedIndex} is preview-only. Click <strong>Use This</strong> before withdrawing.</div>
        )}
      </div>

      {/* dBTC Balance */}
      <div className="balance-section" style={{ marginBottom: 16 }}>
        <h3 style={{ margin: '0 0 8px 0', fontSize: 14, fontWeight: 500 }}>dBTC Balance (DSM)</h3>
        <div className="balance-card" style={{ padding: '12px 16px' }}>
          <div className="balance-info">
            <span className="token-symbol" style={{ display: 'flex', alignItems: 'center' }}>
              <img src={btcLogoSrc} alt="dBTC" className="btc-gif small" style={{ flexShrink: 0 }} />dBTC
            </span>
            <span className="balance-amount" style={{ fontSize: 16 }}>{data.balance ? formatBtc(data.balance.available) : '0.00000000'}</span>
          </div>
        </div>
        {data.balance && data.balance.locked > 0n && (
          <div style={{ fontSize: 10, color: 'var(--text-disabled)', marginTop: 4, paddingLeft: 4 }}>Locked in HTLCs: {formatBtc(data.balance.locked)} BTC</div>
        )}
      </div>

      {/* Native BTC Balance */}
      <div className="balance-section" style={{ marginBottom: 16 }}>
        <h3 style={{ margin: '0 0 8px 0', fontSize: 14, fontWeight: 500 }}>
          Native BTC Balance
          {data.walletHealth?.source && <span style={{ marginLeft: 8, fontSize: 10, fontWeight: 600, opacity: 0.85 }}>[{data.walletHealth.source}]</span>}
          {data.walletHealth?.network && <span style={{ marginLeft: 6, fontSize: 10, fontWeight: 400, color: 'var(--text-disabled)', textTransform: 'uppercase' }}>{data.walletHealth.network}</span>}
        </h3>
        <div className="balance-card" style={{ padding: '12px 16px' }}>
          <div className="balance-info">
            <span className="token-symbol" style={{ display: 'flex', alignItems: 'center' }}>
              <img src={btcLogoSrc} alt="BTC" className="btc-gif small" style={{ flexShrink: 0 }} />BTC
            </span>
            <span className="balance-amount" style={{ fontSize: 16 }}>{data.nativeBalance ? formatBtc(data.nativeBalance.available) : '0.00000000'}</span>
          </div>
        </div>
        {data.nativeBalance && data.nativeBalance.locked > 0n && (
          <div style={{ fontSize: 10, color: 'var(--text-disabled)', marginTop: 4, paddingLeft: 4 }}>Pending outgoing: {formatBtc(data.nativeBalance.locked)} BTC</div>
        )}
        {data.walletHealth && (
          <div style={{ fontSize: 10, color: 'var(--text-disabled)', marginTop: 6, paddingLeft: 4 }}>
            {data.walletHealth.source === 'MEMPOOL' ? 'Mempool.space' : 'RPC'}: {data.walletHealth.reachable ? 'Connected' : 'Unavailable'} • Network: {data.walletHealth.network}{data.walletHealth.rpcUrl ? ` • ${data.walletHealth.rpcUrl}` : ''}{data.walletHealth.reason ? ` • ${data.walletHealth.reason}` : ''}
          </div>
        )}
      </div>

      {/* Address Section */}
      <div style={{ marginBottom: 16 }}>
        <h3 style={{ margin: '0 0 8px 0', fontSize: 14, fontWeight: 500 }}>
          Your Bitcoin Address
          {networkLabel && <span style={{ marginLeft: 8, fontSize: 10, fontWeight: 400, color: 'var(--text-disabled)', textTransform: 'uppercase' }}>[{networkLabel}]</span>}
        </h3>
        {!activeAccount ? (
          <div style={{ padding: '12px 14px', border: '1px dashed var(--border)', borderRadius: 8, fontSize: 11, color: 'var(--text-disabled)', textAlign: 'center' }}>
            No wallet yet — use Bitcoin Accounts below to create one or import an existing one.
          </div>
        ) : (
          <>
            {!isWif && (
              <div style={{ display: 'flex', gap: 8, marginBottom: 8, alignItems: 'center' }}>
                <select value={data.selectedIndex} onChange={(e) => void data.handleAddressSelect(Number(e.target.value))} className="form-input" style={{ flex: 1 }}>
                  {Array.from({ length: 10 }, (_, i) => {
                    const cached = data.addressCache.get(i);
                    const preview = cached ? ` (${cached.address.slice(0, 10)}…)` : '';
                    return <option key={i} value={i}>Address #{i}{preview}</option>;
                  })}
                </select>
                <button onClick={() => void data.handleAddressUse()} className="button-brick" disabled={data.addressSelectLoading || data.selectedIndex === (data.address?.index ?? 0)} style={{ fontSize: 10, padding: '6px 10px', borderRadius: 8, whiteSpace: 'nowrap' }}>
                  {data.addressSelectLoading ? '...' : 'Use This'}
                </button>
              </div>
            )}
            <div className="address-display" style={{ padding: '10px 12px' }}>
              <div className="address-text" style={{ fontSize: 10, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace' }}>{displayAddr ? displayAddr.address : '—'}</div>
              <button onClick={data.handleCopy} className="copy-button button-brick" style={{ fontSize: 10, padding: '6px 10px', borderRadius: 8, whiteSpace: 'nowrap' }} disabled={!displayAddr}>
                {data.copied ? 'Copied' : 'Copy'}
              </button>
            </div>
            {displayAddr && (
              <div style={{ fontSize: 9, color: 'var(--text-disabled)', paddingLeft: 4 }}>
                {isWif ? 'Single-key account — index selection not available' : `Index: ${displayAddr.index}${displayAddr.index === (data.address?.index ?? 0) ? ' • active' : ' • preview only'}`}
              </div>
            )}
          </>
        )}
      </div>

      {/* Action Buttons */}
      <div className="quick-actions" style={{ marginBottom: 16 }}>
        <button onClick={() => data.setSubView('deposit')} className="action-button button-brick" style={{ fontSize: 11 }}>Deposit (BTC → dBTC)</button>
        <button onClick={() => data.setSubView('withdraw')} className="action-button button-brick" style={{ fontSize: 11 }} disabled={!activeAccount || !displayAddr}>Withdraw (dBTC → BTC)</button>
      </div>

      {!activeAccount && (
        <div className="btc-tap-hint btc-tap-hint-muted" style={{ marginTop: -8, marginBottom: 14 }}>
          Create or import a Bitcoin account below to enable deposits and withdrawals.
        </div>
      )}

      {/* Wallet Accounts */}
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

      {/* Active Deposits */}
      {data.deposits.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <h3 style={{ margin: '0 0 8px 0', fontSize: 14, fontWeight: 500 }}>Active Deposits</h3>
          {data.deposits.map((deposit) => (
            <DepositCard key={deposit.vaultOpId} deposit={deposit} onRefresh={data.loadData} network={activeNetwork} />
          ))}
        </div>
      )}

      {/* Vault Monitor */}
      {data.vaults.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <h3 style={{ margin: '0 0 8px 0', fontSize: 14, fontWeight: 500, cursor: 'pointer' }} onClick={() => data.setVaultsExpanded(!data.vaultsExpanded)}>
            {data.vaultsExpanded ? '\u25BC' : '\u25B6'} DLV Vaults ({data.vaults.length})
          </h3>
          {data.vaultsExpanded && data.vaults.map((v) => (
            <VaultCard key={v.vaultId} vault={v} />
          ))}
        </div>
      )}
    </div>
  );
}
