// SPDX-License-Identifier: Apache-2.0
// Bitcoin accounts: the list of accounts on this device, and a form to add one
// (create a new wallet, or import a phrase / key). Rendered inline when there
// is no account yet, and under the Advanced fold once there is.
import React from 'react';
import { bitcoinNetworkLabel } from '../../../services/bitcoinTap';
import { middleTruncate } from '../../common/ScreenFrame';
import { importKindLabel } from './labels';
import type { BitcoinWalletAccountEntry } from '../../../services/bitcoinTap';

type Props = {
  walletAccounts: BitcoinWalletAccountEntry[];
  walletActiveId: string;
  walletLoading: boolean;
  walletMessage: string | null;
  globalNetwork: number;
  setGlobalNetwork: (n: number) => void;
  walletTab: 'create' | 'import';
  setWalletTab: (t: 'create' | 'import') => void;
  createLabel: string;
  setCreateLabel: (s: string) => void;
  createWordCount: 12 | 24;
  setCreateWordCount: (n: 12 | 24) => void;
  createLoading: boolean;
  generatedMnemonic: string | null;
  mnemonicCopied: boolean;
  mnemonicConfirmed: boolean;
  setMnemonicConfirmed: (b: boolean) => void;
  importKind: 'wif' | 'xpriv' | 'mnemonic';
  setImportKind: (k: 'wif' | 'xpriv' | 'mnemonic') => void;
  importSecret: string;
  setImportSecret: (s: string) => void;
  importLabel: string;
  setImportLabel: (s: string) => void;
  importStartIndex: number;
  setImportStartIndex: (n: number) => void;
  handleCreateWallet: () => Promise<void>;
  handleImportWallet: () => Promise<void>;
  handleMnemonicCopy: () => Promise<void>;
  handleMnemonicDone: () => void;
  handleSelectWallet: (accountId: string) => Promise<void>;
};

const WalletAccountsPanel = React.memo(function WalletAccountsPanel(props: Props) {
  const {
    walletAccounts, walletActiveId, walletLoading, walletMessage,
    globalNetwork, setGlobalNetwork, walletTab, setWalletTab,
    createLabel, setCreateLabel, createWordCount, setCreateWordCount,
    createLoading, generatedMnemonic, mnemonicCopied, mnemonicConfirmed, setMnemonicConfirmed,
    importKind, setImportKind, importSecret, setImportSecret,
    importLabel, setImportLabel, importStartIndex, setImportStartIndex,
    handleCreateWallet, handleImportWallet, handleMnemonicCopy, handleMnemonicDone, handleSelectWallet,
  } = props;

  const hasAccounts = walletAccounts.length > 0;

  return (
    <div className="btc-accounts">
      {hasAccounts && (
        <div className="sb-card" style={{ padding: '0 10px' }}>
          {walletAccounts.map((acct) => {
            const isActive = acct.active || acct.accountId === walletActiveId;
            return (
              <div key={acct.accountId} className="sb-row">
                <div className="sb-row__main">
                  <div className="sb-row__title">{acct.label || 'Bitcoin wallet'}</div>
                  <div className="sb-row__sub">
                    {importKindLabel(acct.importKind)} {'·'} {bitcoinNetworkLabel(acct.network)} {'·'} {middleTruncate(acct.firstAddress || acct.accountId, 8, 6)}
                  </div>
                </div>
                {isActive ? (
                  <span className="sb-tag sb-tag--solid">Active</span>
                ) : (
                  <button type="button" onClick={() => void handleSelectWallet(acct.accountId)} className="sb-btn sb-btn--small" disabled={walletLoading}>
                    Use
                  </button>
                )}
              </div>
            );
          })}
        </div>
      )}

      <div className="sb-seg sb-seg--block" role="group" aria-label="Add a Bitcoin account">
        {(['create', 'import'] as const).map((tab) => (
          <button
            key={tab}
            type="button"
            onClick={() => setWalletTab(tab)}
            className={`sb-seg__opt${walletTab === tab ? ' active' : ''}`}
            aria-pressed={walletTab === tab}
          >
            {tab === 'create' ? 'New wallet' : 'Import'}
          </button>
        ))}
      </div>

      <div className="sb-card" style={{ marginTop: 8 }}>
        {walletTab === 'create' ? (
          generatedMnemonic ? (
            <>
              <div className="sb-card__title">Back up your recovery phrase</div>
              <p className="sb-hint">
                Write these words down, in order, and keep them somewhere safe. They are the only way to recover this wallet, and this is the only time they are shown.
              </p>
              <textarea
                readOnly
                value={generatedMnemonic}
                className="sb-input sb-input--mono"
                style={{ minHeight: 84, marginBottom: 8, letterSpacing: '0.02em' }}
                aria-label="Recovery phrase"
              />
              <button type="button" onClick={() => void handleMnemonicCopy()} className="sb-btn sb-btn--small sb-btn--block" style={{ marginBottom: 8 }}>
                {mnemonicCopied ? 'Copied' : 'Copy phrase'}
              </button>
              <label className="dsm-toggle" style={{ marginBottom: 10 }}>
                <input type="checkbox" checked={mnemonicConfirmed} onChange={(e) => setMnemonicConfirmed(e.target.checked)} />
                <span className="dsm-checkmark" aria-hidden="true" />
                <span className="dsm-label-text">I have saved my recovery phrase</span>
              </label>
              <button type="button" onClick={handleMnemonicDone} className="sb-btn sb-btn--primary sb-btn--block" disabled={!mnemonicConfirmed}>
                Done
              </button>
            </>
          ) : (
            <>
              <div className="sb-field">
                <label htmlFor="btc-create-label">Name (optional)</label>
                <input id="btc-create-label" type="text" value={createLabel} onChange={(e) => setCreateLabel(e.target.value)} placeholder="e.g. Main wallet" className="sb-input sb-input--small" />
              </div>
              <div className="sb-field">
                <label htmlFor="btc-create-network">Network</label>
                <select id="btc-create-network" value={globalNetwork} onChange={(e) => setGlobalNetwork(Number(e.target.value))} className="sb-input sb-input--small">
                  <option value={0}>Mainnet</option>
                  <option value={1}>Testnet</option>
                  <option value={2}>Signet</option>
                </select>
              </div>
              <div className="sb-field">
                <label htmlFor="btc-create-words">Recovery phrase</label>
                <select id="btc-create-words" value={createWordCount} onChange={(e) => setCreateWordCount(Number(e.target.value) as 12 | 24)} className="sb-input sb-input--small">
                  <option value={12}>12 words</option>
                  <option value={24}>24 words (recommended)</option>
                </select>
              </div>
              <button type="button" onClick={() => void handleCreateWallet()} className="sb-btn sb-btn--primary sb-btn--block" disabled={createLoading}>
                {createLoading ? 'Generating…' : 'Create wallet'}
              </button>
            </>
          )
        ) : (
          <>
            <div className="sb-field">
              <label htmlFor="btc-import-kind">What are you importing?</label>
              <select id="btc-import-kind" value={importKind} onChange={(e) => setImportKind(e.target.value as 'wif' | 'xpriv' | 'mnemonic')} className="sb-input sb-input--small">
                <option value="mnemonic">Recovery phrase (12 or 24 words)</option>
                <option value="xpriv">Extended private key (xprv)</option>
                <option value="wif">Single private key (WIF)</option>
              </select>
            </div>
            <div className="sb-field">
              <label htmlFor="btc-import-secret">
                {importKind === 'mnemonic' ? 'Recovery phrase' : importKind === 'xpriv' ? 'Extended private key' : 'Private key'}
              </label>
              <textarea
                id="btc-import-secret"
                value={importSecret}
                onChange={(e) => setImportSecret(e.target.value)}
                placeholder={importKind === 'mnemonic' ? 'word word word …' : importKind === 'xpriv' ? 'xprv…' : 'WIF key'}
                className="sb-input sb-input--mono"
                style={{ minHeight: 56 }}
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
              />
            </div>
            <div className="sb-field">
              <label htmlFor="btc-import-label">Name (optional)</label>
              <input id="btc-import-label" type="text" value={importLabel} onChange={(e) => setImportLabel(e.target.value)} placeholder="e.g. Cold wallet" className="sb-input sb-input--small" />
            </div>
            <div className="sb-field">
              <label htmlFor="btc-import-network">Network</label>
              <select id="btc-import-network" value={globalNetwork} onChange={(e) => setGlobalNetwork(Number(e.target.value))} className="sb-input sb-input--small">
                <option value={0}>Mainnet</option>
                <option value={1}>Testnet</option>
                <option value={2}>Signet</option>
              </select>
            </div>
            {importKind !== 'wif' && (
              <div className="sb-field">
                <label htmlFor="btc-import-index">Starting address index</label>
                <input id="btc-import-index" type="number" min={0} max={999} value={importStartIndex} onChange={(e) => setImportStartIndex(Math.max(0, Number(e.target.value)))} className="sb-input sb-input--small" style={{ width: 96 }} />
                <p className="sb-hint sb-hint--tight">Leave at 0 unless you know this wallet used later addresses.</p>
              </div>
            )}
            <button type="button" onClick={() => void handleImportWallet()} className="sb-btn sb-btn--primary sb-btn--block" disabled={walletLoading || !importSecret.trim()}>
              {walletLoading ? 'Working…' : 'Import wallet'}
            </button>
          </>
        )}
      </div>

      {walletMessage && !hasAccounts && (
        <div className={`sb-notice${walletMessage.startsWith('Error') ? ' sb-notice--error' : ''}`} role="status">
          <span style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{walletMessage}</span>
        </div>
      )}
    </div>
  );
});

export default WalletAccountsPanel;
