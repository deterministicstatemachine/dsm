// SPDX-License-Identifier: Apache-2.0
import React from 'react';
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

  return (
    <div style={{ marginBottom: 16 }}>
      <h3 style={{ margin: '0 0 8px 0', fontSize: 14, fontWeight: 500 }}>Bitcoin Accounts</h3>

      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
        <select value={globalNetwork} onChange={(e) => setGlobalNetwork(Number(e.target.value))} className="form-input" style={{ flex: 1 }}>
          <option value={0}>mainnet</option>
          <option value={1}>testnet</option>
          <option value={2}>signet</option>
        </select>
      </div>

      <div style={{ display: 'flex', gap: 4, marginBottom: 8 }}>
        {(['create', 'import'] as const).map((tab) => (
          <button key={tab} onClick={() => setWalletTab(tab)} className="button-brick" style={{ flex: 1, padding: '6px 0', fontSize: 11, borderRadius: 8, opacity: walletTab === tab ? 1 : 0.45, fontWeight: walletTab === tab ? 600 : 400 }}>
            {tab === 'create' ? 'New Wallet' : 'Import'}
          </button>
        ))}
      </div>

      <div style={{ border: '1px solid var(--border)', borderRadius: 8, padding: 10, marginBottom: 10 }}>
        {walletTab === 'create' ? (
          generatedMnemonic ? (
            <>
              <div style={{ fontSize: 11, fontWeight: 600, marginBottom: 6, color: 'var(--text-dark)' }}>Back up your recovery phrase</div>
              <div style={{ fontSize: 10, color: 'var(--text-disabled)', marginBottom: 8 }}>Write these words down or copy them somewhere safe. This is the only time you&apos;ll see this.</div>
              <textarea readOnly value={generatedMnemonic} className="form-input btc-tap-themed-input" style={{ width: '100%', minHeight: 72, boxSizing: 'border-box', fontFamily: 'ui-monospace, monospace', fontSize: 10, marginBottom: 8, letterSpacing: '0.02em' }} />
              <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
                <button onClick={() => void handleMnemonicCopy()} className="button-brick" style={{ flex: 1, fontSize: 10, padding: '6px 0', borderRadius: 8 }}>
                  {mnemonicCopied ? 'Copied' : 'Copy phrase'}
                </button>
              </div>
              <label className="dsm-toggle" style={{ marginBottom: 8 }}>
                <input type="checkbox" checked={mnemonicConfirmed} onChange={(e) => setMnemonicConfirmed(e.target.checked)} />
                <span className="dsm-checkmark" aria-hidden="true" />
                <span className="dsm-label-text">I&apos;ve saved my recovery phrase</span>
              </label>
              <button onClick={handleMnemonicDone} className="button-brick" disabled={!mnemonicConfirmed} style={{ width: '100%', padding: '8px 0', fontSize: 11, borderRadius: 8 }}>Done</button>
            </>
          ) : (
            <>
              <input type="text" value={createLabel} onChange={(e) => setCreateLabel(e.target.value)} placeholder="Wallet name (optional)" className="form-input" style={{ width: '100%', boxSizing: 'border-box', marginBottom: 8 }} />
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <label style={{ fontSize: 10, color: 'var(--text-disabled)', whiteSpace: 'nowrap' }}>Recovery phrase</label>
                <select value={createWordCount} onChange={(e) => setCreateWordCount(Number(e.target.value) as 12 | 24)} className="form-input" style={{ flex: 1 }}>
                  <option value={12}>12 words</option>
                  <option value={24}>24 words (recommended)</option>
                </select>
              </div>
              <button onClick={() => void handleCreateWallet()} className="button-brick" disabled={createLoading} style={{ width: '100%', padding: '8px 10px', fontSize: 11, borderRadius: 8 }}>
                {createLoading ? 'Generating…' : 'Create Wallet'}
              </button>
            </>
          )
        ) : (
          <>
            <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
              <select value={importKind} onChange={(e) => setImportKind(e.target.value as 'wif' | 'xpriv' | 'mnemonic')} className="form-input" style={{ flex: 1, boxSizing: 'border-box' }}>
                <option value="mnemonic">mnemonic</option>
                <option value="xpriv">xpriv</option>
                <option value="wif">wif</option>
              </select>
            </div>
            <input type="text" value={importLabel} onChange={(e) => setImportLabel(e.target.value)} placeholder="Label (optional)" className="form-input" style={{ width: '100%', boxSizing: 'border-box', marginBottom: 8 }} />
            {importKind !== 'wif' && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <label style={{ fontSize: 10, color: 'var(--text-disabled)', whiteSpace: 'nowrap' }}>Starting index</label>
                <input type="number" min={0} max={999} value={importStartIndex} onChange={(e) => setImportStartIndex(Math.max(0, Number(e.target.value)))} className="form-input" style={{ width: 72, boxSizing: 'border-box' }} />
              </div>
            )}
            <textarea value={importSecret} onChange={(e) => setImportSecret(e.target.value)} placeholder="Paste mnemonic, xpriv, or WIF" className="form-input btc-tap-themed-input" style={{ width: '100%', minHeight: 56, boxSizing: 'border-box', marginBottom: 8 }} />
            <button onClick={() => void handleImportWallet()} className="button-brick" disabled={walletLoading || !importSecret.trim()} style={{ width: '100%', padding: '8px 10px', fontSize: 11, borderRadius: 8 }}>
              {walletLoading ? 'Working…' : 'Import Wallet'}
            </button>
          </>
        )}
      </div>

      {walletAccounts.length > 0 && (
        <div style={{ border: '1px solid var(--border)', borderRadius: 8, padding: 8 }}>
          {walletAccounts.map((acct) => (
            <div key={acct.accountId} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 4px', borderBottom: '1px solid var(--border)' }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 11, fontWeight: 500 }}>{acct.label}</div>
                <div style={{ fontSize: 10, color: 'var(--text-disabled)', overflow: 'hidden', textOverflow: 'ellipsis' }}>{acct.importKind} • {acct.firstAddress || acct.accountId}</div>
              </div>
              {acct.active || acct.accountId === walletActiveId ? (
                <span style={{ fontSize: 10, color: 'var(--text-dark)' }}>active</span>
              ) : (
                <button onClick={() => void handleSelectWallet(acct.accountId)} className="button-brick" disabled={walletLoading} style={{ fontSize: 10, padding: '4px 8px', borderRadius: 6 }}>Use</button>
              )}
            </div>
          ))}
        </div>
      )}

      {walletMessage && (
        <div style={{ marginTop: 8, padding: '6px 8px', border: '1px solid var(--border)', borderRadius: 4, fontSize: 10, whiteSpace: 'pre-wrap', wordBreak: 'break-all', color: 'var(--text-dark)', background: walletMessage.startsWith('Error') ? 'var(--bg-secondary)' : 'var(--bg)', borderStyle: walletMessage.startsWith('Error') ? 'dashed' : 'solid' }}>
          {walletMessage}
        </div>
      )}
    </div>
  );
});

export default WalletAccountsPanel;
