// SPDX-License-Identifier: Apache-2.0
import { useState, useCallback } from 'react';
import { createBitcoinWallet, importBitcoinWallet, normalizeBitcoinUiNetwork } from '../../../../services/bitcoinTap';

export function useBitcoinWallet(loadData: () => Promise<void>, setWalletMessage: (msg: string | null) => void) {
  const [walletTab, setWalletTab] = useState<'create' | 'import'>('create');
  const [globalNetwork, setGlobalNetworkState] = useState(2);
  const [createWordCount, setCreateWordCount] = useState<12 | 24>(24);
  const [createLabel, setCreateLabel] = useState('');
  const [createLoading, setCreateLoading] = useState(false);
  const [generatedMnemonic, setGeneratedMnemonic] = useState<string | null>(null);
  const [mnemonicCopied, setMnemonicCopied] = useState(false);
  const [mnemonicConfirmed, setMnemonicConfirmed] = useState(false);
  const [importKind, setImportKind] = useState<'wif' | 'xpriv' | 'mnemonic'>('mnemonic');
  const [importSecret, setImportSecret] = useState('');
  const [importLabel, setImportLabel] = useState('');
  const [importStartIndex, setImportStartIndex] = useState(0);

  const setGlobalNetwork = useCallback((network: number) => {
    setGlobalNetworkState(normalizeBitcoinUiNetwork(network));
  }, []);

  const handleCreateWallet = useCallback(async () => {
    if (createLoading) return;
    setCreateLoading(true);
    setWalletMessage(null);
    try {
      const resp = await createBitcoinWallet(globalNetwork, createLabel.trim(), createWordCount);
      setGeneratedMnemonic(resp.mnemonic);
      setMnemonicCopied(false);
      setMnemonicConfirmed(false);
      setCreateLabel('');
      await loadData();
    } catch (e) {
      setWalletMessage(`Error: ${e instanceof Error ? e.message : 'Wallet creation failed'}`);
    } finally {
      setCreateLoading(false);
    }
  }, [createLoading, globalNetwork, createLabel, createWordCount, loadData, setWalletMessage]);

  const handleImportWallet = useCallback(async () => {
    if (createLoading || !importSecret.trim()) return;
    setCreateLoading(true);
    setWalletMessage(null);
    try {
      const resp = await importBitcoinWallet(importKind, importSecret.trim(), importLabel.trim(), globalNetwork, importStartIndex);
      setWalletMessage(resp.message || `Imported wallet ${resp.accountId}`);
      setImportSecret('');
      setImportLabel('');
      setImportStartIndex(0);
      await loadData();
    } catch (e) {
      setWalletMessage(`Error: ${e instanceof Error ? e.message : 'Wallet import failed'}`);
    } finally {
      setCreateLoading(false);
    }
  }, [createLoading, importSecret, importKind, importLabel, globalNetwork, importStartIndex, loadData, setWalletMessage]);

  const handleMnemonicCopy = useCallback(async () => {
    if (!generatedMnemonic) return;
    await navigator.clipboard.writeText(generatedMnemonic);
    setMnemonicCopied(true);
  }, [generatedMnemonic]);

  const handleMnemonicDone = useCallback(() => {
    setGeneratedMnemonic(null);
    setMnemonicConfirmed(false);
    setMnemonicCopied(false);
  }, []);

  return {
    walletTab, setWalletTab, globalNetwork, setGlobalNetwork,
    createWordCount, setCreateWordCount, createLabel, setCreateLabel, createLoading,
    generatedMnemonic, mnemonicCopied, mnemonicConfirmed, setMnemonicConfirmed,
    importKind, setImportKind, importSecret, setImportSecret,
    importLabel, setImportLabel, importStartIndex, setImportStartIndex,
    handleCreateWallet, handleImportWallet, handleMnemonicCopy, handleMnemonicDone,
  };
}
