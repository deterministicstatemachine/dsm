// SPDX-License-Identifier: Apache-2.0
import { useState, useCallback, useEffect } from 'react';
import {
  getBitcoinAddress,
  peekBitcoinAddress,
  selectBitcoinAddress,
  getDbtcBalance,
  getNativeBtcBalance,
  getBitcoinWalletHealth,
  listDeposits,
  listBitcoinWalletAccounts,
  selectBitcoinWalletAccount,
  listVaults,
  settleWithdrawals,
} from '../../../../services/bitcoinTap';
import type {
  BitcoinAddress,
  DbtcBalance,
  NativeBtcBalance,
  BitcoinWalletHealth,
  DepositEntry,
  BitcoinWalletAccountEntry,
  VaultSummary,
} from '../../../../services/bitcoinTap';

export type SubView = 'main' | 'deposit' | 'withdraw';

export function useBitcoinTapData() {
  const [address, setAddress] = useState<BitcoinAddress | null>(null);
  const [balance, setBalance] = useState<DbtcBalance | null>(null);
  const [nativeBalance, setNativeBalance] = useState<NativeBtcBalance | null>(null);
  const [walletHealth, setWalletHealth] = useState<BitcoinWalletHealth | null>(null);
  const [deposits, setDeposits] = useState<DepositEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [subView, setSubView] = useState<SubView>('main');
  const [walletAccounts, setWalletAccounts] = useState<BitcoinWalletAccountEntry[]>([]);
  const [walletActiveId, setWalletActiveId] = useState('');
  const [walletLoading, setWalletLoading] = useState(false);
  const [walletMessage, setWalletMessage] = useState<string | null>(null);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [addressCache, setAddressCache] = useState<Map<number, BitcoinAddress>>(() => new Map());
  const [addressSelectLoading, setAddressSelectLoading] = useState(false);
  const [vaults, setVaults] = useState<VaultSummary[]>([]);
  const [vaultsExpanded, setVaultsExpanded] = useState(false);

  const loadData = useCallback(async () => {
    try {
      setError(null);
      const walletList = await listBitcoinWalletAccounts();
      const hasActiveWallet = walletList?.accounts.some(a => a.active) ?? false;

      const [bal, nativeBal, depositList] = await Promise.all([
        getDbtcBalance(),
        getNativeBtcBalance(),
        listDeposits(),
      ]);

      if (hasActiveWallet) {
        const addr = await getBitcoinAddress();
        setAddress(addr);
        setSelectedIndex(addr.index);
        setAddressCache(prev => { const next = new Map(prev); next.set(addr.index, addr); return next; });
      } else {
        setAddress(null);
      }

      setBalance(bal);
      setNativeBalance(nativeBal);
      setDeposits(depositList);
      const health = await getBitcoinWalletHealth();
      setWalletHealth(health);
      setWalletAccounts(walletList.accounts);
      setWalletActiveId(walletList.activeAccountId);
      const vaultList = await listVaults();
      setVaults(vaultList);

      // dBTC §13: resolve any committed in-flight withdrawals (settle or refund).
      // Best-effort — runs on every data refresh (mount, pull-to-refresh, foreground).
      settleWithdrawals().catch(() => { /* settlement polling is non-fatal */ });
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load Bitcoin data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void loadData(); }, [loadData]);

  const findActiveVault = useCallback(() => {
    // Only vaults in active or limbo state are eligible for withdrawal.
    // Exclude: unlocked, claimed, invalidated
    const isWithdrawable = (state: string) => state === 'active' || state === 'limbo';
    const depositVault = vaults.find(
      (v) => v.direction === 'btc_to_dbtc' && v.amountSats > 0n && isWithdrawable(v.state),
    );
    if (depositVault) return depositVault;
    return vaults.find(
      (v) => v.amountSats > 0n && isWithdrawable(v.state),
    );
  }, [vaults]);

  const handleCopy = useCallback(() => {
    const displayAddr = addressCache.get(selectedIndex) ?? address;
    if (!displayAddr) return;
    void navigator.clipboard.writeText(displayAddr.address).then(() => { setCopied(true); }).catch(() => {});
  }, [address, addressCache, selectedIndex]);

  const handleAddressSelect = useCallback(async (idx: number) => {
    setSelectedIndex(idx);
    if (!addressCache.has(idx)) {
      try {
        const peeked = await peekBitcoinAddress(idx);
        setAddressCache(prev => { const m = new Map(prev); m.set(idx, peeked); return m; });
      } catch { /* preview fetch failed */ }
    }
  }, [addressCache]);

  const handleAddressUse = useCallback(async () => {
    if (addressSelectLoading) return;
    setAddressSelectLoading(true);
    try {
      const selected = await selectBitcoinAddress(selectedIndex);
      setAddress(selected);
      setAddressCache(prev => { const m = new Map(prev); m.set(selectedIndex, selected); return m; });
      setWalletMessage(`Active address set to index ${selectedIndex}`);
    } catch (e) {
      setWalletMessage(`Error: ${e instanceof Error ? e.message : 'Select failed'}`);
    } finally {
      setAddressSelectLoading(false);
    }
  }, [addressSelectLoading, selectedIndex]);

  const handleSelectWallet = useCallback(async (accountId: string) => {
    if (walletLoading) return;
    setWalletLoading(true);
    setWalletMessage(null);
    try {
      const resp = await selectBitcoinWalletAccount(accountId);
      setWalletActiveId(resp.activeAccountId);
      setWalletMessage(resp.message || 'Bitcoin account activated');
      await loadData();
    } catch (e) {
      setWalletMessage(`Error: ${e instanceof Error ? e.message : 'Wallet select failed'}`);
    } finally {
      setWalletLoading(false);
    }
  }, [walletLoading, loadData]);

  return {
    address, balance, nativeBalance, walletHealth, deposits, loading, error, copied,
    subView, setSubView, walletAccounts, walletActiveId, walletLoading, walletMessage, setWalletMessage,
    selectedIndex, addressCache, addressSelectLoading, vaults, vaultsExpanded, setVaultsExpanded,
    loadData, findActiveVault, handleCopy, handleAddressSelect, handleAddressUse,
    handleSelectWallet, setError,
  };
}
