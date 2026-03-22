// SPDX-License-Identifier: Apache-2.0
// Data loading hook for the wallet screen — identity, balances, contacts, transactions.
import { useState, useCallback, useEffect, useMemo, useRef } from 'react';
import { dsmClient } from '../../../../services/dsmClient';
import { formatBtc } from '../../../../services/bitcoinTap';
import { encodeBase32Crockford } from '../../../../utils/textId';
import { useWalletRefreshListener } from '../../../../hooks/useWalletRefreshListener';
import { bridgeEvents } from '../../../../bridge/bridgeEvents';
import { buildAliasLookup } from '../helpers';
import type { Balance } from '../helpers';
import type { DomainContact, DomainIdentity, DomainTransaction } from '../../../../domain/types';
import logger from '../../../../utils/logger';

export type WalletScreenData = {
  identity: DomainIdentity | null;
  genesisB32: string;
  deviceB32: string;
  balances: Balance[];
  contacts: DomainContact[];
  transactions: DomainTransaction[];
  aliasLookup: Map<string, string>;
  loading: boolean;
  error: string | null;
  warning: string | null;
  refreshing: boolean;
  setError: (err: string | null) => void;
  setWarning: (warn: string | null) => void;
  loadWalletData: () => Promise<void>;
  handleRefresh: () => Promise<void>;
  touchFeedback: 'refreshed' | 'copied' | 'transaction_sent' | 'b0x_checked' | null;
  setTouchFeedback: (fb: 'refreshed' | 'copied' | 'transaction_sent' | 'b0x_checked' | null) => void;
};

export function useWalletScreenData(activeTab: string): WalletScreenData {
  const [identity, setIdentity] = useState<DomainIdentity | null>(null);
  const [genesisB32, setGenesisB32] = useState('');
  const [deviceB32, setDeviceB32] = useState('');
  const [balances, setBalances] = useState<Balance[]>([]);
  const [contacts, setContacts] = useState<DomainContact[]>([]);
  const [transactions, setTransactions] = useState<DomainTransaction[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [warning, setWarning] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [touchFeedback, setTouchFeedback] = useState<'refreshed' | 'copied' | 'transaction_sent' | 'b0x_checked' | null>(null);
  const inFlightLoadRef = useRef<Promise<void> | null>(null);
  const reloadQueuedRef = useRef(false);
  const hasLoadedOnceRef = useRef(false);

  const aliasLookup = useMemo(() => buildAliasLookup(contacts), [contacts]);

  const performWalletDataLoad = useCallback(async () => {
    // Only show the full-screen "Loading wallet…" spinner on the very first
    // load.  Subsequent refreshes keep the current UI visible so the screen
    // never flashes back to the spinner during BLE bilateral transfers —
    // which emit wallet.refresh rapidly.
    if (!hasLoadedOnceRef.current) setLoading(true);
    const keepLoading = false;
    try {
      setError(null);
      setWarning(null);
      const warnings: string[] = [];
      const id = await dsmClient.getIdentity();
      if (!id || !id.genesisHash || !id.deviceId) {
        throw new Error('Identity not initialized');
      }
      setIdentity(id);
      setGenesisB32(id.genesisHash);
      setDeviceB32(id.deviceId);

      try {
        const list = await dsmClient.getContacts();
        const normalized: DomainContact[] = list.contacts.map((c) => {
          const deviceId = typeof c.deviceId === 'string'
            ? c.deviceId
            : encodeBase32Crockford(c.deviceId as unknown as Uint8Array);
          const genesisHash = typeof (c as { genesisHash?: unknown }).genesisHash === 'string'
            ? (c as { genesisHash?: string }).genesisHash || ''
            : encodeBase32Crockford((c as { genesisHash?: Uint8Array }).genesisHash ?? new Uint8Array(0));
          const anyC = c as unknown as Record<string, unknown>;
          const tipObj = anyC.chainTip as { tipHash?: Uint8Array } | undefined;
          const chainTipStr = (tipObj && tipObj.tipHash instanceof Uint8Array && tipObj.tipHash.length === 32)
            ? encodeBase32Crockford(tipObj.tipHash)
            : undefined;
          const lastSeen = anyC.lastSeenTick;
          const counterVal = typeof lastSeen === 'bigint' ? Number(lastSeen)
            : typeof lastSeen === 'number' ? lastSeen : undefined;
          return {
            alias: c.alias,
            deviceId,
            genesisHash,
            chainTip: chainTipStr,
            bleAddress: (anyC.bleAddress as string) || undefined,
            status: (anyC.status as string) || undefined,
            needsOnlineReconcile: (anyC.needsOnlineReconcile as boolean) || undefined,
            genesisVerifiedOnline: (anyC.genesisVerifiedOnline as boolean) || undefined,
            verifyCounter: counterVal,
            addedCounter: counterVal,
            verifyingStorageNodes: (anyC.verifyingStorageNodes as number) || undefined,
          };
        });
        setContacts(normalized);
      } catch (e) {
        warnings.push(e instanceof Error ? e.message : 'Failed to load contacts');
      }

      try {
        const bal = await dsmClient.getAllBalances();
        const raw = Array.isArray(bal) ? bal : [];
        const eraTokens: Balance[] = raw
          .filter((b) => b.tokenId.toUpperCase() !== 'BTC_CHAIN')
          .map((b) => ({
            tokenId: b.tokenId,
            symbol: b.symbol || b.ticker || b.tokenId,
            balance: b.tokenId.toUpperCase() === 'DBTC'
              ? formatBtc(b.baseUnits)
              : b.balance,
            decimals: b.decimals,
          }));
        setBalances(eraTokens);
      } catch (e) {
        warnings.push(e instanceof Error ? e.message : 'Failed to load balances');
      }

      try {
        const history = await dsmClient.getWalletHistory();
        if (history && Array.isArray(history.transactions)) {
          setTransactions(history.transactions);
        }
      } catch (e) {
        warnings.push(e instanceof Error ? e.message : 'Failed to load transactions');
      }

      if (warnings.length > 0) {
        setWarning(warnings.join(' \u2022 '));
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load');
    } finally {
      if (!keepLoading) {
        hasLoadedOnceRef.current = true;
        setLoading(false);
      }
    }
  }, []);

  const loadWalletData = useCallback(async () => {
    if (inFlightLoadRef.current) {
      reloadQueuedRef.current = true;
      await inFlightLoadRef.current;
      return;
    }

    do {
      reloadQueuedRef.current = false;
      const run = performWalletDataLoad();
      inFlightLoadRef.current = run;
      try {
        await run;
      } finally {
        inFlightLoadRef.current = null;
      }
    } while (reloadQueuedRef.current);
  }, [performWalletDataLoad]);

  useEffect(() => { void loadWalletData(); }, [loadWalletData]);

  // Listen for wallet refresh events with RAF coalescing to avoid bridge spam.
  useWalletRefreshListener(() => void loadWalletData(), [loadWalletData]);

  // Direct bilateral transfer-complete listener — bypasses the wallet.refresh
  // throttle chain.  When a BLE bilateral transfer completes on the receiver,
  // the event chain (Rust → JNI → Kotlin → MessagePort → EventBridge) emits
  // bilateral.transferComplete.  This direct subscription ensures the wallet
  // data reloads even if the wallet.refresh → useWalletRefreshListener path
  // drops the event (e.g. during cooldown or RAF scheduling edge cases).
  useEffect(() => {
    const unsub = bridgeEvents.on('bilateral.transferComplete', () => {
      logger.debug('[useWalletScreenData] bilateral.transferComplete -> reloading wallet data');
      void loadWalletData();
    });
    return unsub;
  }, [loadWalletData]);

  // Reload when leaving bitcoin tab
  const activeTabRef = useRef(activeTab);
  useEffect(() => {
    const prev = activeTabRef.current;
    if (prev === 'bitcoin' && activeTab !== 'bitcoin') {
      void loadWalletData();
    }
    activeTabRef.current = activeTab;
  }, [activeTab, loadWalletData]);

  const handleRefresh = useCallback(async () => {
    setRefreshing(true);
    await loadWalletData();
    setRefreshing(false);
    setTouchFeedback('refreshed');
  }, [loadWalletData]);

  // Auto-dismiss touchFeedback toast
  useEffect(() => {
    if (!touchFeedback) return;
    const id = setTimeout(() => setTouchFeedback(null), 2500);
    return () => clearTimeout(id);
  }, [touchFeedback]);

  return {
    identity,
    genesisB32,
    deviceB32,
    balances,
    contacts,
    transactions,
    aliasLookup,
    loading,
    error,
    warning,
    refreshing,
    setError,
    setWarning,
    loadWalletData,
    handleRefresh,
    touchFeedback,
    setTouchFeedback,
  };
}
