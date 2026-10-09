// SPDX-License-Identifier: Apache-2.0
// The wallet screen's data. Balances and history are the wallet store's and
// contacts are the contacts store's — the one copy of each, reloaded in the
// providers — and this hook reads them; it used to hold second copies and
// reload them beside the stores', so one wallet change was two reads of
// `balance.list` and `wallet.history`. What the screen owns is the identity,
// read once, or the reason it was not.
import { useState, useCallback, useEffect, useMemo, useRef } from 'react';
import { dsmClient } from '../../../../services/dsmClient';
import { useWallet } from '../../../../contexts/WalletContext';
import { contactsStore, useContactsStore } from '../../../../stores/contactsStore';
import type { TokenBalanceView } from '../../../../dsm/types';
import type { DomainContact, DomainIdentity, DomainTransaction } from '../../../../domain/types';

export type WalletScreenData = {
  identity: DomainIdentity | null;
  genesisB32: string;
  deviceB32: string;
  balances: TokenBalanceView[];
  /** The store has not answered balances yet; nothing is known either way. */
  balancesLoading: boolean;
  contacts: DomainContact[];
  transactions: DomainTransaction[];
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
  const wallet = useWallet();
  const contactsState = useContactsStore();
  const [identity, setIdentity] = useState<DomainIdentity | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [warningDismissed, setWarningDismissed] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [touchFeedback, setTouchFeedback] = useState<'refreshed' | 'copied' | 'transaction_sent' | 'b0x_checked' | null>(null);

  // The identity, answered or refused with its reason: missing, runtime not
  // ready, or not read. The screen shows the reason.
  const loadIdentity = useCallback(async () => {
    try {
      setError(null);
      setIdentity(await dsmClient.getIdentity());
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void loadIdentity(); }, [loadIdentity]);

  // A manual refresh reloads both stores. Balances and history otherwise
  // reload on `wallet.refresh`, in the wallet provider, once per change;
  // contacts on the contact events, in the contacts provider.
  const { refreshAll } = wallet;
  const loadWalletData = useCallback(async () => {
    await Promise.all([refreshAll(), contactsStore.refreshContacts()]);
  }, [refreshAll]);

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

  // What the stores report failed, as they word it; dismissable until it changes.
  const contactsError = contactsState.error;
  const warning = useMemo(() => {
    const parts = [wallet.error, contactsError].filter((w): w is string => Boolean(w));
    const joined = parts.length > 0 ? parts.join(' • ') : null;
    return joined && joined !== warningDismissed ? joined : null;
  }, [wallet.error, contactsError, warningDismissed]);
  const setWarning = useCallback((next: string | null) => {
    if (next === null) {
      setWarningDismissed([wallet.error, contactsError].filter(Boolean).join(' • ') || null);
    }
  }, [wallet.error, contactsError]);

  const contacts: DomainContact[] = contactsState.contacts;

  return {
    identity,
    genesisB32: identity?.genesisHash ?? '',
    deviceB32: identity?.deviceId ?? '',
    balances: wallet.balances,
    balancesLoading: wallet.isLoading && wallet.balances.length === 0,
    contacts,
    transactions: wallet.transactions,
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
