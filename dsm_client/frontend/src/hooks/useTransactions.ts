// SPDX-License-Identifier: Apache-2.0
// path: dsm_client/frontend/src/hooks/useTransactions.ts

// The wallet history as Rust reports it (`wallet.history`, mapped strictly at
// the envelope boundary). Nothing here re-derives, defaults or relabels a row.

import { useCallback, useEffect, useState } from 'react';
import { dsmClient } from '@/services/dsmClient';
import type { DomainTransaction } from '@/domain/types';
import logger from '@/utils/logger';

export type Transaction = DomainTransaction;

export function useTransactions() {
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setError(null);
    const history = await dsmClient.getWalletHistory();
    setTransactions(history.transactions);
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        // Only refresh if we have an identity
        const hasIdentity = await dsmClient.isReady();
        if (!hasIdentity) {
          logger.debug('[useTransactions] Skipping refresh: no identity yet');
          return;
        }
        await refresh();
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => { cancelled = true; };
  }, [refresh]);

  return {
    transactions,
    error,
    refresh,
  };
}
