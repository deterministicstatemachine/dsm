// SPDX-License-Identifier: Apache-2.0
// path: dsm_client/frontend/src/hooks/useTransactions.ts

// The wallet history as Rust reports it (`wallet.history`, mapped strictly at
// the envelope boundary). Nothing here re-derives, defaults or relabels a row.

import { useCallback, useEffect, useState } from 'react';
import { dsmClient } from '@/services/dsmClient';
import { checkIdentityState } from '@/utils/identity';
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
        // History exists only for an identity. The native session is Rust's
        // word on whether there is one; "missing" and "runtime not ready" are
        // both no read, and each is logged as itself.
        const state = await checkIdentityState();
        if (state !== 'READY') {
          logger.debug(`[useTransactions] no history read: identity ${state}`);
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
