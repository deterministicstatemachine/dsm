// SPDX-License-Identifier: Apache-2.0
// The payments held pending, read from Rust whenever the balances the wallet
// store holds are read again: a payment received offline, and its settlement,
// each change what the wallet holds, and the store reloads on every change.
import { useEffect, useRef, useState } from 'react';
import { getPendingOffline, type PendingOfflineReceipt } from '../../../../dsm/pendingOffline';

export type PendingOfflineState = {
  receipts: PendingOfflineReceipt[];
  /** The last read failed, in Rust's words; the receipts are the last read's. */
  error: string | null;
};

export function usePendingOffline(readAgainWhen: unknown): PendingOfflineState {
  const [state, setState] = useState<PendingOfflineState>({ receipts: [], error: null });
  // Only the latest read answers: one started earlier and finishing later
  // would show an older list.
  const latest = useRef(0);
  useEffect(() => {
    latest.current += 1;
    const read = latest.current;
    getPendingOffline().then(
      (receipts) => {
        if (latest.current === read) setState({ receipts, error: null });
      },
      (e: unknown) => {
        if (latest.current === read) {
          const error = e instanceof Error ? e.message : String(e);
          setState((prev) => ({ receipts: prev.receipts, error }));
        }
      },
    );
  }, [readAgainWhen]);
  return state;
}
