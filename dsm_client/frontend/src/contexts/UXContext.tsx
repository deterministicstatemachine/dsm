/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/contexts/UXContext.tsx
// SPDX-License-Identifier: Apache-2.0
import React, { createContext, useContext, useMemo, useState } from 'react';
import { useBridgeEvent } from '@/hooks/useBridgeEvents';
import { playCoinSound } from '@/utils/coinSound';

export interface UXContextValue {
  hideComplexity: boolean;
  setHideComplexity: (value: boolean) => void;
  toggleHideComplexity: () => void;
  formatMoney: (amount: number) => string;
  // Global toast control: null or simple type+message (persistent skips auto-dismiss)
  globalToast: { type: string; message?: string; persistent?: boolean } | null;
  notifyToast: (type: string, message?: string, opts?: { persistent?: boolean }) => void;
  clearToast: () => void;
  // BLE features state
}

const defaultValue: UXContextValue = {
  hideComplexity: true,
  setHideComplexity: () => void 0,
  toggleHideComplexity: () => void 0,
  formatMoney: (amount: number) =>
    amount.toLocaleString(undefined, { style: 'currency', currency: 'USD' }),
  globalToast: null,
  notifyToast: () => void 0,
  clearToast: () => void 0,
};

const Ctx = createContext<UXContextValue>(defaultValue);

export const UXProvider: React.FC<{ defaultHideComplexity?: boolean; children?: React.ReactNode }> = ({
  defaultHideComplexity = true,
  children,
}) => {
  const [hideComplexity, setHideComplexity] = useState<boolean>(defaultHideComplexity);
  const [globalToast, setGlobalToast] = useState<{ type: string; message?: string; persistent?: boolean } | null>(null);

  // Toasts are auto-dismissed by GlobalToast (setTimeout, UI-only — not used in protocol logic).

  const notifyToast = React.useCallback((type: string, message?: string, opts?: { persistent?: boolean }) => {
    setGlobalToast({ type, message, persistent: opts?.persistent });
  }, [setGlobalToast]);

  const clearToast = React.useCallback(() => {
    setGlobalToast(null);
  }, [setGlobalToast]);

  // BLE permission event listeners (standardized)
  useBridgeEvent('ble.permission.error', (detail) => {
    notifyToast('error', `Bluetooth permission error: ${detail?.message ?? ''}`);
  }, [notifyToast]);

  // Global notification when a dBTC deposit auto-completes (visible on any screen)
  useBridgeEvent('deposit.completed', (detail?: { depositId: string; amount: string }) => {
    notifyToast('success', `Deposit complete: ${detail?.amount || '?'} BTC`);
  }, [notifyToast]);

  // Global notification when a dBTC exit/withdrawal completes
  useBridgeEvent('wallet.exitCompleted', () => {
    notifyToast('exit_completed');
  }, [notifyToast]);

  // The coin sound follows a credit Rust reported: a completed deposit
  // (wallet.creditReceived) or items the inbox poller processed
  // (inbox.updated, below). Never a difference between two balance reads.
  useBridgeEvent('wallet.creditReceived', () => {
    playCoinSound();
  }, []);

  // Global notification when new inbox items arrive from storage sync.
  useBridgeEvent('inbox.updated', (detail?: { newItems?: number }) => {
    const newItems = typeof detail?.newItems === 'number' ? detail.newItems : 0;
    if (newItems <= 0) return;
    playCoinSound();
    const label = newItems === 1 ? 'New inbox item received' : `${newItems} new inbox items received`;
    notifyToast('inbox_received', label);
  }, [notifyToast]);

  // A BLE bilateral transfer completed.
  useBridgeEvent('bilateral.transferComplete', () => {
    notifyToast('transfer_accepted');
  }, [notifyToast]);

  const value = useMemo<UXContextValue>(() => ({
    hideComplexity,
    setHideComplexity,
    toggleHideComplexity: () => setHideComplexity(v => !v),
    formatMoney: (amount: number) =>
      amount.toLocaleString(undefined, { style: 'currency', currency: 'USD' }),
    globalToast,
    notifyToast,
    clearToast,
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }), [hideComplexity, globalToast]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
};

export function useUX(): UXContextValue {
  return useContext(Ctx);
}
