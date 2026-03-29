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
  // Global toast control: null or simple type+message
  globalToast: { type: string; message?: string } | null;
  notifyToast: (type: string, message?: string) => void;
  clearToast: () => void;
  // BLE features state
  bleFeaturesDisabled: boolean;
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
  bleFeaturesDisabled: false,
};

const Ctx = createContext<UXContextValue>(defaultValue);

export const UXProvider: React.FC<{ defaultHideComplexity?: boolean; children?: React.ReactNode }> = ({
  defaultHideComplexity = true,
  children,
}) => {
  const [hideComplexity, setHideComplexity] = useState<boolean>(defaultHideComplexity);
  const [globalToast, setGlobalToast] = useState<{ type: string; message?: string } | null>(null);
  const [bleFeaturesDisabled, setBleFeaturesDisabled] = useState<boolean>(false);
  
  // Toasts are auto-dismissed by GlobalToast (setTimeout, UI-only — not used in protocol logic).

  const notifyToast = React.useCallback((type: string, message?: string) => {
    setGlobalToast({ type, message });
  }, [setGlobalToast]);

  const clearToast = React.useCallback(() => {
    setGlobalToast(null);
  }, [setGlobalToast]);

  // BLE permission event listeners (standardized)
  useBridgeEvent('ble.permission.error', ({ message }) => {
    notifyToast('error', `Bluetooth permission error: ${message}`);
  }, [notifyToast]);

  useBridgeEvent('ble.permission.recovery.needed', () => {
    notifyToast('warning', 'Bluetooth permissions are required for device-to-device transfers. Please grant permissions in settings.');
  }, [notifyToast]);

  useBridgeEvent('ble.features.disabled', () => {
    setBleFeaturesDisabled(true);
    notifyToast('error', 'Bluetooth features have been disabled due to repeated permission issues. Please restart the app and grant permissions.');
  }, [notifyToast]);

  // Recovery path: re-enable BLE features if permissions are restored
  useBridgeEvent('ble.features.enabled', () => {
    setBleFeaturesDisabled(false);
    notifyToast('success', 'Bluetooth features re-enabled.');
  }, [notifyToast]);

  useBridgeEvent('contact.reconcileNeeded', (detail?: { deviceId?: string; message?: string }) => {
    const suffix = detail?.deviceId ? ` (${String(detail.deviceId).slice(0, 8)}...)` : '';
    const msg = detail?.message || 'Online reconciliation required for a contact.';
    notifyToast('warning', `${msg}${suffix}`);
  }, [notifyToast]);

  // Global notification when a dBTC deposit auto-completes (visible on any screen)
  useBridgeEvent('deposit.completed', (detail?: { depositId: string; amount: string }) => {
    notifyToast('success', `Deposit complete: ${detail?.amount || '?'} BTC`);
  }, [notifyToast]);

  // Global notification when a dBTC exit/withdrawal completes
  useBridgeEvent('wallet.exitCompleted', () => {
    notifyToast('exit_completed');
  }, [notifyToast]);

  // Global coin sound when a BLE bilateral transfer completes (receiver side).
  useBridgeEvent('bilateral.transferComplete', () => {
    playCoinSound();
  }, []);

  // Global notification when new inbox items arrive from storage sync.
  useBridgeEvent('inbox.updated', (detail?: { unreadCount?: number; newItems?: number }) => {
    const newItems = typeof detail?.newItems === 'number' ? detail.newItems : 0;
    if (newItems <= 0) return;
    playCoinSound();
    const label = newItems === 1 ? 'New inbox item received' : `${newItems} new inbox items received`;
    notifyToast('inbox_received', label);
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
    bleFeaturesDisabled,
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }), [hideComplexity, globalToast, bleFeaturesDisabled]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
};

export function useUX(): UXContextValue {
  return useContext(Ctx);
}

export function useUXTerms() {
  return {
    getScreenTitle: (key: string) => key,
    getActionLabel: (key: string) => key,
  };
}
