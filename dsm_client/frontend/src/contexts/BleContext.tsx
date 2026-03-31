/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/contexts/BleContext.tsx
// SPDX-License-Identifier: Apache-2.0
// BLE React context wired to deterministic DSM BLE bridge (protobuf-only events)

import React, { createContext, useCallback, useContext, useMemo, useRef, useState } from 'react';
import { useUX } from './UXContext';
import { useBridgeEvent } from '../hooks/useBridgeEvents';
import { startBleScanViaRouter, stopBleScanViaRouter } from '../dsm/WebViewBridge';

type ScanState = 'idle' | 'scanning' | 'connected';
type Device = { address: string; name?: string };

type BleApi = {
  state: ScanState;
  devices: Device[];
  startScan: () => Promise<void>;
  stopScan: () => Promise<void>;
  connect: (address: string) => Promise<void>;
  disconnect: (address: string) => Promise<void>;
  write: (address: string, data: Uint8Array) => Promise<void>;
  read: (address: string) => Promise<Uint8Array | null>;
};

const Ctx = createContext<BleApi | null>(null);

export function BleProvider({ children }: { children: React.ReactNode }) {
  const { bleFeaturesDisabled } = useUX();
  const [state, setState] = useState<ScanState>('idle');
  const [devices, setDevices] = useState<Device[]>([]);
  const seen = useRef<Set<string>>(new Set());

  const checkBleEnabled = useCallback(() => {
    if (bleFeaturesDisabled) {
      throw new Error('Bluetooth features are disabled due to permission issues. Please restart the app and grant permissions.');
    }
  }, [bleFeaturesDisabled]);

  const startScan = useCallback(async () => {
    checkBleEnabled();
    try {
      seen.current.clear();
      setDevices([]);
      await startBleScanViaRouter();
      // State will be set by ble.scanStarted event from binary bridge
    } catch {
      // State will be corrected by scan events or stay idle
    }
  }, [checkBleEnabled]);

  const stopScan = useCallback(async () => {
    checkBleEnabled();
    try {
      await stopBleScanViaRouter();
      // State will be set by ble.scanStopped event from binary bridge
    } catch {
      setState('idle');
    }
  }, [checkBleEnabled]);

  const connect = useCallback(async (_address: string) => {
    checkBleEnabled();
    // Connection is initiated by BleCoordinator automatically after discovery.
    // State will be set by ble.deviceConnected event from binary bridge.
  }, [checkBleEnabled]);

  const disconnect = useCallback(async (_address: string) => {
    checkBleEnabled();
    // Disconnection state will be set by ble.deviceDisconnected event from binary bridge.
  }, [checkBleEnabled]);

  const write = useCallback(async (_address: string, _data: Uint8Array) => {
    checkBleEnabled();
    // Transaction writes go through BleCoordinator's outbox, not direct GATT writes.
  }, [checkBleEnabled]);

  const read = useCallback(async (_address: string): Promise<Uint8Array | null> => {
    checkBleEnabled();
    // Identity reads are handled automatically by BleCoordinator after MTU negotiation.
    return null;
  }, [checkBleEnabled]);

  // Subscribe to protobuf-driven BLE state events from the binary bridge
  useBridgeEvent('ble.scanStarted', () => {
    setState('scanning');
  });

  useBridgeEvent('ble.scanStopped', () => {
    setState(prev => prev === 'connected' ? 'connected' : 'idle');
  });

  useBridgeEvent('ble.deviceFound', (detail) => {
    const addr = detail?.address;
    if (!addr || seen.current.has(addr)) return;
    seen.current.add(addr);
    setDevices(ds => ds.concat({ address: addr, name: detail.name || undefined }));
  });

  useBridgeEvent('ble.deviceConnected', () => {
    setState('connected');
  });

  useBridgeEvent('ble.deviceDisconnected', () => {
    setState('idle');
  });

  const value = useMemo<BleApi>(
    () => ({ state, devices, startScan, stopScan, connect, disconnect, write, read }),
    [state, devices, startScan, stopScan, connect, disconnect, write, read]
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useBle(): BleApi {
  const v = useContext(Ctx);
  if (!v) throw new Error('BleContext missing provider');
  return v;
}
