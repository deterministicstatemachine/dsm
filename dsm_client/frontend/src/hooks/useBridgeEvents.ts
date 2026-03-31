/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/hooks/useBridgeEvents.ts
// A small helper hook to subscribe/unsubscribe to bridgeEvents deterministically.
// This centralizes event binding logic and avoids zombie listeners.

import { useEffect, useRef } from 'react';
import { bridgeEvents } from '../bridge/bridgeEvents';

/**
 * Hook to subscribe to bridge events securely with automatic cleanup.
 * Prevents "zombie listeners" and memory leaks.
 * 
 * @param eventName The name of the event to listen for (e.g. 'ble.deviceFound', 'wallet.refresh')
 * @param handler The callback to run. 
 * @param deps Dependencies for the effect. If these change, the subscription is recreated.
 */
export function useBridgeEvent<T = any>(
  eventName: string,
  handler: (detail?: T) => void,
  deps: React.DependencyList = []
) {
  // Use a ref for the handler to avoid re-subscribing just because the handler function identity changes
  const savedHandler = useRef(handler);

  useEffect(() => {
    savedHandler.current = handler;
  }, [handler]);

  useEffect(() => {
    // Determine the actual listener
    const listener = (payload: T) => {
      savedHandler.current(payload);
    };

    const unsubscribe = bridgeEvents.on(eventName as any, listener as any);
    return () => unsubscribe();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [eventName, ...deps]);
}
