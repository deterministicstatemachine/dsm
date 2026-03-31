// SPDX-License-Identifier: Apache-2.0

import React, { useEffect, useRef } from 'react';
import { dsmClient } from '../services/dsmClient';

const BluetoothIndicatorController: React.FC = () => {
  const failedRef = useRef(false);

  useEffect(() => {
    const setActive = (active: boolean) => {
      if (typeof document === 'undefined') return;
      const el = document.querySelector('.battery-light');
      if (!el) return;
      el.classList.toggle('bluetooth', active);
    };

    const updateStatus = async () => {
      // Once the bridge has been confirmed unavailable, stop retrying.
      // The BLE event subscription below will activate the indicator
      // if the bridge becomes ready later.
      if (failedRef.current) return;
      try {
        const status = await dsmClient.getBluetoothStatus();
        setActive(Boolean(status?.enabled));
      } catch {
        failedRef.current = true;
        setActive(false);
      }
    };

    updateStatus();

    const unsubscribe: (() => void) | undefined = dsmClient.subscribeBleEvents?.((detail: Record<string, unknown>) => {
      const state = String(detail?.state ?? '').toLowerCase();
      // Bridge delivered an event — it is alive. Clear the failure flag.
      failedRef.current = false;

      switch (state) {
        case 'enabled':
        case 'scanning':
        case 'advertising':
        case 'connected':
          setActive(true);
          break;
        case 'disabled':
        case 'idle':
          setActive(false);
          break;
        default:
          break;
      }
    });

    return () => {
      try {
        if (unsubscribe) unsubscribe();
      } catch {
        /* ignore */
      }
    };
  }, []);

  return null;
};

export default BluetoothIndicatorController;
