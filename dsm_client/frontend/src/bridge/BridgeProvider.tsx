// SPDX-License-Identifier: MIT OR Apache-2.0

import React, { PropsWithChildren, useEffect } from 'react';
import type { AndroidBridgeV3 } from '../dsm/bridgeTypes';
import { setBridgeInstance } from './BridgeRegistry';
import { bridgeSessionStore } from '../runtime/bridgeSessionStore';
import { installRigQueryHook } from '../dsm/rigDebug';

interface BridgeProviderProps {
  bridge?: AndroidBridgeV3;
}

export const BridgeProvider: React.FC<PropsWithChildren<BridgeProviderProps>> = ({ bridge, children }) => {
  useEffect(() => {
    setBridgeInstance(bridge);
    bridgeSessionStore.setBridgeBound(Boolean(bridge));
    // Rig-only, read-only query hook for the two-device end-to-end proof.
    installRigQueryHook();

    const onBridgeReady = () => {
      bridgeSessionStore.markBridgeReady();
    };

    window.addEventListener('dsm-bridge-ready', onBridgeReady);

    return () => {
      window.removeEventListener('dsm-bridge-ready', onBridgeReady);
      bridgeSessionStore.reset();
      setBridgeInstance(undefined);
    };
  }, [bridge]);

  return <>{children}</>;
};
