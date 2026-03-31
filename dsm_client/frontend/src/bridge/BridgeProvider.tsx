import React, { PropsWithChildren, useEffect } from 'react';
import type { AndroidBridgeV3 } from '../dsm/bridgeTypes';
import { setBridgeInstance } from './BridgeRegistry';
import { bridgeSessionStore } from '../runtime/bridgeSessionStore';

interface BridgeProviderProps {
  bridge?: AndroidBridgeV3;
}

export const BridgeProvider: React.FC<PropsWithChildren<BridgeProviderProps>> = ({ bridge, children }) => {
  useEffect(() => {
    setBridgeInstance(bridge);
    bridgeSessionStore.setBridgeBound(Boolean(bridge));

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
