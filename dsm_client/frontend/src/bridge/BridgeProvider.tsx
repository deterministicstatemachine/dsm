// SPDX-License-Identifier: MIT OR Apache-2.0

import React, { PropsWithChildren, useEffect } from 'react';
import type { AndroidBridgeV3 } from '../dsm/bridgeTypes';
import { setBridgeInstance } from './BridgeRegistry';
import { bridgeSessionStore } from '../runtime/bridgeSessionStore';
import { installRigQueryHook } from '../dsm/rigDebug';
import { getBuildType } from '../dsm/WebViewBridge/diagnostics';
import logger from '../utils/logger';

interface BridgeProviderProps {
  bridge?: AndroidBridgeV3;
}

export const BridgeProvider: React.FC<PropsWithChildren<BridgeProviderProps>> = ({ bridge, children }) => {
  useEffect(() => {
    setBridgeInstance(bridge);
    bridgeSessionStore.setBridgeBound(Boolean(bridge));
    // Rig-only, read-only query hook for the two-device end-to-end proof: a
    // debug build's alone (the rig drives the WebView over DevTools, which only
    // a debug build opens), never installed in a release build.
    if (bridge !== undefined) {
      getBuildType().then(
        (build) => {
          if (build === 'debug') installRigQueryHook();
        },
        (e: unknown) => logger.warn('[bridge] the build type was not read; the rig hook is not installed:', e),
      );
    }

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
