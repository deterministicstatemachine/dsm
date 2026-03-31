/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import { useCallback, useEffect, useRef } from 'react';
import type { AppState } from '../types/app';
import logger from '../utils/logger';
import { decodeFramedEnvelopeV3 } from '../dsm/decoding';
import { addDsmEventListener } from '../dsm/WebViewBridge';

type Args = {
  appState: AppState;
  setAppState: (s: AppState) => void;
  setError: (s: string | null) => void;
  setSecuringProgress: (p: number) => void;
};

export function useGenesisFlow({ appState, setAppState, setError, setSecuringProgress }: Args) {
  const genesisInFlight = useRef(false);
  const interruptedMessage = 'Device securing was interrupted. Do not leave the screen until finished. Initialization was wiped and must be started again so DBRW is not corrupted.';

  // Abort DBRW salt initialisation if the user navigates away during securing.
  // If the securing is interrupted the device state is corrupt — wipe and restart.
  useEffect(() => {
    if (appState !== 'securing_device') return;
    const onVisibilityChange = () => {
      if (document.visibilityState === 'hidden') {
        logger.warn('FRONTEND: User left screen during DBRW securing - aborting and wiping');
        genesisInFlight.current = false;
        setSecuringProgress(0);
        setError(interruptedMessage);
        setAppState('needs_genesis');
      }
    };
    document.addEventListener('visibilitychange', onVisibilityChange);
    return () => document.removeEventListener('visibilitychange', onVisibilityChange);
  }, [appState, interruptedMessage, setAppState, setError, setSecuringProgress]);

  // Listen for silicon fingerprint enrollment progress events from Kotlin
  useEffect(() => {
    const unsub = addDsmEventListener((evt) => {
      if (evt.topic === 'genesis.securing-device') {
        logger.info('FRONTEND: Silicon fingerprint enrollment started');
        setSecuringProgress(0);
        setAppState('securing_device');
      } else if (evt.topic === 'genesis.securing-device-progress') {
        const pct = evt.payload.length > 0 ? (evt.payload[0] & 0xFF) : 0;
        logger.info(`FRONTEND: Silicon fingerprint progress: ${pct}%`);
        setSecuringProgress(pct);
      } else if (evt.topic === 'genesis.securing-device-complete') {
        logger.info('FRONTEND: Silicon fingerprint enrollment complete');
        setSecuringProgress(100);
      } else if (evt.topic === 'genesis.securing-device-aborted') {
        logger.warn('FRONTEND: Device securing aborted after the screen was left');
        genesisInFlight.current = false;
        setSecuringProgress(0);
        setError(interruptedMessage);
        setAppState('needs_genesis');
      }
    });
    return unsub;
  }, [interruptedMessage, setAppState, setError, setSecuringProgress]);

  const handleGenerateGenesis = useCallback(async () => {
    if (genesisInFlight.current) {
      logger.debug('FRONTEND: handleGenerateGenesis already running; skipping');
      return;
    }
    logger.info('FRONTEND: handleGenerateGenesis called');
    try {
      genesisInFlight.current = true;
      logger.info('FRONTEND: Triggering genesis via router (Kotlin owns entropy/locale/network)');

      const { createGenesisViaRouter } = await import('../dsm/WebViewBridge');

      // Generate 32 bytes of cryptographic entropy for genesis key material.
      // Kotlin's parseCreateGenesisPayload requires non-blank locale/networkId
      // and non-empty entropy — it forwards them to the JNI genesis handler.
      const entropy = new Uint8Array(32);
      crypto.getRandomValues(entropy);
      const locale = navigator.language || 'en-US';
      const networkId = 'mainnet';

      const envelopeBytes = await createGenesisViaRouter(locale, networkId, entropy);
      logger.debug('FRONTEND: createGenesisViaRouter returned bytes', envelopeBytes?.length);

      if (!envelopeBytes || envelopeBytes.length < 10) {
        throw new Error('Genesis envelope is empty or too small');
      }

      const env = decodeFramedEnvelopeV3(envelopeBytes);
      const payload: any = env.payload;
      logger.debug('FRONTEND: Envelope payload case', payload?.case);

      if (payload?.case === 'error') {
        const errMsg = payload.value?.message || 'Unknown error from native genesis';
        logger.error('FRONTEND: Genesis error', errMsg);
        throw new Error(`Genesis creation failed: ${errMsg}`);
      }

      const gc = payload?.case === 'genesisCreatedResponse' ? payload.value : null;
      if (!gc) throw new Error(`Invalid GenesisCreated envelope - got case: ${payload?.case}`);

      logger.info('FRONTEND: Genesis completed successfully');
      // Native session state event will transition appState to wallet_ready
    } catch (err) {
      logger.error('FRONTEND: Genesis generation failed', err);
      const message = err instanceof Error ? err.message : 'Genesis generation failed';
      setError(message);
      if (message.includes('Do not leave the screen until finished')) {
        setSecuringProgress(0);
        setAppState('needs_genesis');
      } else {
        setAppState('error');
      }
    } finally {
      genesisInFlight.current = false;
    }
  }, [setAppState, setError, setSecuringProgress]);

  return { handleGenerateGenesis };
}
