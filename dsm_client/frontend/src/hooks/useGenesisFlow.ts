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
  /**
   * Called with the freshly generated BIP39 mnemonic (Genesis v2) so the UI can show it for
   * backup. The mnemonic is the ONLY recovery path; the host never persists it.
   */
  onMnemonicGenerated?: (mnemonic: string) => void;
};

export function useGenesisFlow({
  appState,
  setAppState,
  setError,
  setSecuringProgress,
  onMnemonicGenerated,
}: Args) {
  const genesisInFlight = useRef(false);
  const interruptedMessage = 'Device securing was interrupted. Do not leave the screen until finished. Initialization was wiped and must be started again so the device key material is not corrupted.';

  // Abort device-key initialisation if the user navigates away during securing.
  // If the securing is interrupted the device state is corrupt — wipe and restart.
  useEffect(() => {
    if (appState !== 'securing_device') return;
    const onVisibilityChange = () => {
      if (document.visibilityState === 'hidden') {
        logger.warn('FRONTEND: User left screen during device securing - aborting and wiping');
        genesisInFlight.current = false;
        setSecuringProgress(0);
        setError(interruptedMessage);
        setAppState('needs_genesis');
      }
    };
    document.addEventListener('visibilitychange', onVisibilityChange);
    return () => document.removeEventListener('visibilitychange', onVisibilityChange);
  }, [appState, interruptedMessage, setAppState, setError, setSecuringProgress]);

  // When the session manager transitions to securing_device (driven by Rust BOOTSTRAP_SECURING flag
  // on second-boot resume), mark genesis as in-flight so the progress event listener below
  // will process GENESIS_KIND_SECURING_PROGRESS events and update the progress bar.
  useEffect(() => {
    if (appState === 'securing_device') {
      genesisInFlight.current = true;
    }
  }, [appState]);

  // Listen for device-key enrollment progress events from Kotlin
  useEffect(() => {
    const unsub = addDsmEventListener((evt) => {
      if (!genesisInFlight.current) {
        if (evt.topic.startsWith('genesis.')) {
          logger.debug(`FRONTEND: Ignoring stale genesis lifecycle event '${evt.topic}' with no genesis in flight`);
        }
        return;
      }
      if (evt.topic === 'genesis.securing-device') {
        logger.info('FRONTEND: Device-key enrollment started');
        setSecuringProgress(0);
        setAppState('securing_device');
      } else if (evt.topic === 'genesis.securing-device-progress') {
        const pct = evt.payload.length > 0 ? (evt.payload[0] & 0xFF) : 0;
        logger.info(`FRONTEND: Device-key enrollment progress: ${pct}%`);
        setSecuringProgress(pct);
      } else if (evt.topic === 'genesis.securing-device-complete') {
        logger.info('FRONTEND: Device-key enrollment complete');
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
      logger.info('FRONTEND: Triggering canonical mnemonic-rooted Genesis v2');

      const { createGenesisViaRouter, generateMnemonic } = await import('../dsm/WebViewBridge');

      // Canonical Genesis v2 (whitepaper §2.5): the BIP39 mnemonic is the sole root — no random
      // genesis entropy, no silicon. Generate it, surface it for the user to back up, then create
      // the wallet from it. The mnemonic is the ONLY way to recover the wallet.
      const mnemonic = await generateMnemonic();
      if (!mnemonic || mnemonic.trim().split(/\s+/).length < 12) {
        throw new Error('Genesis: failed to generate a valid recovery mnemonic');
      }
      onMnemonicGenerated?.(mnemonic);
      const locale = navigator.language || 'en-US';
      const networkId = 'mainnet';

      const envelopeBytes = await createGenesisViaRouter(mnemonic, locale, networkId);
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
  }, [setAppState, setError, setSecuringProgress, onMnemonicGenerated]);

  return { handleGenerateGenesis };
}
