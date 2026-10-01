/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import { useCallback, useEffect, useRef } from 'react';
import type { AppState } from '../types/app';
import logger from '../utils/logger';
import { decodeFramedEnvelopeV3 } from '../dsm/decoding';
import { addDsmEventListener } from '../dsm/WebViewBridge';
import { recoveryPhraseStore } from '../runtime/recoveryPhraseStore';

type Args = {
  appState: AppState;
  setAppState: (s: AppState) => void;
  setError: (s: string | null) => void;
  setSecuringProgress: (p: number) => void;
};

export function useGenesisFlow({
  appState,
  setAppState,
  setError,
  setSecuringProgress,
}: Args) {
  const genesisInFlight = useRef(false);
  const phraseInFlight = useRef<Promise<void> | null>(null);
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

  // Canonical Genesis v2 (whitepaper §2.5): the BIP39 mnemonic is the sole root — no random
  // genesis entropy, no silicon — and the ONLY way to recover the wallet. INITIALIZE generates
  // it and puts it on the screen for the user to write down; the wallet is created from it only
  // once the user has picked the checked words back out (createWalletFromPhrase).
  const handleGenerateGenesis = useCallback((): Promise<void> => {
    if (genesisInFlight.current || phraseInFlight.current) {
      logger.debug('FRONTEND: handleGenerateGenesis already running; skipping');
      return phraseInFlight.current ?? Promise.resolve();
    }
    logger.info('FRONTEND: Generating the recovery phrase for a new wallet');
    const run = (async () => {
      try {
        const { generateMnemonic } = await import('../dsm/WebViewBridge');
        const mnemonic = await generateMnemonic();
        if (!mnemonic || mnemonic.trim().split(/\s+/).length < 12) {
          throw new Error('Genesis: failed to generate a valid recovery mnemonic');
        }
        recoveryPhraseStore.begin(mnemonic);
        setAppState('backup_phrase');
      } catch (err) {
        logger.error('FRONTEND: Recovery phrase generation failed', err);
        setError(err instanceof Error ? err.message : 'Recovery phrase generation failed');
        setAppState('error');
      } finally {
        phraseInFlight.current = null;
      }
    })();
    phraseInFlight.current = run;
    return run;
  }, [setAppState, setError]);

  /** Leave the backup without creating a wallet; the phrase is forgotten. */
  const cancelPhraseBackup = useCallback(() => {
    recoveryPhraseStore.clear();
    setAppState('needs_genesis');
  }, [setAppState]);

  /** Create the wallet from the phrase the user wrote down and checked (answerPhraseCheck). */
  const createWalletFromPhrase = useCallback(async () => {
    if (genesisInFlight.current) {
      logger.debug('FRONTEND: createWalletFromPhrase already running; skipping');
      return;
    }
    const mnemonic = recoveryPhraseStore.mnemonic();
    logger.info('FRONTEND: Creating the wallet from the checked recovery phrase');
    try {
      genesisInFlight.current = true;
      const { createGenesisViaRouter } = await import('../dsm/WebViewBridge');
      const envelopeBytes = await createGenesisViaRouter(mnemonic);
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
      recoveryPhraseStore.clear();
    }
  }, [setAppState, setError, setSecuringProgress]);

  /** A word picked for the current check; the last match creates the wallet. */
  const answerPhraseCheck = useCallback((choice: string): Promise<void> => {
    if (recoveryPhraseStore.answer(choice) === 'complete') {
      return createWalletFromPhrase();
    }
    return Promise.resolve();
  }, [createWalletFromPhrase]);

  return { handleGenerateGenesis, cancelPhraseBackup, answerPhraseCheck };
}
