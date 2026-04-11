/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import { useCallback, useEffect, useRef } from 'react';
import logger from '../utils/logger';
import { decodeFramedEnvelopeV3 } from '../dsm/decoding';
import { addDsmEventListener } from '../dsm/WebViewBridge';

type Args = {
  setSecuringProgress: (p: number) => void;
  setError: (s: string | null) => void;
};

/**
 * Genesis flow hook — UI-ONLY.
 *
 * Rust SessionManager owns the `securing_device` phase via the
 * MarkGenesisSecuringOp ingress markers ({STARTED, COMPLETE, ABORTED}).
 * After those markers fire, Kotlin's NativeBoundaryBridge post-hook
 * triggers publishCurrentSessionState which propagates the phase via
 * session.state → useNativeSessionBridge → appRuntimeStore.setAppState.
 *
 * This hook MUST NOT write appState directly — doing so reintroduces
 * the multi-writer race that caused bounce-to-initialize.
 *
 * Responsibilities of this hook:
 *  - Listen for genesis lifecycle DOM events purely to update the bar (%).
 *  - Surface error messages from the genesis call into UI state.
 *  - Trigger the genesis call when the user taps INITIALIZE.
 */
export function useGenesisFlow({ setSecuringProgress, setError }: Args) {
  const genesisInFlight = useRef(false);

  // Progress events update only the bar percentage. Phase transitions are
  // driven by Rust via session.state — see useNativeSessionBridge.
  useEffect(() => {
    const unsub = addDsmEventListener((evt) => {
      if (evt.topic === 'genesis.securing-device') {
        logger.info('FRONTEND: Silicon fingerprint enrollment started');
        setSecuringProgress(0);
      } else if (evt.topic === 'genesis.securing-device-progress') {
        const pct = evt.payload.length > 0 ? (evt.payload[0] & 0xFF) : 0;
        logger.info(`FRONTEND: Silicon fingerprint progress: ${pct}%`);
        setSecuringProgress(pct);
      } else if (evt.topic === 'genesis.securing-device-complete') {
        logger.info('FRONTEND: Silicon fingerprint enrollment complete');
        setSecuringProgress(100);
      } else if (evt.topic === 'genesis.securing-device-aborted') {
        logger.warn('FRONTEND: Device securing aborted - phase transition handled by Rust');
        setSecuringProgress(0);
      }
    });
    return unsub;
  }, [setSecuringProgress]);

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
      // Phase transitions to wallet_ready via session.state event from Rust.
    } catch (err) {
      logger.error('FRONTEND: Genesis generation failed', err);
      const message = err instanceof Error ? err.message : 'Genesis generation failed';
      setError(message);
      // Phase transition to needs_genesis or error is handled by Rust via the
      // catch path of installGenesisEnvelope (which calls markGenesisSecuring(ABORTED)
      // through the ingress seam). Do NOT setAppState here.
    } finally {
      genesisInFlight.current = false;
    }
  }, [setError]);

  return { handleGenerateGenesis };
}
