// SPDX-License-Identifier: Apache-2.0

import { useCallback, useEffect, useState } from 'react';
import type { AppState } from '../types/app';

export type IntroGate = {
  /** The intro cutscene is on the screen. */
  showIntro: boolean;
  /** The intro has played out: whatever phase the app is in shows its own screen. */
  onIntroPlayed: () => void;
};

/**
 * The boot intro plays until the app is settled (the wallet, or genesis to set
 * up) or until it has played out, whichever comes first. A phase still waiting
 * on the network then shows its own screen (publishing, starting the runtime,
 * an error) instead of the intro's empty last frame. Once over, it stays over.
 */
export function useIntroGate(appState: AppState): IntroGate {
  const [showIntro, setShowIntro] = useState<boolean>(true);

  useEffect(() => {
    if (appState === 'wallet_ready' || appState === 'needs_genesis') {
      setShowIntro(false);
    }
  }, [appState]);

  const onIntroPlayed = useCallback(() => setShowIntro(false), []);

  return { showIntro, onIntroPlayed };
}
