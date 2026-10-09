// SPDX-License-Identifier: Apache-2.0

import { useCallback, useState } from 'react';

export type IntroGate = {
  /** The intro cutscene is on the screen. */
  showIntro: boolean;
  /** The user pressed A: the intro is over, and the app's phase shows its own screen. */
  dismissIntro: () => void;
};

/**
 * The boot intro stays on the screen until the user presses A, however soon
 * the app is settled, so the cutscene is always seen. Past it, whatever phase
 * the app is in shows its own screen: the wallet, genesis to set up, or a phase
 * still waiting on the network (publishing, starting the runtime, an error).
 * Once over, it stays over.
 */
export function useIntroGate(): IntroGate {
  const [showIntro, setShowIntro] = useState<boolean>(true);
  const dismissIntro = useCallback(() => setShowIntro(false), []);
  return { showIntro, dismissIntro };
}
