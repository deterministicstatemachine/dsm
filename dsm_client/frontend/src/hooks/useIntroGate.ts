/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useState } from 'react';
import type { AppState } from '../types/app';

export function useIntroGate(appState: AppState): boolean {
  const [showIntro, setShowIntro] = useState<boolean>(true);

  useEffect(() => {
    if (appState === 'wallet_ready' || appState === 'needs_genesis') {
      setShowIntro(false);
    }
  }, [appState]);

  return showIntro;
}
