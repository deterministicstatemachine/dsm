/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import type { AppState } from '../types/app';

export function useIntroGate(appState: AppState): boolean {
  return !(appState === 'wallet_ready' || appState === 'needs_genesis');
}
