/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import React, { PropsWithChildren } from 'react';
import { useKeyboardBindings } from '../../hooks/useKeyboardBindings';

type Intents = {
  select: () => void;
  back: () => void;
  nextItem: () => void;
  prevItem: () => void;
  toggleTheme?: () => void;
  start?: () => void;
};

interface StateBoyInputProviderProps {
  intents: Intents;
}

// Maps StateBoy UI (keyboard + on-screen buttons) to generic intents.
export const StateBoyInputProvider: React.FC<PropsWithChildren<StateBoyInputProviderProps>> = ({ intents, children }) => {
  useKeyboardBindings(intents);
  return <>{children}</>;
};
