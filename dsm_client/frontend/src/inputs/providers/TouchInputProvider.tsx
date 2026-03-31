/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import React, { PropsWithChildren, useEffect, useRef } from 'react';

type Intents = {
  select: () => void;
  back: () => void;
  nextItem: () => void;
  prevItem: () => void;
  toggleTheme?: () => void;
  start?: () => void;
};

interface TouchInputProviderProps {
  intents: Intents;
}

// Minimal stub for a future touch/swipe provider.
// Adds basic swipe up/down to prev/next item.
export const TouchInputProvider: React.FC<PropsWithChildren<TouchInputProviderProps>> = ({ intents, children }) => {
  const startX = useRef<number | null>(null);
  const startY = useRef<number | null>(null);

  useEffect(() => {
    const onTouchStart = (e: TouchEvent) => {
      const t = e.touches[0];
      startX.current = t.clientX;
      startY.current = t.clientY;
    };
    const onTouchEnd = (e: TouchEvent) => {
      const t = e.changedTouches[0];
      if (startX.current == null || startY.current == null) return;
      const dx = t.clientX - startX.current;
      const dy = t.clientY - startY.current;
      // Simple vertical swipe detection
      if (Math.abs(dy) > Math.abs(dx) && Math.abs(dy) > 30) {
        if (dy < 0) intents.prevItem();
        else intents.nextItem();
      }
      startX.current = null;
      startY.current = null;
    };
    document.addEventListener('touchstart', onTouchStart);
    document.addEventListener('touchend', onTouchEnd);
    return () => {
      document.removeEventListener('touchstart', onTouchStart);
      document.removeEventListener('touchend', onTouchEnd);
    };
  }, [intents]);

  return <>{children}</>;
};
