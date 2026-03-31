/* eslint-disable @typescript-eslint/no-explicit-any */
import React, { ReactNode } from 'react';
import { ThemeName } from '@/utils/theme';

interface ScreenContainerProps {
  children: ReactNode;
  theme?: ThemeName;
}

// Layout-agnostic screen container.
// All themes use the StateBoy frame with different color palettes.
const ScreenContainer: React.FC<ScreenContainerProps> = ({ children }) => {
  return (
    <div className="stateboy-screen-host">
      {children}
    </div>
  );
};

export default ScreenContainer;
