/* eslint-disable @typescript-eslint/no-explicit-any */
import React, { ReactNode } from 'react';

interface StateBoyScreenProps {
  children: ReactNode;
}

// This component just passes through the children since the StateBoy shell
// is already provided by the HTML template
const StateBoyScreen: React.FC<StateBoyScreenProps> = ({ children }) => {
  return (
    <div className="stateboy-screen-host">
      {children}
    </div>
  );
};

export default StateBoyScreen;
