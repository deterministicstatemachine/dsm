/* eslint-disable @typescript-eslint/no-explicit-any */
// Shim screen to forward to the main settings component.
// The previous contents of this file duplicated transport code and caused type errors.
// Keep a single source of truth for DSM transport in src/dsm/index.ts and
// render the actual settings UI from SettingsMainScreen here.
import React from 'react';
import SettingsMainScreen from './SettingsMainScreen';

const SettingsScreen: React.FC = () => {
  return <SettingsMainScreen />;
};

export default SettingsScreen;