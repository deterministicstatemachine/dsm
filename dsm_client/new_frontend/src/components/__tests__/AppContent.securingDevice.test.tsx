// SPDX-License-Identifier: Apache-2.0

import React from 'react';
import { render, screen } from '@testing-library/react';
import AppContent from '../AppContent';

describe('AppContent securing device state', () => {
  test('shows the leave-screen warning while DBRW securing is in progress', () => {
    render(
      <AppContent
        appState="securing_device"
        error={null}
        showIntro={false}
        introGifSrc="intro.gif"
        eraTokenSrc="era.png"
        btcLogoSrc="btc.png"
        dsmLogoSrc="dsm.png"
        chameleonSrc="chameleon.gif"
        setChameleonSrc={() => {}}
        soundEnabled
        securingProgress={42}
        currentScreen="home"
        navigate={() => {}}
        handleGenerateGenesis={() => {}}
        showLockPrompt={false}
        dismissLockPrompt={() => {}}
        unlockToWallet={() => {}}
        menuItems={[]}
        currentMenuIndex={0}
        setCurrentMenuIndex={() => {}}
      />,
    );

    expect(screen.getByText(/DBRW SALT INITIALIZATION/i)).toBeTruthy();
    expect(screen.getByText(/THIS ONLY HAPPENS ONCE/i)).toBeTruthy();
    expect(screen.getByText(/DO NOT LEAVE THE SCREEN UNTIL FINISHED/i)).toBeTruthy();
    expect(screen.queryByText(/PLEASE WAIT/i)).toBeNull();
  });
});
