// SPDX-License-Identifier: Apache-2.0
// A phone that has not chosen how its wallet looks sees only that choice:
// not the intro, not setup's INITIALIZE behind it.

import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import AppContent from '../AppContent';

function boot(choosing: 'choose' | 'chosen') {
  return render(
    <AppContent
      appState="needs_genesis"
      skin="classic"
      choosing={choosing}
      error={null}
      showIntro={choosing === 'chosen'}
      introGifSrc="intro.gif"
      eraTokenSrc="era.png"
      btcLogoSrc="btc.png"
      dsmLogoSrc="dsm.png"
      chameleonSrc="chameleon.gif"
      setChameleonSrc={() => undefined}
      soundEnabled={choosing === 'choose'}
      securingProgress={0}
      currentScreen="home"
      navigate={() => undefined}
      handleGenerateGenesis={() => undefined}
      cancelPhraseBackup={() => undefined}
      answerPhraseCheck={() => Promise.resolve()}
      menuItems={['INITIALIZE', 'DEVICE RECOVERY']}
      currentMenuIndex={0}
      setCurrentMenuIndex={() => undefined}
    />,
  );
}

describe('the choice of look comes before anything', () => {
  test('a phone with no choice shows only the choice', () => {
    boot('choose');
    expect(screen.getByRole('menu', { name: 'Wallet looks' })).toBeInTheDocument();
    expect(screen.getAllByRole('menuitem').map((m) => m.textContent)).toEqual(['Simple · Light', 'Simple · Dark', 'Classic']);
    expect(screen.queryByText('INITIALIZE')).not.toBeInTheDocument();
    expect(screen.queryByText(/WALLET SETUP REQUIRED/)).not.toBeInTheDocument();
  });
});
