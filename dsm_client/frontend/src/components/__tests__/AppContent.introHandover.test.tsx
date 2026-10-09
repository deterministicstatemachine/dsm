// SPDX-License-Identifier: Apache-2.0

import React from 'react';
import { act, render, renderHook, screen } from '@testing-library/react';
import AppContent from '../AppContent';
import { useIntroGate } from '../../hooks/useIntroGate';
import type { AppState } from '../../types/app';

// The intro scene's pixel engine loads a script; the fallback GIF is enough here.
jest.mock('../fx/fxEngine', () => ({ loadFxEngine: () => Promise.resolve(false) }));

let dismiss: () => void = () => {};

function Boot({ appState }: { appState: AppState }) {
  const { showIntro, dismissIntro } = useIntroGate();
  dismiss = dismissIntro;
  return (
    <AppContent
      appState={appState}
      skin="classic"
      choosing="chosen"
      error={null}
      showIntro={showIntro}
      introGifSrc="intro.gif"
      eraTokenSrc="era.png"
      btcLogoSrc="btc.png"
      dsmLogoSrc="dsm.png"
      chameleonSrc="chameleon.gif"
      setChameleonSrc={() => {}}
      soundEnabled
      securingProgress={0}
      currentScreen="home"
      navigate={() => {}}
      handleGenerateGenesis={() => {}}
      cancelPhraseBackup={() => {}}
      answerPhraseCheck={() => Promise.resolve()}
      menuItems={[]}
      currentMenuIndex={0}
      setCurrentMenuIndex={() => {}}
    />
  );
}

function animationEnd(target: Element, animationName: string) {
  const event = new Event('animationend', { bubbles: true });
  Object.defineProperty(event, 'animationName', { value: animationName });
  act(() => {
    target.dispatchEvent(event);
  });
}

function intro(): HTMLElement {
  const el = document.querySelector('.intro-container');
  if (!el) throw new Error('the intro is not on the screen');
  return el as HTMLElement;
}

describe('the boot intro stays until A', () => {
  test('the intro stays on the screen, whatever the phase and however long it has played, and says to press A', async () => {
    const { rerender } = render(<Boot appState="runtime_loading" />);
    await act(async () => {});

    rerender(<Boot appState="wallet_ready" />);
    animationEnd(intro(), 'introFadeOut');
    animationEnd(intro(), 'introPromptIn');

    expect(intro()).toBeTruthy();
    expect(screen.getByText('PRESS A')).toBeTruthy();
  });

  test('past the intro, a phase still waiting on the network shows its own screen', async () => {
    render(<Boot appState="publication_pending" />);
    await act(async () => {});
    expect(screen.queryByText(/PUBLISHING TO NETWORK/i)).toBeNull();

    act(() => dismiss());

    expect(document.querySelector('.intro-container')).toBeNull();
    expect(screen.getByText(/PUBLISHING TO NETWORK/i)).toBeTruthy();
  });
});

describe('useIntroGate', () => {
  test('the intro is on until it is dismissed, and it stays over', () => {
    const { result } = renderHook(() => useIntroGate());
    expect(result.current.showIntro).toBe(true);

    act(() => result.current.dismissIntro());
    expect(result.current.showIntro).toBe(false);

    act(() => result.current.dismissIntro());
    expect(result.current.showIntro).toBe(false);
  });
});
