// SPDX-License-Identifier: Apache-2.0

import React from 'react';
import { act, render, renderHook, screen } from '@testing-library/react';
import AppContent from '../AppContent';
import { useIntroGate } from '../../hooks/useIntroGate';
import type { AppState } from '../../types/app';

// The intro scene's pixel engine loads a script; the fallback GIF is enough here.
jest.mock('../fx/fxEngine', () => ({ loadFxEngine: () => Promise.resolve(false) }));

function Boot({ appState }: { appState: AppState }) {
  const { showIntro, onIntroPlayed } = useIntroGate(appState);
  return (
    <AppContent
      appState={appState}
      error={null}
      showIntro={showIntro}
      onIntroPlayed={onIntroPlayed}
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
      showLockPrompt={false}
      dismissLockPrompt={() => {}}
      unlockToWallet={() => {}}
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

describe('the boot intro hands over to the phase screen', () => {
  test('a phase still waiting on the network shows its own screen once the intro has played out', async () => {
    render(<Boot appState="publication_pending" />);
    await act(async () => {});

    expect(intro()).toBeTruthy();
    expect(screen.queryByText(/PUBLISHING TO NETWORK/i)).toBeNull();

    animationEnd(intro(), 'introFadeOut');

    expect(document.querySelector('.intro-container')).toBeNull();
    expect(screen.getByText(/PUBLISHING TO NETWORK/i)).toBeTruthy();
  });

  test('an animation inside the scene, or another animation, does not end the intro', async () => {
    render(<Boot appState="publication_pending" />);
    await act(async () => {});

    const scene = intro().firstElementChild;
    if (!scene) throw new Error('the intro has no scene');
    animationEnd(scene, 'introFadeOut');
    animationEnd(intro(), 'somethingElse');

    expect(intro()).toBeTruthy();
    expect(screen.queryByText(/PUBLISHING TO NETWORK/i)).toBeNull();
  });
});

describe('useIntroGate', () => {
  test('a settled app ends the intro at once, and it stays over', () => {
    const { result, rerender } = renderHook(({ appState }: { appState: AppState }) => useIntroGate(appState), {
      initialProps: { appState: 'runtime_loading' as AppState },
    });
    expect(result.current.showIntro).toBe(true);

    rerender({ appState: 'wallet_ready' });
    expect(result.current.showIntro).toBe(false);

    rerender({ appState: 'locked' });
    expect(result.current.showIntro).toBe(false);
  });

  test('the intro playing out ends it in any phase', () => {
    const { result } = renderHook(() => useIntroGate('runtime_loading'));
    expect(result.current.showIntro).toBe(true);

    act(() => result.current.onIntroPlayed());
    expect(result.current.showIntro).toBe(false);
  });
});
