/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import { renderHook, act } from '@testing-library/react';
import { useThemeAssets } from '../useThemeAssets';
import type { ThemeName } from '../../utils/theme';

describe('useThemeAssets', () => {
  it('returns correct assets for stateboy theme', () => {
    const { result } = renderHook(() => useThemeAssets('stateboy'));

    expect(result.current.chameleonSrc).toBe('images/vaulthunters/chameleon-lime.gif');
    expect(result.current.introGifSrc).toBe('images/cutscenes/stateboy.gif');
    expect(result.current.eraTokenSrc).toBe('images/logos/era_token_gb.gif');
    expect(result.current.btcLogoSrc).toBe('images/logos/btc-logo.gif');
    expect(result.current.bricksSrc).toBe('images/vaulthunters/bricks2.svg');
    expect(result.current.dsmLogoSrc).toBe('images/logos/dsm-stateboy-on-screen-logo.svg');
  });

  it('returns correct assets for berry theme', () => {
    const { result } = renderHook(() => useThemeAssets('berry'));

    expect(result.current.chameleonSrc).toBe('images/vaulthunters/chameleon-pink.GIF');
    expect(result.current.introGifSrc).toBe('images/cutscenes/stateboy_pink.gif');
    expect(result.current.eraTokenSrc).toBe('images/logos/era_token_gb_pink.gif');
    expect(result.current.btcLogoSrc).toBe('images/logos/btc-logo-pink.gif');
    expect(result.current.bricksSrc).toBe('images/vaulthunters/bricks2_pink.png');
    expect(result.current.dsmLogoSrc).toBe('images/logos/dsm-stateboy-on-screen-logo_pink.png');
  });

  it('updates assets when theme changes', () => {
    const { result, rerender } = renderHook(
      ({ theme }) => useThemeAssets(theme),
      { initialProps: { theme: 'stateboy' as ThemeName } },
    );

    expect(result.current.chameleonSrc).toBe('images/vaulthunters/chameleon-lime.gif');

    rerender({ theme: 'grape' });

    expect(result.current.chameleonSrc).toBe('images/vaulthunters/chameleon-purple.GIF');
    expect(result.current.introGifSrc).toBe('images/cutscenes/stateboy_purple.gif');
    expect(result.current.eraTokenSrc).toBe('images/logos/era_token_gb_purple.gif');
    expect(result.current.btcLogoSrc).toBe('images/logos/btc-logo-purple.gif');
  });

  it('sets --bricks-bg CSS variable on document', () => {
    const setProperty = jest.spyOn(document.documentElement.style, 'setProperty');

    renderHook(() => useThemeAssets('teal'));

    expect(setProperty).toHaveBeenCalledWith(
      '--bricks-bg',
      "url('images/vaulthunters/bricks2_blue.png')",
    );

    setProperty.mockRestore();
  });

  it('updates CSS variable when theme changes', () => {
    const setProperty = jest.spyOn(document.documentElement.style, 'setProperty');

    const { rerender } = renderHook(
      ({ theme }) => useThemeAssets(theme),
      { initialProps: { theme: 'stateboy' as ThemeName } },
    );

    rerender({ theme: 'crimson' });

    expect(setProperty).toHaveBeenCalledWith(
      '--bricks-bg',
      "url('images/vaulthunters/bricks2_red.png')",
    );

    setProperty.mockRestore();
  });

  it('allows manual chameleon override via setChameleonSrc', () => {
    const { result } = renderHook(() => useThemeAssets('stateboy'));

    act(() => {
      result.current.setChameleonSrc('images/custom/chameleon.gif');
    });

    expect(result.current.chameleonSrc).toBe('images/custom/chameleon.gif');
  });

  it('resets chameleon to theme-correct asset on theme change', () => {
    const { result, rerender } = renderHook(
      ({ theme }) => useThemeAssets(theme),
      { initialProps: { theme: 'stateboy' as ThemeName } },
    );

    act(() => {
      result.current.setChameleonSrc('images/custom/override.gif');
    });
    expect(result.current.chameleonSrc).toBe('images/custom/override.gif');

    rerender({ theme: 'orange' });

    expect(result.current.chameleonSrc).toBe('images/vaulthunters/chameleon-orange.gif');
  });

  it('returns all 12 themes with valid assets', () => {
    const themes: ThemeName[] = [
      'stateboy', 'pocket', 'light', 'berry', 'grape', 'dandelion',
      'orange', 'teal', 'kiwi', 'greyscale', 'inverted', 'crimson',
    ];

    for (const theme of themes) {
      const { result } = renderHook(() => useThemeAssets(theme));
      expect(result.current.chameleonSrc).toBeTruthy();
      expect(result.current.introGifSrc).toBeTruthy();
      expect(result.current.eraTokenSrc).toBeTruthy();
      expect(result.current.btcLogoSrc).toBeTruthy();
      expect(result.current.bricksSrc).toBeTruthy();
      expect(result.current.dsmLogoSrc).toBeTruthy();
    }
  });
});
