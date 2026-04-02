/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// eslint-env jest
declare const describe: any;
declare const test: any;
declare const expect: any;
declare const beforeEach: any;

import { palettes, applyTheme, getAvailableThemes, ThemeName } from '../theme';

describe('palettes', () => {
  test('every theme listed in getAvailableThemes has a palette entry', () => {
    for (const name of getAvailableThemes()) {
      expect(palettes[name]).toBeDefined();
    }
  });

  test('every palette has required CSS variable keys', () => {
    const requiredKeys = ['--bg', '--bg-secondary', '--text', '--text-dark', '--border'];
    for (const [name, vars] of Object.entries(palettes)) {
      for (const key of requiredKeys) {
        expect(vars[key]).toBeDefined();
      }
    }
  });

  test('all palette colour values look like CSS colours', () => {
    const colorRegex = /^#[0-9a-fA-F]{3,8}$/;
    const rgbRegex = /^\d{1,3},\d{1,3},\d{1,3}$/;
    for (const [, vars] of Object.entries(palettes)) {
      for (const [key, value] of Object.entries(vars)) {
        expect(colorRegex.test(value) || rgbRegex.test(value)).toBe(true);
      }
    }
  });
});

describe('getAvailableThemes', () => {
  test('returns an array of theme names', () => {
    const themes = getAvailableThemes();
    expect(Array.isArray(themes)).toBe(true);
    expect(themes.length).toBeGreaterThan(0);
  });

  test('includes stateboy as the first theme', () => {
    expect(getAvailableThemes()[0]).toBe('stateboy');
  });

  test('includes all known themes', () => {
    const themes = getAvailableThemes();
    expect(themes).toContain('stateboy');
    expect(themes).toContain('pocket');
    expect(themes).toContain('light');
    expect(themes).toContain('inverted');
    expect(themes).toContain('crimson');
  });

  test('has no duplicates', () => {
    const themes = getAvailableThemes();
    expect(new Set(themes).size).toBe(themes.length);
  });
});

describe('applyTheme', () => {
  beforeEach(() => {
    document.documentElement.style.cssText = '';
    document.body.innerHTML = '';
  });

  test('sets CSS variables on document.documentElement', () => {
    applyTheme('stateboy');
    const root = document.documentElement;
    expect(root.style.getPropertyValue('--bg')).toBe('#9bbc0f');
    expect(root.style.getPropertyValue('--text')).toBe('#0f380f');
  });

  test('sets --nav-lit-color to the theme --bg value', () => {
    applyTheme('berry');
    expect(document.documentElement.style.getPropertyValue('--nav-lit-color')).toBe('#e8a2bf');
  });

  test('applies a different theme with different values', () => {
    applyTheme('inverted');
    const root = document.documentElement;
    expect(root.style.getPropertyValue('--bg')).toBe('#252525');
    expect(root.style.getPropertyValue('--text')).toBe('#bec4b5');
  });

  test('sets data-theme on .stateboy element if present', () => {
    const shell = document.createElement('div');
    shell.className = 'stateboy';
    document.body.appendChild(shell);

    applyTheme('grape');
    expect(shell.getAttribute('data-theme')).toBe('grape');
  });

  test('sets data-theme on #dsm-app-root if present', () => {
    const appRoot = document.createElement('div');
    appRoot.id = 'dsm-app-root';
    document.body.appendChild(appRoot);

    applyTheme('teal');
    expect(appRoot.getAttribute('data-theme')).toBe('teal');
  });

  test('falls back to stateboy for invalid theme name', () => {
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    applyTheme('nonexistent' as ThemeName);
    const root = document.documentElement;
    expect(root.style.getPropertyValue('--bg')).toBe('#9bbc0f');
    expect(warnSpy).toHaveBeenCalled();
  });
});
