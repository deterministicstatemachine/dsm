// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState } from 'react';
import { getAvailableThemes, type ThemeName } from '../utils/theme';

function readTheme(): ThemeName {
  const stamped =
    document.getElementById('dsm-app-root')?.getAttribute('data-theme') ??
    document.querySelector('.stateboy')?.getAttribute('data-theme');
  return getAvailableThemes().find((theme) => theme === stamped) ?? 'stateboy';
}

/** The theme `applyTheme` last stamped on the app, following every change. */
export function useActiveTheme(): ThemeName {
  const [theme, setTheme] = useState<ThemeName>(readTheme);
  useEffect(() => {
    const observer = new MutationObserver(() => setTheme(readTheme()));
    observer.observe(document.documentElement, { subtree: true, attributes: true, attributeFilter: ['data-theme'] });
    return () => observer.disconnect();
  }, []);
  return theme;
}
