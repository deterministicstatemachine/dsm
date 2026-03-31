// SPDX-License-Identifier: Apache-2.0

import { useEffect } from 'react';
import { dsmClient } from '../services/dsmClient';
import { AudioManager } from '../utils/audio';
import { applyTheme, type ThemeName } from '../utils/theme';
import { appRuntimeStore } from '../runtime/appRuntimeStore';
import { useNativeSessionStore } from '../runtime/nativeSessionStore';
import type { NativeSessionSnapshot } from '../runtime/nativeSessionTypes';

type Args = {
  themes: ThemeName[];
  setThemeIndex: (index: number) => void;
};

function mapSessionPhaseToAppState(session: NativeSessionSnapshot) {
  if (!session.received) {
    return 'loading' as const;
  }
  return session.phase;
}

export function useNativeSessionBridge({ themes, setThemeIndex }: Args): NativeSessionSnapshot {
  const session = useNativeSessionStore();

  useEffect(() => {
    const appState = mapSessionPhaseToAppState(session);
    appRuntimeStore.setAppState(appState);
    appRuntimeStore.setError(session.fatal_error);
  }, [session]);

  useEffect(() => {
    if (!session.received) {
      return;
    }

    let cancelled = false;

    const applyUiPrefs = async () => {
      if (session.identity_status !== 'ready') {
        if (!cancelled) {
          applyTheme('stateboy');
          appRuntimeStore.setTheme('stateboy');
          appRuntimeStore.setSoundEnabled(true);
          AudioManager.enabled = true;
          setThemeIndex(0);
        }
        return;
      }

      let nextTheme: ThemeName = 'stateboy';
      let nextSoundEnabled = true;

      try {
        const savedTheme = await dsmClient.getPreference('ui_theme');
        if (savedTheme && themes.includes(savedTheme as ThemeName)) {
          nextTheme = savedTheme as ThemeName;
        }
      } catch {}

      try {
        const sfx = await dsmClient.getPreference('sfx_enabled');
        nextSoundEnabled = !(sfx === 'false' || sfx === '0' || sfx === 'no');
      } catch {}

      if (cancelled) {
        return;
      }

      appRuntimeStore.setTheme(nextTheme);
      applyTheme(nextTheme);
      const nextThemeIndex = themes.indexOf(nextTheme);
      if (nextThemeIndex >= 0) {
        setThemeIndex(nextThemeIndex);
      }

      appRuntimeStore.setSoundEnabled(nextSoundEnabled);
      AudioManager.enabled = nextSoundEnabled;
    };

    void applyUiPrefs();

    return () => {
      cancelled = true;
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps -- themes is memoized, setThemeIndex is stable from useState
  }, [session.received, session.identity_status]);

  return session;
}
