/// <reference types="jest" />
/* eslint-disable @typescript-eslint/no-explicit-any */
import { isFeatureEnabled, enableFeatureForSession, clearFeatureOverrideForSession, clearAllFeatureOverridesForSession } from '../featureFlags';

describe('featureFlags', () => {
  beforeEach(() => {
    clearAllFeatureOverridesForSession();
    (globalThis as any).window = (globalThis as any).window || ({} as any);
    delete (globalThis as any).window.__DSM_DEV_MODE__;
  });

  test('storageObjectBrowser disabled by default in test env', async () => {
    expect(await isFeatureEnabled('storageObjectBrowser')).toBe(false);
  });

  test('storageObjectBrowser enabled when __DSM_DEV_MODE__ is true', async () => {
    (globalThis as any).window.__DSM_DEV_MODE__ = true;
    expect(await isFeatureEnabled('storageObjectBrowser')).toBe(true);
  });

  test('local override enables feature in non-dev', async () => {
    enableFeatureForSession('storageObjectBrowser', true);
    expect(await isFeatureEnabled('storageObjectBrowser')).toBe(true);
  });

  test('local override disables feature even in dev', async () => {
    (globalThis as any).window.__DSM_DEV_MODE__ = true;
    enableFeatureForSession('storageObjectBrowser', false);
    expect(await isFeatureEnabled('storageObjectBrowser')).toBe(false);
    clearFeatureOverrideForSession('storageObjectBrowser');
  });
});
