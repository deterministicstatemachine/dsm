/* eslint-disable @typescript-eslint/no-explicit-any */
// Centralized feature flag helpers for DSM frontend

import { getPreference, setPreference } from '../dsm/WebViewBridge';

type FeatureKey =
  | 'storageObjectBrowser'
  | 'storageDiagnostics';

const DEFAULTS: Record<FeatureKey, boolean> = {
  storageObjectBrowser: false,
  storageDiagnostics: true,
};

const sessionOverrides = new Map<FeatureKey, boolean>();

async function readLocalOverride(key: FeatureKey): Promise<boolean | null> {
  // 1) check session overrides (in-memory)
  if (sessionOverrides.has(key)) {
    return sessionOverrides.get(key) === true;
  }

  // 2) check persistent preferences
  try {
    const v = await getPreference(`feature.${key}`);
    if (v == null) return null;
    if (v === '1' || v.toLowerCase() === 'true') return true;
    if (v === '0' || v.toLowerCase() === 'false') return false;
  } catch {}
  return null;
}

export function isDevMode(): boolean {
  try {
    // webpack DefinePlugin typically injects process.env.NODE_ENV
    const env = (typeof process !== 'undefined' ? (process as any).env?.NODE_ENV : undefined) || '';
    if (env === 'development') return true;
  } catch {}
  try {
    // Allow runtime flag to enable dev features in production builds for local debugging
    const w: any = typeof window !== 'undefined' ? window : {};
    if (w.__DSM_DEV_MODE__ === true) return true;
  } catch {}
  return false;
}

export async function isFeatureEnabled(key: FeatureKey): Promise<boolean> {
  // 1) explicit local override wins
  const override = await readLocalOverride(key);
  if (override !== null) return override;

  // 2) development defaults
  if (isDevMode()) {
    if (key === 'storageObjectBrowser') return true;
  }

  // 3) production defaults
  return DEFAULTS[key];
}

export async function setFeatureEnabled(key: FeatureKey, enabled: boolean): Promise<void> {
  await setPreference(`feature.${key}`, enabled ? '1' : '0');
}

export async function clearFeatureOverride(key: FeatureKey): Promise<void> {
  await setPreference(`feature.${key}`, '');
}

export function enableFeatureForSession(key: FeatureKey, enabled: boolean): void {
  sessionOverrides.set(key, enabled === true);
}

export function clearFeatureOverrideForSession(key: FeatureKey): void {
  sessionOverrides.delete(key);
}

// Test helper: clear all in-memory overrides.
export function clearAllFeatureOverridesForSession(): void {
  sessionOverrides.clear();
}

export type { FeatureKey };
