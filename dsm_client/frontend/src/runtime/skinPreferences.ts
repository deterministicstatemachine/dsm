// SPDX-License-Identifier: Apache-2.0
// The wallet's look and the user's switches, kept as native preferences: which
// skin (Simple or the Game Boy), the Simple skin's colours, whether Simple
// offers the offline appliance, and whether receipts are emailed. Each is read
// as soon as the bridge is up (they are the app's, not a wallet's: they hold
// before any wallet exists) and written the moment the user changes it. The
// skin is also kept on the page as a hint, so the first paint after a restart
// is already in the chosen look; the preference stays the authority.

import { dsmClient } from '../services/dsmClient';
import logger from '../utils/logger';
import { appRuntimeStore, type Scheme, type Skin, type Switch } from './appRuntimeStore';
import {
  RECEIPTS_EMAIL_PREFERENCE,
  SCHEME_PREFERENCE,
  SIMPLE_OFFLINE_PREFERENCE,
  SKIN_PREFERENCE,
} from './skinKeys';

const SKIN_HINT = 'dsm-skin-hint';

/** The skin the page last drew, for the first paint; `null` when none is kept. */
export function readSkinHint(): Skin | null {
  try {
    return readSkin(window.localStorage.getItem(SKIN_HINT));
  } catch (e: unknown) {
    logger.warn('[skin] the page keeps no skin hint here:', e);
    return null;
  }
}

function keepSkinHint(skin: Skin | null): void {
  try {
    if (skin === null) window.localStorage.removeItem(SKIN_HINT);
    else window.localStorage.setItem(SKIN_HINT, skin);
  } catch (e: unknown) {
    logger.warn('[skin] the page could not keep the skin hint:', e);
  }
}

export function readSkin(value: string | null): Skin | null {
  return value === 'simple' || value === 'classic' ? value : null;
}

export function readScheme(value: string | null): Scheme {
  return value === 'dark' ? 'dark' : 'light';
}

export function readSwitch(value: string | null): Switch {
  return value === 'on' ? 'on' : 'off';
}

/** Reads every preference into the runtime store. */
export async function loadSkinPreferences(): Promise<void> {
  const [skin, scheme, offline, receipts] = await Promise.all([
    dsmClient.getPreference(SKIN_PREFERENCE),
    dsmClient.getPreference(SCHEME_PREFERENCE),
    dsmClient.getPreference(SIMPLE_OFFLINE_PREFERENCE),
    dsmClient.getPreference(RECEIPTS_EMAIL_PREFERENCE),
  ]);
  appRuntimeStore.setSkin(readSkin(skin));
  keepSkinHint(readSkin(skin));
  appRuntimeStore.setScheme(readScheme(scheme));
  appRuntimeStore.setSimpleOffline(readSwitch(offline));
  appRuntimeStore.setReceiptsEmail(readSwitch(receipts));
  appRuntimeStore.setSkinRead('read');
}

export async function chooseSkin(skin: Skin): Promise<void> {
  await dsmClient.setPreference(SKIN_PREFERENCE, skin);
  appRuntimeStore.setSkin(skin);
  keepSkinHint(skin);
}

export async function chooseScheme(scheme: Scheme): Promise<void> {
  await dsmClient.setPreference(SCHEME_PREFERENCE, scheme);
  appRuntimeStore.setScheme(scheme);
}

export async function setSimpleOffline(value: Switch): Promise<void> {
  await dsmClient.setPreference(SIMPLE_OFFLINE_PREFERENCE, value);
  appRuntimeStore.setSimpleOffline(value);
}

/**
 * Email receipts are switched on only from the consent screen, which states
 * what the receipt service is sent; switching them off needs no consent.
 */
export async function setReceiptsEmail(value: Switch): Promise<void> {
  await dsmClient.setPreference(RECEIPTS_EMAIL_PREFERENCE, value);
  appRuntimeStore.setReceiptsEmail(value);
}
