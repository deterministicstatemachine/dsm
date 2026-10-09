// SPDX-License-Identifier: Apache-2.0
// The wallet's look and the user's switches, kept as native preferences: which
// skin (Simple or the Game Boy), the Simple skin's colours, whether Simple
// offers the offline appliance, and whether receipts are emailed. Each is read
// once the identity is ready and written the moment the user changes it.

import { dsmClient } from '../services/dsmClient';
import { appRuntimeStore, type Scheme, type Skin, type Switch } from './appRuntimeStore';
import {
  RECEIPTS_EMAIL_PREFERENCE,
  SCHEME_PREFERENCE,
  SIMPLE_OFFLINE_PREFERENCE,
  SKIN_PREFERENCE,
} from './skinKeys';

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
  appRuntimeStore.setScheme(readScheme(scheme));
  appRuntimeStore.setSimpleOffline(readSwitch(offline));
  appRuntimeStore.setReceiptsEmail(readSwitch(receipts));
  appRuntimeStore.setSkinRead('read');
}

/** Forgets what was read: no identity, no choices. */
export function clearSkinPreferences(): void {
  appRuntimeStore.setSkinRead('unread');
  appRuntimeStore.setSkin(null);
  appRuntimeStore.setScheme('light');
  appRuntimeStore.setSimpleOffline('off');
  appRuntimeStore.setReceiptsEmail('off');
}

export async function chooseSkin(skin: Skin): Promise<void> {
  await dsmClient.setPreference(SKIN_PREFERENCE, skin);
  appRuntimeStore.setSkin(skin);
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
