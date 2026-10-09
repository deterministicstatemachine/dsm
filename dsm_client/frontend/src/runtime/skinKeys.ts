// SPDX-License-Identifier: Apache-2.0
// The names of the skin preferences. Kept apart from runtime/skinPreferences.ts,
// which reads them through the bridge, so the bridge's practice gate can name
// them without importing the bridge back.

export const SKIN_PREFERENCE = 'ui_skin';
export const SCHEME_PREFERENCE = 'ui_scheme';
export const SIMPLE_MODE_PREFERENCE = 'simple_mode';
export const SIMPLE_OFFLINE_PREFERENCE = 'simple_offline';
export const RECEIPTS_EMAIL_PREFERENCE = 'receipts_email';

/** Every skin preference: the practice gate lets the tour change them. */
export const SKIN_PREFERENCES = [
  SKIN_PREFERENCE,
  SCHEME_PREFERENCE,
  SIMPLE_MODE_PREFERENCE,
  SIMPLE_OFFLINE_PREFERENCE,
  RECEIPTS_EMAIL_PREFERENCE,
] as const;
