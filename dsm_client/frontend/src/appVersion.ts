// SPDX-License-Identifier: Apache-2.0
// The version of this build of the app, as the Android build names it
// (versionName): the bundler reads it there (scripts/appVersion.js), so the
// screens and the APK they ship in never disagree.

export function appVersion(): string {
  const version = process.env.DSM_APP_VERSION;
  if (version === undefined || version.length === 0) {
    throw new Error('The build did not name the app version (DSM_APP_VERSION).');
  }
  return version;
}

/** How the app names itself: "DSM v0.1.0-beta.4 Pre-release". A SemVer pre-release version says so. */
export function versionLabel(): string {
  const version = appVersion();
  return `DSM v${version}${version.includes('-') ? ' Pre-release' : ''}`;
}
