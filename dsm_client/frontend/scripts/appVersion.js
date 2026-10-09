// SPDX-License-Identifier: Apache-2.0
/*
 The app's version, read where the Android build names it: versionName in
 android/app/build.gradle.kts. The bundler puts it in the page as
 process.env.DSM_APP_VERSION (and the tests' setup does the same), so the
 version the screens show is the version of the APK they ship in. A build
 file without a versionName stops the build rather than show another.
*/
const fs = require('fs');
const path = require('path');

const GRADLE = path.resolve(__dirname, '../../android/app/build.gradle.kts');

function readAppVersion() {
  const text = fs.readFileSync(GRADLE, 'utf8');
  const found = text.match(/versionName\s*=\s*"([^"]+)"/);
  if (!found) throw new Error(`no versionName in ${GRADLE}`);
  return found[1];
}

module.exports = { readAppVersion };
