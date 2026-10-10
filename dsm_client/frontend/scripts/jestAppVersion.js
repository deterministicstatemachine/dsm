// SPDX-License-Identifier: Apache-2.0
// The tests see the app's version as the bundled page does (scripts/appVersion.js).
const { readAppVersion } = require('./appVersion');

process.env.DSM_APP_VERSION = readAppVersion();
