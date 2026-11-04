#!/usr/bin/env node
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copies the React build into the iOS app's bundle folder (`DsmWallet/www`),
// which Xcode packages as a folder reference. The folder is regenerated on
// every build: nothing in it is kept from a previous build, so nothing stale
// can be packaged. The same build the Android copy script takes, from the
// same `dist`.

const fs = require('fs');
const path = require('path');

const sourceDir = path.join(__dirname, '..', 'dist');
const targetDir = path.join(__dirname, '..', '..', 'ios', 'DsmWallet', 'www');

if (!fs.existsSync(sourceDir)) {
  console.error(`copy-to-ios: no build at ${sourceDir}; run the webpack build first`);
  process.exit(1);
}

// The copy mirrors the build's tree, so each operation is recursive exactly
// when the path it acts on is a directory; the parent (`DsmWallet/`) is part
// of the checkout and is created only when it is missing.
const sourceIsTree = fs.statSync(sourceDir).isDirectory();
if (fs.existsSync(targetDir)) {
  fs.rmSync(targetDir, { recursive: fs.statSync(targetDir).isDirectory() });
}
fs.mkdirSync(targetDir, { recursive: !fs.existsSync(path.dirname(targetDir)) });
fs.cpSync(sourceDir, targetDir, { recursive: sourceIsTree });

const index = path.join(targetDir, 'index.html');
if (!fs.existsSync(index)) {
  console.error(`copy-to-ios: the build has no index.html at ${index}`);
  process.exit(1);
}
console.log(`copy-to-ios: ${sourceDir} -> ${targetDir}`);
