#!/usr/bin/env node
/*
 Simple validator to ensure required frontend build artifacts exist in the Android assets dir.
 Fails with non-zero exit if any required file is missing.
*/

const fs = require('fs');
const path = require('path');

const ASSETS_DIR = path.resolve(__dirname, '../../android/app/src/main/assets');

const REQUIRED = [
  'index.html',
  // prefix match (hashed filename). The Android build emits one entry chunk:
  // webpack.config.js sets splitChunks and runtimeChunk off for it, so there
  // is no js/runtime or js/vendors to find (those are the web build's).
  'js/main',
  'css/main',
  'config/app.json',
  'images/logos/era_token_gb.gif',
  'dsm_env_config.toml',
];

// Optional assets: warn if missing, but don't fail
const OPTIONAL = [
  'config/mobile.json',
];

function existsPrefix(pfx) {
  const dir = path.dirname(pfx);
  const base = path.basename(pfx);
  const absDir = path.join(ASSETS_DIR, dir === '.' ? '' : dir);
  if (!fs.existsSync(absDir) || !fs.statSync(absDir).isDirectory()) return false;
  const entries = fs.readdirSync(absDir);
  return entries.some(e => e.startsWith(base));
}

function existsExact(rel) {
  return fs.existsSync(path.join(ASSETS_DIR, rel));
}

let ok = true;
for (const item of REQUIRED) {
  const ext = path.extname(item);
  const good = (ext === '.html' || ext === '.json' || ext === '.gif' || ext === '.png' || ext === '.svg')
    ? existsExact(item)
    : existsPrefix(item);
  if (!good) {
    console.error(`Error: Missing asset: ${item}`);
    ok = false;
  } else {
    console.log(`OK: Found: ${item}`);
  }
}

// The network config and the fleet's CA must be exactly the tracked files in
// frontend/public/: a copy that differs by one byte means the APK would ship a
// fleet or a CA nobody committed.
const PUBLIC_DIR = path.resolve(__dirname, '../public');
for (const name of ['dsm_env_config.toml', 'ca.crt']) {
  const shipped = path.join(ASSETS_DIR, name);
  const tracked = path.join(PUBLIC_DIR, name);
  if (!fs.existsSync(shipped) || !fs.existsSync(tracked)) {
    console.error(`Error: ${name} is missing from ${fs.existsSync(shipped) ? PUBLIC_DIR : ASSETS_DIR}`);
    ok = false;
  } else if (!fs.readFileSync(shipped).equals(fs.readFileSync(tracked))) {
    console.error(`Error: ${shipped} is not the tracked ${tracked}`);
    ok = false;
  } else {
    console.log(`OK: ${name} is the tracked public/${name}`);
  }
}

// The policy the shipped page runs under (pre-audit item 13).
const policyProblems = existsExact('index.html')
  ? require('./webview-policy').policyProblems(fs.readFileSync(path.join(ASSETS_DIR, 'index.html'), 'utf8'))
  : [];
for (const problem of policyProblems) {
  console.error(`Error: index.html's Content-Security-Policy: ${problem}`);
}
if (policyProblems.length === 0) {
  console.log("OK: index.html's Content-Security-Policy admits no eval and no unhashed inline script");
}

if (!ok || policyProblems.length > 0) {
  console.error(`\nAsset validation failed in ${ASSETS_DIR}`);
  process.exit(1);
}
console.log(`\nAll required assets present in ${ASSETS_DIR}`);

// Warn for optional assets
for (const item of OPTIONAL) {
  const ext = path.extname(item);
  const good = (ext === '.html' || ext === '.json' || ext === '.gif' || ext === '.png' || ext === '.svg')
    ? existsExact(item)
    : existsPrefix(item);
  if (!good) {
    console.warn(`Optional asset missing: ${item}`);
  }
}
