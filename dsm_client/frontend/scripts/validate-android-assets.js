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
  'js/main', // prefix match (hashed filename)
  'js/runtime',
  'js/vendors',
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

if (!ok) {
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
