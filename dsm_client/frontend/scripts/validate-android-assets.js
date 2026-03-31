#!/usr/bin/env node
/*
 Simple validator to ensure required frontend build artifacts exist in the Android assets dir.
 Fails with non-zero exit if any required file is missing.
*/

const fs = require('fs');
const path = require('path');

const ASSETS_DIR = path.resolve(__dirname, '../../android/app/src/main/assets');

const REQUIRED_EXACT = [
  'index.html',
  'config/app.json',
  'images/logos/era_token_gb.gif',
  'dsm_env_config.toml',
];

const REQUIRED_PREFIX = [
  'js/main',
  'css/main',
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

function listJsAssets() {
  const jsDir = path.join(ASSETS_DIR, 'js');
  if (!fs.existsSync(jsDir) || !fs.statSync(jsDir).isDirectory()) return [];
  return fs.readdirSync(jsDir).filter(entry => entry.endsWith('.js'));
}

let ok = true;
for (const item of REQUIRED_EXACT) {
  const good = existsExact(item);
  if (!good) {
    console.error(`Error: Missing asset: ${item}`);
    ok = false;
  } else {
    console.log(`OK: Found: ${item}`);
  }
}

for (const item of REQUIRED_PREFIX) {
  const good = existsPrefix(item);
  if (!good) {
    console.error(`Error: Missing asset: ${item}`);
    ok = false;
  } else {
    console.log(`OK: Found: ${item}`);
  }
}

const jsAssets = listJsAssets();
if (jsAssets.length === 0) {
  console.error('Error: Missing JavaScript assets in js/') ;
  ok = false;
} else {
  console.log(`OK: Found JavaScript assets: ${jsAssets.join(', ')}`);
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
