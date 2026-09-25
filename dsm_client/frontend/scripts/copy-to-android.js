#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const sourceDir = path.join(__dirname, '..', 'dist');
const compiledTsDir = path.join(__dirname, '..', 'dist', 'compiled');
const targetDir = path.join(__dirname, '..', '..', 'android', 'app', 'src', 'main', 'assets');

console.log('Info: Copying React build assets to Android...');
console.log(`   From: ${sourceDir}`);
console.log(`   To: ${targetDir}`);

const overlayDir = path.join(__dirname, '..', 'android-assets');

// Ensure target directory exists
if (!fs.existsSync(targetDir)) {
  fs.mkdirSync(targetDir, { recursive: true });
  console.log('Created Android assets directory');
}

// Remove stale assets (but preserve whitelisted files such as env configs)
const whitelist = new Set(['dsm_env_config.json', 'dsm_env_config.toml', 'ca.crt']);
console.log('Cleaning existing Android assets (preserving whitelist)...');
try {
  const existing = fs.readdirSync(targetDir);
  existing.forEach((name) => {
    if (whitelist.has(name)) return; // keep whitelisted files
    const full = path.join(targetDir, name);
    try {
      const stat = fs.lstatSync(full);
      if (stat.isDirectory()) {
        fs.rmSync(full, { recursive: true, force: true });
        console.log(`   Removed dir: ${name}`);
      } else {
        fs.unlinkSync(full);
        console.log(`   Removed file: ${name}`);
      }
    } catch (e) {
      console.warn(`   Warning: failed to remove ${full}: ${e.message}`);
    }
  });
} catch (e) {
  console.warn('Warning: Could not clean Android assets directory:', e.message);
}

// Copy all files from dist to Android assets
function copyRecursive(source, target) {
  const stats = fs.statSync(source);

  if (stats.isDirectory()) {
    if (!fs.existsSync(target)) {
      fs.mkdirSync(target, { recursive: true });
    }

    const files = fs.readdirSync(source);
    files.forEach(file => {
      const sourcePath = path.join(source, file);
      const targetPath = path.join(target, file);
      copyRecursive(sourcePath, targetPath);
    });
  } else {
    fs.copyFileSync(source, target);
    console.log(`   ${path.relative(sourceDir, source)}`);
  }
}

if (fs.existsSync(sourceDir)) {
  copyRecursive(sourceDir, targetDir);
  console.log('OK: Assets copied successfully');
} else {
  console.error(`Error: Source directory not found: ${sourceDir}`);
  console.log('Note: Make sure to run the React build first: npm run build:webpack');
  process.exit(1);
}

// Copy compiled TypeScript output if it exists
if (fs.existsSync(compiledTsDir)) {
  console.log('Info: Copying compiled TypeScript output to Android...');
  const tsTargetDir = path.join(targetDir, 'compiled');
  copyRecursive(compiledTsDir, tsTargetDir);
  console.log('OK: Compiled TypeScript copied successfully');
} else {
  console.log('Info: No compiled TypeScript output found (skipping)');
}

// Overlay any Android-specific assets from frontend/android-assets (source of truth)
if (fs.existsSync(overlayDir)) {
  console.log(`Overlaying Android-specific assets from ${overlayDir}`);
  copyRecursive(overlayDir, targetDir);
}

// Single source of truth for config: android/app/src/main/assets/dsm_env_config.toml.
// Do NOT add code that copies over that file — it will break allow_localhost.
