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

// The Android assets directory is regenerated on every build: nothing in it
// is kept from a previous build, so nothing stale can be packaged.
console.log('Cleaning existing Android assets...');
try {
  const existing = fs.readdirSync(targetDir);
  existing.forEach((name) => {
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

// The network config and the fleet's CA the app ships with. Their one tracked
// source is frontend/public/; they are written here straight from it, after
// everything else, and checked byte for byte. They are not taken from dist/:
// a build once packaged dist/'s previous copy of both while public/ held the
// new ones, and the app then trusted a retired CA and a retired fleet. For a
// local fleet, push an override config to the device
// (scripts/push_env_override.sh); do not edit the copies here — every build
// rewrites them.
const RUNTIME_CONFIG = ['dsm_env_config.toml', 'ca.crt'];
const publicDir = path.join(__dirname, '..', 'public');
for (const name of RUNTIME_CONFIG) {
  const source = path.join(publicDir, name);
  const target = path.join(targetDir, name);
  if (!fs.existsSync(source)) {
    console.error(`Error: ${source} is missing; the app cannot reach the network without it`);
    process.exit(1);
  }
  fs.copyFileSync(source, target);
  if (!fs.readFileSync(source).equals(fs.readFileSync(target))) {
    console.error(`Error: ${target} does not equal ${source} after copying`);
    process.exit(1);
  }
  console.log(`OK: ${name} written from public/`);
}
