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

// Overlay any Android-specific assets from new_frontend/android-assets (source of truth)
if (fs.existsSync(overlayDir)) {
  console.log(`Overlaying Android-specific assets from ${overlayDir}`);
  copyRecursive(overlayDir, targetDir);
}

// Inject MPC API key from environment into the assets TOML if provided.
// Single source of truth for config: android/app/src/main/assets/dsm_env_config.toml
// Do NOT add any other code that copies over that file — it will break allow_localhost.
try {
  const assetsToml = path.join(targetDir, 'dsm_env_config.toml');
  const envKey = process.env.DSM_MPC_API_KEY && String(process.env.DSM_MPC_API_KEY);
  const envKeyFile = process.env.DSM_MPC_API_KEY_FILE && String(process.env.DSM_MPC_API_KEY_FILE);
  let keyToUse = '';
  if (envKey && envKey.trim().length > 0) {
    keyToUse = envKey.trim();
  } else if (envKeyFile && envKeyFile.trim().length > 0) {
    try {
      keyToUse = fs.readFileSync(envKeyFile.trim(), 'utf8').trim();
    } catch (e) {
      console.warn(`Warning: Failed to read DSM_MPC_API_KEY_FILE: ${e.message}`);
    }
  }

  if (keyToUse && keyToUse.length > 0 && fs.existsSync(assetsToml)) {
    let toml = fs.readFileSync(assetsToml, 'utf8');
    const line = `mpc_api_key = "${keyToUse.replace(/"/g, '\\"')}"`;
    if (/^\s*mpc_api_key\s*=\s*".*"/m.test(toml)) {
      toml = toml.replace(/^\s*mpc_api_key\s*=\s*".*"/m, line);
    } else if (/^\s*#\s*mpc_api_key\s*=\s*".*"/m.test(toml)) {
      toml = toml.replace(/^\s*#\s*mpc_api_key\s*=\s*".*"/m, line);
    } else {
      toml = toml.trimEnd() + "\n" + line + "\n";
    }
    fs.writeFileSync(assetsToml, toml);
    const masked = keyToUse.length <= 6 ? '*'.repeat(keyToUse.length) : `${keyToUse.slice(0,3)}***${keyToUse.slice(-2)}`;
    console.log(`Injected DSM_MPC_API_KEY into dsm_env_config.toml (value masked: ${masked})`);
  } else {
    console.log('Info: DSM_MPC_API_KEY not set; dsm_env_config.toml left as-is.');
  }
} catch (e) {
  console.warn('Warning: Failed to inject DSM_MPC_API_KEY into TOML:', e.message);
}
