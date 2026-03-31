#!/usr/bin/env node

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('Starting complete DSM wallet build process...');

// Build React frontend
console.log('Building React frontend for Android...');
try {
  execSync('npm run build:android-webpack', { stdio: 'inherit' });
  console.log('OK: React build completed for Android');
} catch (error) {
  console.error('Error: React build failed:', error.message);
  process.exit(1);
}

// Copy assets to Android
console.log('Info: Copying assets to Android...');
try {
  execSync('npm run copy:android', { stdio: 'inherit' });
  console.log('OK: Assets copied to Android');
} catch (error) {
  console.error('Error: Asset copy failed:', error.message);
  process.exit(1);
}

// Build Android app
console.log('Building Android app...');
try {
  execSync('npm run build:android', { stdio: 'inherit' });
  console.log('OK: Android build completed');
} catch (error) {
  console.error('Error: Android build failed:', error.message);
  process.exit(1);
}

console.log('Complete build process finished successfully!');
console.log('Next steps:');
console.log('   1. Connect Android device or start emulator');
console.log('   2. Run: npm run build:android (from android directory)');
console.log('   3. Or use Android Studio to deploy');
