#!/usr/bin/env node
/*
  Sanitize Android WebView index.html for deterministic, private assets:
  - Remove Google Fonts preconnect and stylesheet links
  - Remove fonts.googleapis.com and fonts.gstatic.com from CSP
  - Ensure local css/fonts.css link is present
  - Idempotent: safe to run multiple times
*/
const fs = require('fs');
const path = require('path');

const targets = [
  // Historical path (older layout)
  path.resolve(__dirname, '../dsm_client/android/app/src/main/assets/index.html'),
  // Current top-level Android app assets
  path.resolve(__dirname, '../android/app/src/main/assets/index.html'),
  // Nested web bundle
  path.resolve(__dirname, '../android/app/src/main/assets/webview/index.html'),
];

function sanitizeOne(indexPath) {
  if (!fs.existsSync(indexPath)) {
    console.warn(`[sanitize] Skip missing: ${indexPath}`);
    return false;
  }
  let html = fs.readFileSync(indexPath, 'utf8');
  const original = html;

  // Canonical strict CSP (no external fonts)
  const strictCsp = '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'; script-src \'self\' \'unsafe-inline\' \'unsafe-eval\'; style-src \'self\' \'unsafe-inline\'; font-src \'self\' data:; img-src \'self\' data:; connect-src \'self\' https://*.dsm-wallet.io; object-src \'none\';">';
  html = html.replace(/<meta[^>]*http-equiv=["']Content-Security-Policy["'][^>]*>/i, strictCsp);

  // Remove Google Fonts link and preconnect tags (minified-safe)
  const fontsPatterns = [
    /<link[^>]*href="https:\/\/fonts\.googleapis[^"']+"[^>]*>/g,
    /<link[^>]*href="https:\/\/fonts\.gstatic[^"']+"[^>]*>/g,
  ];
  fontsPatterns.forEach((re) => {
    html = html.replace(re, '');
  });
  // Also strip any @import google fonts statements
  html = html.replace(/@import url\(https:\/\/fonts\.googleapis\.com[^\)]*\);?/g, '');

  // Ensure local fonts stylesheet link exists, insert before first <style> in <head>
  if (!/href=["']css\/fonts\.css["']/.test(html)) {
    const insertionPoint = html.indexOf('<style>');
    if (insertionPoint !== -1) {
      html = html.slice(0, insertionPoint) + '<link rel="stylesheet" href="css/fonts.css">' + html.slice(insertionPoint);
    } else {
      // Fallback: try to insert before closing head
      const headClose = html.indexOf('</head>');
      if (headClose !== -1) {
        html = html.slice(0, headClose) + '<link rel="stylesheet" href="css/fonts.css">' + html.slice(headClose);
      }
    }
  }

  if (html !== original) {
    fs.writeFileSync(indexPath, html, 'utf8');
    console.log(`[sanitize] Updated: ${indexPath}`);
  } else {
    console.log(`[sanitize] No changes needed: ${indexPath}`);
  }

  // Post-checks
  const stillHasGoogleFonts = /(fonts\.googleapis|fonts\.gstatic)/.test(html);
  if (stillHasGoogleFonts) {
    console.warn('[sanitize] Warning: Detected residual Google Fonts reference.');
    process.exitCode = Math.max(process.exitCode || 0, 2);
  } else {
    console.log('[sanitize] Verified: no external Google Fonts references remain.');
  }
  return true;
}

function main() {
  let anyProcessed = false;
  for (const t of targets) {
    const ok = sanitizeOne(t);
    anyProcessed = anyProcessed || ok;
  }
  if (!anyProcessed) {
    console.error('[sanitize] No targets processed.');
    process.exit(1);
  }
}

main();
