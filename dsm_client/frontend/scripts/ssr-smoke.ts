/*
  Minimal SSR smoke test for the React app. This doesn't need a DOM; it simply
  renders the App component to a string to ensure there are no import-time or
  render-time crashes in a Node environment.
*/

/* eslint-disable no-console */
import React from 'react';
import { renderToString } from 'react-dom/server';
import path from 'path';

// Lightweight path alias shim for ts-node (maps '@/...' -> src/...)
// Only for SSR smoke; webpack handles this in real builds.
import Module from 'module';
// Stub out style and asset imports that aren't meaningful in Node SSR
type RequireExtensions = {
  [key: string]: (module: NodeModule, filename: string) => void;
};
const reqExt = require.extensions as unknown as RequireExtensions;
const ignoredExts = [
  '.css', '.scss', '.sass', '.less',
  '.svg', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico',
  '.mp3', '.ogg', '.wav'
];
for (const ext of ignoredExts) {
  // Controlled stubbing of known extensions for SSR-only context
  // eslint-disable-next-line security/detect-object-injection
  reqExt[ext] = (_module: NodeModule, _filename: string) => {
    // No-op export to satisfy importers in Node SSR
    // @ts-expect-error NodeModule typing doesn't declare exports
    _module.exports = {};
  };
}
const originalResolve = Module._resolveFilename as (
  request: string,
  parent: unknown,
  isMain: boolean,
  options: unknown
) => string;
Module._resolveFilename = function(
  request: string,
  parent: unknown,
  isMain: boolean,
  options: unknown
) {
  if (request.startsWith('@/')) {
    const mapped = path.join(__dirname, '../src', request.slice(2));
    return originalResolve.call(this, mapped, parent, isMain, options);
  }
  if (request === 'leaflet' || request.startsWith('leaflet/')) {
    const stub = path.join(__dirname, './leaflet-stub.js');
    return originalResolve.call(this, stub, parent, isMain, options);
  }
  return originalResolve.call(this, request, parent, isMain, options);
};

// Use a minimal shell for App to avoid requiring window. If App relies on
// browser globals, we can guard usage inside effects.
import App from '../src/App';

function main() {
  try {
    const html = renderToString(React.createElement(App));
    if (typeof html !== 'string' || html.length === 0) {
      throw new Error('SSR render produced empty output');
    }
    console.log('[SSR-SMOKE] Render OK, length:', html.length);
    process.exit(0);
  } catch (err) {
    console.error('[SSR-SMOKE] Render failed:', err);
    process.exit(1);
  }
}

main();
