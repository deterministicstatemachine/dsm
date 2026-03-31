/* DSM Service Worker - offline-first tiles + app shell */
const VERSION = 'v1';
const APP_SHELL = [
  '/',
  '/index.html',
  '/styles.css',
  // Add other critical assets if needed
];

// Separate caches to keep tiles bounded
const APP_CACHE = `dsm-app-${VERSION}`;
const TILE_CACHE = `dsm-tiles-${VERSION}`;

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(APP_CACHE).then((cache) => cache.addAll(APP_SHELL)).then(self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((k) => ![APP_CACHE, TILE_CACHE].includes(k))
          .map((k) => caches.delete(k))
      )
    ).then(() => self.clients.claim())
  );
});

// Helper: is tile request
function isTileRequest(url) {
  try {
    const u = new URL(url);
    return (
      u.hostname.endsWith('tile.openstreetmap.org') ||
      u.hostname.endsWith('demotiles.maplibre.org')
    );
  } catch (_) {
    return false;
  }
}

self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = request.url;

  // Only handle GET
  if (request.method !== 'GET') return;

  // Cache-first for map tiles with expiration
  if (isTileRequest(url)) {
    event.respondWith(
      caches.open(TILE_CACHE).then(async (cache) => {
        const cached = await cache.match(request);
        if (cached) return cached;
        try {
          const resp = await fetch(request, { mode: 'cors' });
          // Only cache successful, opaque or basic responses
          if (resp && (resp.status === 200 || resp.type === 'opaque')) {
            cache.put(request, resp.clone());
          }
          return resp;
        } catch (err) {
          // If offline and no cache, fall through (will fail)
          return cached || Response.error();
        }
      })
    );
    return;
  }

  // Network-first for app/json requests
  event.respondWith(
    (async () => {
      try {
        const netResp = await fetch(request);
        // Optionally cache app shell assets
        if (request.destination === 'document' || request.destination === 'style' || request.destination === 'script') {
          const cache = await caches.open(APP_CACHE);
          cache.put(request, netResp.clone());
        }
        return netResp;
      } catch (e) {
        const cache = await caches.open(APP_CACHE);
        const cached = await cache.match(request);
        if (cached) return cached;
        // If document request, try fallback to index
        if (request.destination === 'document') {
          const index = await cache.match('/index.html');
          if (index) return index;
        }
        throw e;
      }
    })()
  );
});
