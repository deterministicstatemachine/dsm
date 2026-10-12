/* DSM Service Worker - offline-first app shell */
const VERSION = 'v1';
const APP_SHELL = [
  '/',
  '/index.html',
  '/styles.css',
  // Add other critical assets if needed
];

const APP_CACHE = `dsm-app-${VERSION}`;

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
          .filter((k) => k !== APP_CACHE)
          .map((k) => caches.delete(k))
      )
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = request.url;

  // Only handle GET
  if (request.method !== 'GET') return;

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
