// Offline-Cache: mit Netz kommen App-Dateien immer frisch vom Server (und landen im Cache), ohne Netz aus dem Cache.
// Nicht „erst Cache, im Hintergrund aktualisieren“: dann könnten index.html und sync.js aus verschiedenen Versionen stammen.
// Bei neuen/umbenannten Dateien CACHE hochzählen.
const CACHE = 'kaffee-v4';
const FILES = ['./', 'index.html', 'sync.js', 'manifest.webmanifest', 'icon-180.png', 'icon-512.png', 'Logo_NoBackground.png'];

self.addEventListener('install', e => e.waitUntil(
  caches.open(CACHE).then(c => c.addAll(FILES)).then(() => self.skipWaiting())
));

self.addEventListener('activate', e => e.waitUntil(
  caches.keys()
    .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
    .then(() => self.clients.claim())
));

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== location.origin) return; // fremde Bild-Links normal laden
  e.respondWith(fetch(e.request).then(r => {
    if (r.ok) { const copy = r.clone(); caches.open(CACHE).then(c => c.put(e.request, copy)); }
    return r;
  }).catch(() => caches.match(e.request, {ignoreSearch: true}).then(hit => hit || Response.error())));
});
