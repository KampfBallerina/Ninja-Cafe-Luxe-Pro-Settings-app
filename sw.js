// Offline-Cache: App-Dateien kommen sofort aus dem Cache und werden bei Netz im Hintergrund
// aktualisiert – eine neue Version ist also ab dem übernächsten Öffnen sichtbar.
// Bei neuen/umbenannten Dateien CACHE hochzählen.
const CACHE = 'kaffee-v2';
const FILES = ['./', 'index.html', 'manifest.webmanifest', 'icon-180.png', 'icon-512.png', 'Logo_NoBackground.png'];

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
  e.respondWith(caches.match(e.request, {ignoreSearch: true}).then(hit => {
    const net = fetch(e.request).then(r => {
      if (r.ok) { const copy = r.clone(); caches.open(CACHE).then(c => c.put(e.request, copy)); }
      return r;
    });
    if (!hit) return net;
    net.catch(() => {}); // offline: Cache reicht
    return hit;
  }));
});
