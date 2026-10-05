// Страницы всегда с сервера (свежие данные), статика из кэша
const CACHE = "vexmont-static-v1";
self.addEventListener("install", e => { e.waitUntil(caches.open(CACHE).then(c => c.addAll(["/static/style.css?v=3", "/static/icon-192.png"]))); self.skipWaiting(); });
self.addEventListener("activate", e => { e.waitUntil(caches.keys().then(k => Promise.all(k.filter(x => x !== CACHE).map(x => caches.delete(x))))); self.clients.claim(); });
self.addEventListener("fetch", e => {
  const u = new URL(e.request.url);
  if (e.request.method !== "GET" || !u.pathname.startsWith("/static/")) return;
  e.respondWith(caches.match(e.request).then(r => r || fetch(e.request).then(res => { const c = res.clone(); caches.open(CACHE).then(x => x.put(e.request, c)); return res; })));
});
