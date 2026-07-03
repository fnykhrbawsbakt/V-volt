const CACHE_NAME = "fanni-queue-shell-v1";
const SHELL_FILES = ["/", "/index.html", "/manifest.json"];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_FILES)).catch(() => {})
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// الداتا الحقيقية (/api/queue) لازم تيجي من النت دايمًا، مش من الكاش
self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (url.pathname.startsWith("/api/")) {
    return; // سيب طلبات الـ API تروح للنت عادي، من غير تدخل من الـ service worker
  }
  event.respondWith(
    fetch(event.request).catch(() => caches.match(event.request))
  );
});
