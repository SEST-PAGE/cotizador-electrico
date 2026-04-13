// ============================================================
// SEST - Service Worker v1.
// Estrategia: Cache-first para assets estáticos,
//             Network-first para llamadas API,
//             Offline fallback para navegación.
// ============================================================
const CACHE_NAME = 'sest-v1';
const CACHE_STATIC = 'sest-static-v1';

// Assets que se cachean al instalar el SW
const PRECACHE_URLS = [
  '/dashboard.html',
  '/index.html',
];

// ── Instalación: pre-cachear assets principales ────────────
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_STATIC).then(cache => {
      return cache.addAll(PRECACHE_URLS).catch(() => {
        // Si falla el pre-cache (ej. sin red en primera carga)
        // continuamos igualmente; se cachearán on-the-fly
      });
    }).then(() => self.skipWaiting())
  );
});

// ── Activación: limpiar caches viejos ──────────────────────
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys
          .filter(k => k !== CACHE_STATIC && k !== CACHE_NAME)
          .map(k => caches.delete(k))
      )
    ).then(() => self.clients.claim())
  );
});

// ── Fetch: estrategia por tipo de request ─────────────────
self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);

  // 1. Llamadas a la API → Network-first, sin cache
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(
      fetch(request).catch(() =>
        new Response(
          JSON.stringify({ error: 'Sin conexión. Reconéctate para usar esta función.' }),
          { status: 503, headers: { 'Content-Type': 'application/json' } }
        )
      )
    );
    return;
  }

  // 2. Requests externos (CDN, etc.) → Network-first con fallback silencioso
  if (url.origin !== self.location.origin) {
    event.respondWith(
      fetch(request).catch(() => new Response('', { status: 408 }))
    );
    return;
  }

  // 3. Assets locales → Cache-first, actualizar en background (stale-while-revalidate)
  event.respondWith(
    caches.open(CACHE_STATIC).then(async cache => {
      const cached = await cache.match(request);
      const fetchPromise = fetch(request).then(networkRes => {
        if (networkRes && networkRes.status === 200) {
          cache.put(request, networkRes.clone());
        }
        return networkRes;
      }).catch(() => null);

      if (cached) {
        // Devuelve el cache inmediatamente y actualiza en background
        fetchPromise; // fire-and-forget
        return cached;
      }

      // Si no hay cache, espera la red
      const networkRes = await fetchPromise;
      if (networkRes) return networkRes;

      // Fallback final: página offline para navegación HTML
      if (request.headers.get('accept')?.includes('text/html')) {
        const fallback = await cache.match('/dashboard.html') ||
                         await cache.match('/index.html');
        if (fallback) {
          return new Response(
            await fallback.text().then(html =>
              html.replace(
                '</body>',
                `<div id="sw-offline-page" style="position:fixed;inset:0;z-index:999999;background:#0e0e1a;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:16px;font-family:system-ui,sans-serif;color:#fff">
                  <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="#c0392b" stroke-width="1.5"><line x1="1" y1="1" x2="23" y2="23"/><path d="M16.72 11.06A10.94 10.94 0 0 1 19 12.55M5 12.55a10.94 10.94 0 0 1 5.17-2.39M10.71 5.05A16 16 0 0 1 22.56 9M1.42 9a15.91 15.91 0 0 1 4.7-2.88M12 20h.01"/></svg>
                  <div style="font-size:22px;font-weight:700">Sin conexión a Internet</div>
                  <div style="font-size:14px;color:#aaa;max-width:320px;text-align:center">La aplicación necesita conexión para sincronizar datos. Revisa tu red y recarga la página.</div>
                  <button onclick="location.reload()" style="margin-top:8px;padding:10px 28px;border-radius:20px;background:#c8a000;border:none;color:#000;font-size:14px;font-weight:700;cursor:pointer">↺ Reintentar</button>
                </div></body>`
              )
            ),
            { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
          );
        }
      }

      return new Response('Sin conexión', { status: 503 });
    })
  );
});

// ── Sincronización en background cuando vuelve la red ────
self.addEventListener('sync', event => {
  if (event.tag === 'sync-pendientes') {
    event.waitUntil(
      self.clients.matchAll().then(clients =>
        clients.forEach(c => c.postMessage({ type: 'SYNC_NOW' }))
      )
    );
  }
});
