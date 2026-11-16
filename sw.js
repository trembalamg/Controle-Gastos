/* Service worker (só no GitHub Pages): guarda os arquivos do app para abrir sem internet.
 * Rede primeiro (pega sempre a versão nova); sem internet, usa a cópia. Chamadas ao GitHub e ao Banco Central
 * passam direto (nunca ficam guardadas aqui). Para publicar uma versão nova, troque VERSAO. */
const VERSAO = 'cg-2026-11-15c';
const ARQUIVOS = ['./', 'index.html', 'nuvem.js', 'regras.js', 'dinheiro.js', 'qrcode.js', 'chart.umd.min.js',
  'manifest.webmanifest', 'icone.png', 'icone-180.png', 'icone-192.png', 'icone-512.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(VERSAO).then(c => c.addAll(ARQUIVOS)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== VERSAO).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (e.request.method !== 'GET' || u.origin !== self.location.origin) return;   // GitHub API, Banco Central: direto
  // cache: 'no-cache' = sempre confere com o GitHub se há versão nova (sem isso o navegador usava a cópia de até 10 min)
  e.respondWith(
    fetch(e.request.url, { cache: 'no-cache', credentials: 'same-origin' }).then(r => {
      if (r.ok) { const c = r.clone(); caches.open(VERSAO).then(ca => ca.put(e.request, c)); }
      return r;
    }).catch(() => caches.match(e.request, { ignoreSearch: true }).then(r => r || caches.match('index.html')))
  );
});
