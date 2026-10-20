/*
 * Sealed playtest build: the service worker. Every game file on this site is
 * encrypted; a phone that has entered the password keeps the content key in
 * IndexedDB (non-extractable), and this worker decrypts each file as the game
 * asks for it. Without the key, navigations get the password page and
 * everything else is refused. Updates follow the app's native lifecycle: a new
 * worker waits until the old app is closed.
 */
const BUILD = '20261020233124-6ee871';
// Sites on the same github.io origin share the cache storage: each keeps its own.
const SITE = 'playtest';
const CACHE = `lbcb-sealed-${SITE}-${BUILD}`;
// Caches from before per-site names ("lbcb-sealed-<build>") belong to the first site, playtest.
const LEGACY_CACHE = /^lbcb-sealed-\d{14}-[0-9a-f]{6}$/;
const PUBLIC = new Set(["gate.html","lock.json","robots.txt","icons/icon-192.png","icons/icon-512.png","icons/maskable-512.png","manifest.webmanifest"]);
const SEALED_IDS = ["fa213f5658ff0db414bc789e","690b8ad142bbcef1d5812f39","10b8409ac3df533931893d71","4d5c3a2c4c3fb9fdd7b9fa38","f61266d1c1b9111de9d555d4","76d25c8aa2c085744e135e5e","c8f737af233389ab36f6f00f","6861e2be2738740bc61f1647","e9378f29c51a62756cfd999c","769f7d68abca7932f4b4aca9","650de883c9d483d766f43d90","995e45ed934b35bc0c2ed5e1","a86583190c78d034ff6ae667","012875b8ce082f00b80d9d35","904a8547ad18074225870a43","ca2e131364063a1d8c918cc4","1a3218481ee3ce2030da1e4c","2dad35126b02a2e481a078eb","e1678bed5190d66beebe5945","6649d98c5fdec59f4dca5b43","f6e6e867403aa814a3b92393","a02d26bae3a519d89a841133","e1e5ae46fc0989673bbf26d6","b4060254fb22ccfe18725266","6b27abc1dad8d20ee77e8cc6","4833024c26f4e1fba3bdc2e6","70fdfd6286edfc0d5060e898","30ba9de3017d290f86d8215e","aeff6a6fa665d80b5e5626df","bf0716b260dd103e66218f72","ed604cf010eb1f50a9c65544","f2bf293034fc49e1f89f6ee7","b1b5e741abe97b929a7796f3","36281196424b9cf3f832158a","3f879b71d5062d84878e2123","c22955f945faacef6de11ca0","863fd69dcb05aa0975a72966","772aa41044b38b0251d9f0f7","6eec9ce0259728037e080f2d","b384d666c191121c25d9f7c2","bc46cd73780a2143c5d3d205","5094675453610e801bd89d31","5ce8937dbd13b2b9fffdc5a4","fc36472bd7dbca080dba717b","6855b34563a8636f02703c40","915ea78289d070def7511f6f","78b45e18863eefc0ca6242f9","92fbb7ea77e93f045763e290","2101279105f8940ef312e577","5e8f36ad94ca771642e6c3aa","f97555af2338fd343f93505e","bbae7b8ebb4b3e60f9090fdb","48e674af25f492fc7cb5312d","c61cfa10b155ed21a5db75ab","44d84ce06a0746f10cb7ed88","6817973ad2c2929d727208ac","8fd149dc328b84303aacfe08","aa3157c666858f7681bb4f77","959fbedca34708edbffbf5c2","86921a0e3ab6799a9df650a5","ffb41994cf9dd837591aa51e","168769f29da7e8db465165d8","1110d21b9ca4d4103b6ff68b","d474bd4c964bb22a8e34bbc8","05eaaf530fcdaa0134644dcd","6a4506c9bd0894369c662d44","c8f5c360485c80a6e7ff5efb","42b164af7b0d85b54a2c4119","e8f92860044f0032e0044b0e","2261a83023403eeb0b11c075","decddc0cdbe5100934d4d79e","c4209b14521e81e1e854e3f7","0a328a7ab547600525d24269","dbffea544ebb3eee4d44c25c","b11891d289976a91b41a1d9e","c8e79644284bf70d8c2abadf","766c9c272eb07c0bb7e926e7","3bbed98e218aa2fa23f8c5be","2b3048163dc641340dafbd5d","2113733ec424ee6f48d1a8b1","004ab52ce7c994bd991e073b","d1c5cbcf7bdb9e40daa51d60","272cf23895cb6f6c986e7998","52c3d87205db3c0d09791ab1","e9fd1f7fae6dd440370d452a","92c6fe058811f8d91a0fd4e2","867a251a306154a11c7bab26","efa5276663b24a0f3ec3d258","b15e4195145f5f8d5fb14938","2a7d356952a6b552f8e14293","729dc7f4fef909ae42067d8f","0096fe9c66f4b220329c5e9e","c6f5445ed45bc49944ae20f4","fc44f3b1ab13b8bff3c80cf9","68f595d54309ab5fb2835883"];

// --- sealed-crypto begin ---
const SEAL_ITERATIONS = 600000;
const sealEncoder = new TextEncoder();

function sealB64(bytes) {
  let text = '';
  for (const byte of new Uint8Array(bytes)) text += String.fromCharCode(byte);
  return btoa(text);
}

function sealUnB64(text) {
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

/** The password's key-encryption key for a lock's salt. */
async function sealPasswordKey(password, salt, iterations = SEAL_ITERATIONS) {
  const base = await crypto.subtle.importKey('raw', sealEncoder.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, base,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/** Opens a lock with a password: the content key (non-extractable), or null if the password is wrong. */
async function sealUnlock(lock, password) {
  const kek = await sealPasswordKey(password, sealUnB64(lock.salt), lock.iterations);
  try {
    const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: sealUnB64(lock.iv), additionalData: sealEncoder.encode('lbcb-lock') },
      kek, sealUnB64(lock.wrapped));
    return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
  } catch {
    return null;
  }
}

/** Decrypts one sealed file (IV followed by ciphertext) stored under `path`. */
async function sealOpen(contentKey, path, sealed) {
  const bytes = new Uint8Array(sealed);
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.slice(0, 12), additionalData: sealEncoder.encode(path) },
    contentKey, bytes.slice(12));
}
// --- sealed-crypto end ---

// --- sealed-keystore begin ---
/* The content key, kept in IndexedDB as a non-extractable CryptoKey (page and worker share it). */
function sealDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('lbcb-sealed', 1);
    request.onupgradeneeded = () => request.result.createObjectStore('keys');
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function sealKeyStore(mode, action) {
  const db = await sealDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('keys', mode);
    const request = action(tx.objectStore('keys'));
    tx.oncomplete = () => { db.close(); resolve(request.result); };
    tx.onerror = () => { db.close(); reject(tx.error); };
  });
}

async function sealKeyGet() {
  try { return (await sealKeyStore('readonly', (store) => store.get('content'))) ?? null; } catch { return null; }
}

function sealKeyPut(key) {
  return sealKeyStore('readwrite', (store) => store.put(key, 'content'));
}

function sealKeyClear() {
  return sealKeyStore('readwrite', (store) => store.delete('content')).catch(() => undefined);
}
// --- sealed-keystore end ---

const scopePath = new URL(self.registration.scope).pathname;
let indexCache = null;

async function cached(path) {
  const cache = await caches.open(CACHE);
  const url = new URL(path, self.registration.scope).href;
  const hit = await cache.match(url);
  if (hit) return hit;
  const response = await fetch(url, { cache: 'no-store' });
  if (response.ok) await cache.put(url, response.clone());
  return response;
}

async function sealedIndex(key) {
  if (indexCache && indexCache.key === key) return indexCache.index;
  const response = await cached('sealed/index.bin');
  const plain = await sealOpen(key, 'index', await response.arrayBuffer());
  const index = JSON.parse(new TextDecoder().decode(plain));
  indexCache = { key, index };
  return index;
}

async function gate() {
  return cached('gate.html');
}

async function serveSealed(path, request) {
  const key = await sealKeyGet();
  const navigate = request.mode === 'navigate';
  if (!key) return navigate ? gate() : new Response('Locked', { status: 401 });
  let index;
  try {
    index = await sealedIndex(key);
  } catch {
    // The stored key belongs to another password: forget it and ask again.
    await sealKeyClear();
    return navigate ? gate() : new Response('Locked', { status: 401 });
  }
  let entry = index.files[path];
  if (!entry && navigate) {
    path = 'index.html';
    entry = index.files[path];
  }
  if (!entry) return fetch(request);
  const sealed = await cached(`sealed/${entry.id}.bin`);
  const body = await sealOpen(key, path, await sealed.arrayBuffer());
  return new Response(body, { headers: { 'Content-Type': entry.type, 'Cache-Control': 'no-store' } });
}

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll([
    ...[...PUBLIC].filter((path) => path !== 'sw.js'),
    'sealed/index.bin',
    ...SEALED_IDS.map((id) => `sealed/${id}.bin`),
  ])));
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    for (const name of await caches.keys()) {
      const ours = name.startsWith(`lbcb-sealed-${SITE}-`) || (SITE === 'playtest' && LEGACY_CACHE.test(name));
      if (ours && name !== CACHE) await caches.delete(name);
    }
    await self.clients.claim();
  })());
});

self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') self.skipWaiting();
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || url.origin !== self.location.origin || !url.pathname.startsWith(scopePath)) return;
  const path = decodeURIComponent(url.pathname.slice(scopePath.length));
  if (PUBLIC.has(path) || path.startsWith('sealed/')) {
    event.respondWith(cached(path));
    return;
  }
  event.respondWith(serveSealed(path === '' ? 'index.html' : path, event.request));
});
