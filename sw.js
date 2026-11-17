/*
 * Sealed playtest build: the service worker. Every game file on this site is
 * encrypted; a phone that has entered the password keeps the content key in
 * IndexedDB (non-extractable), and this worker decrypts each file as the game
 * asks for it. Without the key, navigations get the password page and
 * everything else is refused. Updates follow the app's native lifecycle: a new
 * worker waits until the old app is closed.
 */
const BUILD = '20261117163822-4fb042';
// Sites on the same github.io origin share the cache storage: each keeps its own.
const SITE = 'playtest';
const CACHE = `lbcb-sealed-${SITE}-${BUILD}`;
// Caches from before per-site names ("lbcb-sealed-<build>") belong to the first site, playtest.
const LEGACY_CACHE = /^lbcb-sealed-\d{14}-[0-9a-f]{6}$/;
const PUBLIC = new Set(["gate.html","lock.json","robots.txt","icons/icon-192.png","icons/icon-512.png","icons/maskable-512.png","manifest.webmanifest"]);
const SEALED_IDS = ["93d471d1612866624ba9d03e","ad72c1408b70ab0318f9b7e3","7612347ffdd15ae9818d9c24","4901fa3e5bad0a59598a84f5","f6bd5b3e8f8ae51273d26f30","afd45ebd83e2ec87862e0872","2dc7f0ac81b119f9d0aaa999","05f7df8b882993093b39f8ce","3f54d8c34970f8b28a3233d8","800f3c0aa7fd783bbdabcdc0","6d36e5ebd7798ca0fa5982ad","b78fb2a66d1f2526083af6d4","7237bee9b670732c6c0df707","6037eafffd1543e1847996a1","c1e7780319b33f0072479223","bf671e54665041ebf80c85a2","3066ee195f45da3c924a686e","fad7029d60841c653fa489c7","52683bee78c43fd5cb62a8db","7df9ddc28d615a46b8da57e1","dcdd577149f6f69e50564404","5cf8917b5c83d84207f4149c","a9a6e4bec1751541229a50b2","a8c9d541c1dee56e8d46d566","a376b2f037fec97a3530f8fd","b4a24ef0eb06bd9a9d5dc30d","06350c9d55c6df458327aa7a","47a9320d0c3022b8c2e02303","57e3b7256554502442297dc7","48f486c26f17d761486fc104","20715a6076ebda9f11d60a77","2c5fe3f0f794e7a98e7ae66a","14d63d18068e5e498e717ba3","2a2cf2f401fdbdb09af82d1c","a44fab259e4f06dbb1c0f75e","8b065a88e00acfc0a00ca914","85ddc0e2df483489a6cc8826","4fdf26f233c939d1ea5416ad","e2dfdab957548dff1cd3f457","3b5217c69a82674372a28925","05e9d5c935fc3525ea079f1e","111acd78da90cfaa312bee6a","456b42c810609b00dd1c48fe","3f5f7eeb9400f6b75baf3c2b","5e0115a31a3477bc63efe24a","996a8adfb7c1c0c57a4c2b2b","1ead04977d5c08dc44b0ca83","8db2f0afd20975ed0654d711","8c6577f5291da974c91918d7","437cea209ea200f79295a125","2b103d3d5e341fb26969f8f4","f65b144c7ade3939e0df2ea8","6fc7217ec45790d395946fa1","648e8a0dded69fbfb723bfcb","4e21d71f004c546baa4a58d5","139688c89eab95c56f5f1d24","362c77a9f92867e3e4ef2f9e","83999b10ff11d6feefc89d9a","a666cc53c7b17870fc3e1731","aef699f517afc5b86378a424","1e765f76d1784a998af51a07","4bacf71d82cf0189d5fa52bc","1a82a2fc90695610f06f883b","0ad15fa5bb088f08270eef9c","58797d3b078fbf549171e03a","88015445d006269daf32cc21","48c64d2272626b95993ed310","ce88595807a14120c209ef8d","f3b6f20979daaffbfe7df9ac","3062a4c3d1f1a2fe7d048834","7c304f1797714ed101ebf105","efaf43cf53fd1c1ebbb3ed17","f9d6c908b3e28cbb891bc738","e5f23a943f198d8e2fa3e1cc","aef12d70bc184c6c9a3b781d","906f645619c73b92cdff1fe1","bea0a0eb0283c86ef942e6f5","0b0325010c4f05891bf34f87","ba4be331adb3472ad3ac9f18","9dce7d2bb11cd2a0ae1ee6f1","a133bd20bf10fbb05d199738","7cac76fc74a1fe5526875d8d","8e1ffb5da9f3ce876515d3d7","34f1c3f11220001616ab6c38","10f69f15221967bdc617fb91","5671631a1bdf9ae5e739f4ab","c298784856101eafd4cce1ee","d9cbf1bdb0a5db66598ef127","c9c5e9978e1c0d077f39442f","dedb625c53767da7b1e28da0","5c6992324eaed976fc49f10e","f0da2ee1e4ce4a4f24e70a6c","9ad786a423035b1469acbed5","4ff84a65a552b89cf0ac720f","752f33cb5808d51862b0a6cf","74b5d279cbac0c109183f381","78e73ad5f49e97fd65f2a710","0cca651ce150d7fa110d6ffd","cabacb6daa5de1b8b5a81b0e","965a5bf7121b765a86ff2e2a","4471b3fced487f47b0a86798","8c69d947cf3db5d3c6af2428","694ac1489aaef654016c0dfc","d5ab854b46ace85104ecaa6a","c3ae905863f37faa70dafdea","3a5585bee70a6582f9e8de53","c136bba435addfb6510732f4","391f2f664a516bd209453347","4db72629602c0775d9cc912e"];

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
