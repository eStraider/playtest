/*
 * Sealed playtest build: the service worker. Every game file on this site is
 * encrypted; a phone that has entered the password keeps the content key in
 * IndexedDB (non-extractable), and this worker decrypts each file as the game
 * asks for it. Without the key, navigations get the password page and
 * everything else is refused. Updates follow the app's native lifecycle: a new
 * worker waits until the old app is closed.
 */
const BUILD = '20261003123853-2d1166';
const CACHE = `lbcb-sealed-${BUILD}`;
const PUBLIC = new Set(["gate.html","lock.json","robots.txt","icons/icon-192.png","icons/icon-512.png","icons/maskable-512.png","manifest.webmanifest"]);
const SEALED_IDS = ["410c257abbea97e1315b0294","648a4126f96dadb2869da9a0","e0bb947d38ed06cacb1c4a23","abcde6239a6c2d7e88ec98e1","b3de73bf74c78d8af8f35c71","67201bcd03a7c7e09e1f5b73","00ffc2e119d921f8180fc936","8f1c1b74af180f8e8b68b6b7","a84b359ec1f9c045f59082b1","a589fa0a9bf2351bbbffacdd","5d27e645d8a07ae72bc6a3b1","6d8c7ad83e6f6b232e222a3a","5ee017fc36de0fd62ca0aab0","3fc8c9a51c6a309c3909fe73","7303119d494281bfd740ff69","155e12b899f771fc2b3ce8cb","2e203cfbc5633b7b9f52d5c3","db63d6a6a5cee5510c998d51","b06afad0a977d0fa4d37bf97","dd45bc3a6f6e7d9d3276f419","2de5b672f44a550961e1a6a8","66f3658ea470ebad01adbcae","020742d9170fe516ad0c5943","8904a224089c87b12aa64f50","813a1c5a41178c8dd63c36ac","64017daa907039bd98335d53","527429debc550d6ef9cadeec","ead970125d2ccbdcc41a5cdc","6a3b59da40a4e210277d50ce","b3b109d0a98c930fdc0839e2","34d29c2a08c379b22e81a43c","67b9cbaae3118d12f789f967","5d50c6681e3d9d33947b1de3","bfd604cec1d2b270ae65e77f","0c3d165346e123014ee00347","bc81180c459b3a13cbf98617","bb83637aabe28bc28cb79f6e","7c4377faff8ea7c8b785b196","49120d5e3efc99ebdcb8b3a8","9fd0c3cf44342ab76bec1059","b6650c105b50654a8aa6ba7d","e69758699ca0dd442b22493d","8dd27aac474ea12a1ac22077","c09aafa1dcfa187729cbff77","7c938ff368837485ad4136ca","07bb536ac46aa776cb943e7a","3a9faaeff9fe709415a62593","d4924f6d6afbba8cff652869","103aba77fc8f2280c2ab5ecc","cb698f1cd12f4e8eb6270c21","196e2e70fffc2e89b6cd5873","5b6354784605df7f3a1e1537","f24de59b55475635f42eea98","0fe2db864c71a6d7fe58f3de","b1c0229937e7bdbba59b4892","409bfa3a6bbb1ad7667f693b","09a4dde81ee5d8cf0d522f8d","ae970e49050acacdedde8011","a28eea4c2003e53b2049329b","59a88ab70c242696b7224bf6","b4d39beef29a8d1298d33fc2","526d0e6041a0636305e50f94","4b6ec8d02000c3da9e9210d4","8550b1bfee2be45af049b03a","9c2744968520f0581ac3c4b2","c75207f3c1a16cbc31d6005d","cb4d969a2720d942d3f6cf2c","80739ed4d531ac714f13716e","04fc83072979a0401ea5c076","ce48af6992a47b72fd50025f","626ca4014df40df6958ebdb9","27d91c2f4fd17323caedd704","c27a0e19f4034b533b33baa2","4a74cc8e6bc35d21fdd41fab","68b0f1c1f10c9d740dcb12d9","e6df224a0de45c3b4a4bef38","e991c47eb0bc2c7aa258e063","0aed4457840482379eba3d5f","cfa466d6469129ad002b09af","a35d9b472d99e31d5aca82ac","aeef4c8947c9ff5d76ba79dd"];

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
    for (const name of await caches.keys()) if (name.startsWith('lbcb-sealed-') && name !== CACHE) await caches.delete(name);
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
