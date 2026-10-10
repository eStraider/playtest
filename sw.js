/*
 * Sealed playtest build: the service worker. Every game file on this site is
 * encrypted; a phone that has entered the password keeps the content key in
 * IndexedDB (non-extractable), and this worker decrypts each file as the game
 * asks for it. Without the key, navigations get the password page and
 * everything else is refused. Updates follow the app's native lifecycle: a new
 * worker waits until the old app is closed.
 */
const BUILD = '20261010155702-d4be94';
const CACHE = `lbcb-sealed-${BUILD}`;
const PUBLIC = new Set(["gate.html","lock.json","robots.txt","icons/icon-192.png","icons/icon-512.png","icons/maskable-512.png","manifest.webmanifest"]);
const SEALED_IDS = ["512aa01273c9bd583640ed71","64a19ce95aa19f4669935b36","1c660407584a1dc4712361f1","004f1e92b6983df89a25093c","9fcb951c4e0b677597f01a3d","6d021846eab53980b8a264c3","d4b91eb5a20cb929f90e06a0","e861ab8938f083089fe6b53f","22f7417a0b20b251e41f1732","c2cde15979c084ddd3e2e68d","66571e10e57bf7223397e2ec","d42f42e486384bc3cb9b4dfc","234d95c7bbf3136f4397a3ce","579177fa6baf4e6df0762886","d349567387a049240c3585eb","8af511da7bf2216b41ed91c4","a13379be16e10659e63054cd","2bfe990077272ca950c6a8e8","86286bacd4da57e2ed4a24ef","dd915c18f82a45ff8c8df403","e7d1660d8caa7eb0e3a9fbcd","6c17ec7863f325cd0da944bb","91f7912a2b24893cb585938b","8776caf91792a41834e1ab5f","c634e7ffad843af5ee1727ea","44a1663381fb878f9b7db408","9e36a9d2f1a9b338a05681ad","728da6887b84cee260afc5c6","b8f3847343b2ff96df643316","ca09f3bb67dba201fd781886","4f7ab9fe5bb62c751b75ae92","23d729ba60d63f73c0ae054f","99d373e840d7a4d680678e99","400c54c47db2e360ddd7f9b2","f61edb400359edfbf895ccc9","780b50f6f012def0acf92d08","e23d721994819f0d18008edd","d2457409f4d990358adb6a0e","969eaa1773271b85d79ee629","e9494f7b44405db5292c1fb4","29862b40e96c41f10827f261","cbc33820ef04f2a33b5193f7","b5298692b469ab1ef8628f7a","b46fd4ac0ee804e088c22c6e","465b2121e8c3b724f188fe16","ec2d95ec9aa94d07f7d029b1","4c7ff29760cc91789517b210","6b9bb195abb064517e5e5c77","840ae27f9f0aee42c09103c8","ebe3e5ff7cbb1938b9ec6b6e","2f7cedecf0c135ae0d2139fc","fca756ee1dbad14ddff1e380","1514bbe22b6f6bb2b39d5407","ebf7b872921b83139dec232a","cdc1d8558b0fb153bada5628","863ddf3f28bcc9df7164cacc","704da6047e3da53ea7d93ff8","ecfa1dce4e3040b401da273e","461e4383eb5aff77021c70c6","15df572a9db154d173ffcbb0","d3cd322784d930c582c81529","a9ecf350e4b5147f21cee195","e28eb06be67713ab98dfecaa","47e44fbbf77b7a51f106a11d","7cc215457f6191fd9d9abd65","ce94f74aefbf52ced3e8f3d4","01f0404bcf4d3c2b375b6673","9bd2dbff48b6177278736be6","83d29a7ec6b482f806eff38d","4a4b5d6167178051ab1c6b7a","7eb9b937ca594eaeba90c7ea","2a39c1b5f43e940b489bda2b","b3407cfd771776204aaf21a8","fc001ae80bbdec45500c6831","e1e9904d7f9bea0bd9d20a72","7d21d402fc6702f97b1002d1","aca2b0631cb449cfb8e963df","1240a77f2ece97706f330c3f","0e0903a3e6bb18fb0a86b235","cafa2dfdef478312e2ebc634","3ebba3269f26386a7cac5b8d","a41082df8df04904ee02ce88","567ada4561b0b0517a572df8","cd3192111cd16e6f11ac55b8"];

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
