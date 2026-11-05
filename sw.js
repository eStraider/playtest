/*
 * Sealed playtest build: the service worker. Every game file on this site is
 * encrypted; a phone that has entered the password keeps the content key in
 * IndexedDB (non-extractable), and this worker decrypts each file as the game
 * asks for it. Without the key, navigations get the password page and
 * everything else is refused. Updates follow the app's native lifecycle: a new
 * worker waits until the old app is closed.
 */
const BUILD = '20261105012146-b11456';
// Sites on the same github.io origin share the cache storage: each keeps its own.
const SITE = 'playtest';
const CACHE = `lbcb-sealed-${SITE}-${BUILD}`;
// Caches from before per-site names ("lbcb-sealed-<build>") belong to the first site, playtest.
const LEGACY_CACHE = /^lbcb-sealed-\d{14}-[0-9a-f]{6}$/;
const PUBLIC = new Set(["gate.html","lock.json","robots.txt","icons/icon-192.png","icons/icon-512.png","icons/maskable-512.png","manifest.webmanifest"]);
const SEALED_IDS = ["7f76cf23d825ec9f52b9a41e","857bc21bd3a3137971bc9b24","dc6a801f560cffeed419065a","46062576e58ffdd8882638ea","b4b8aa511c4358772d54a22b","15eb7f682e59eb48e2948db9","6526f029e6c129feea613e77","06152a843bf6fa07983b5a20","dabd42ef5a227e059a60449f","1e11db77489a1c3ca411e39b","6e35be7077ecdaa5cf132785","181896b88922016cd62a7cbf","c44d408a5ebe317d01bb4ea1","ec37eec83d7a3ec90d03ec54","01e6df21741bbb5d7bbb7dc7","f63a021dcbf591c0830b8802","70479e241a3083260b7fad59","9b723d517f537cad879969d7","67ccd1c21cb6e607032abde4","18b88473bdec992df5951cdc","40f3c8ace576232142356a80","ff4a81d8a8ad5f523e1d925a","502639c97bacb6e353c61084","2a96e81cdb3c910db9e594ea","88b0ad9aa5afef433a09d982","551f2c2e1a361920175589d4","5fa668f87c0f5047778b6ae4","20239584e199dac87c2f73a1","17bed91f9635d1698a0a3e13","bde60c5c6905e3693023ad3a","77c7950b94f5ad1bf0ad7818","f19405668dd6d2d81de35f5c","2f14faf5df26550f870dda90","5584f6a49ce33cd09e566838","5fc338851ba8b8617af82c89","711fc8b6ae0e21900f5d92af","a98432386f4071d4dd2cc034","7f892be2d4aa7e3dff746a95","45196b8a3b4e8ecdc62b9bc2","50aba40d67ddfccf55736381","a28f6ae15a2cbcf65395bccf","e2b8be944cfbc964b43729f6","7f5e98352225e2ed84db6b5d","00df52ffe32c501c046acbca","b298cbaa7253b8256167e249","9147638e359e3111a0785dda","66322d8010f9cf0395ea11fd","c00ed9f307d12900335a3153","9d228dd6edc5e46f4ebd4c99","0b82c8d1d4507da1fec6a3b3","a5aa13ee58cb57c4fe6efdf2","7e28539c613056bdcea2d9cc","5d26947e7c0cd30cee7bd5d5","c5ca1b8dd2107a58a9895914","26d4a803902845512862d67d","0d441c53382d5e6dd490c255","5cd5f9c3092bcc2fd6b1ea55","ae14054d68d3bc07eec93986","efdeb6f4f9da855d35301a7c","bd73e94fa294707829b1a77f","a37b738e08f3d9dd0b1f352b","85c34e27c968d607c7392961","4af892ed2a48a4d3a367b9af","1ecc911a4ae987152d87f2df","a702bac26090a2c79555d8b0","4ea0a8fecb764ea45ddb31a7","ac85b0010e351937082b518b","5d7e074dc4b226062e4487aa","18077a70e1012e64b21c9083","56b4e043907b9ec8ac223146","b3bd4afd247e111079b6d3fb","36a671367d792c198a37b267","e223271ac2d85bfd10911e8a","60b6c6d44f0dc5c2964cdcc2","2c021aa2e52a1336576c48cd","497eebe9960bb5477ee352c9","a40c3857b9988eb6b84440ac","922a7ed1b98ef47186eca5ee","37e6c55641c04411a55424ab","c1d6e8378d4e525f6ff302bc","8736f10a716ebc870d820bc0","9a6fc0cd3aac47306b895986","0ea418247d4bf59d7d5a5f22","6666c36d70aceba2c13faffc","f43c353df83e5a4fa1083756","40f8bf63abef9dbe97b09c71","06bafce9973c523221c75bd5","414f19ad0892c0d1c03a29bb","d98ef6b4c44c192474a5f8f2","6f43b384afd18374779d3e41","0d4675ca9920bbd806f4951a","318e0ea2cd8a996e3b4e415f","8f7c33f52d0c1b43d3595a92","7081113a1722eaca137f8bdb","0e62f8a7f5bb83f234caf89b","be9104fdd7f8a0286befee95","068d1e0a8bbc31c7554469c9","54e909595c5bddd9592ad677","d11c169bd275ae42793c26da"];

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
