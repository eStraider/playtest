/*
 * Sealed playtest build: the service worker. Every game file on this site is
 * encrypted; a phone that has entered the password keeps the content key in
 * IndexedDB (non-extractable), and this worker decrypts each file as the game
 * asks for it. Without the key, navigations get the password page and
 * everything else is refused. Updates follow the app's native lifecycle: a new
 * worker waits until the old app is closed.
 */
const BUILD = '20261025145602-7dba04';
// Sites on the same github.io origin share the cache storage: each keeps its own.
const SITE = 'playtest';
const CACHE = `lbcb-sealed-${SITE}-${BUILD}`;
// Caches from before per-site names ("lbcb-sealed-<build>") belong to the first site, playtest.
const LEGACY_CACHE = /^lbcb-sealed-\d{14}-[0-9a-f]{6}$/;
const PUBLIC = new Set(["gate.html","lock.json","robots.txt","icons/icon-192.png","icons/icon-512.png","icons/maskable-512.png","manifest.webmanifest"]);
const SEALED_IDS = ["e562bd53c9bc8c7b63f9e1f9","3d4bdb6c6ffe6ba2cd86c5e6","c9d2545b7c0fbb734830eabd","0e9ae95179c8796b4016b0c9","3eec567790b86e352b0a5e3a","20ab51f28eabfb7e94b8bc9a","67f9ca66fcbdafcae91218e1","569e3bb0a1e438ad22e72e22","541c6f887745fdaacf0c110a","d212e212b895a9da56438d6d","585491a8c36431c2bb4f2210","ff48b4d54b2becffd8f1fb69","7a84235179fb5106e2cdef35","6af06a961fcfda7d7e145142","b393c61cfb0d14105d044b4f","0b8edeb56b43b270b0ed5637","56c4429117b7bd5cc6e162f4","40fa22fe13398c4f7746a0ee","2d5a07614399a2952adf75b6","657bf813bc9a87f4a06cdba6","b11b3d3b3c6bcc4a77f2c0dc","be26162edf6e35421db7beda","87d12193579ed66008aba8b5","3a9e96d9fdd4c4966d470f80","cb0d82a415faa826fd34ae9e","5340cf3a14c1af27b575cccd","a6f57908e3fcd4263f509597","d3119868d1f6d7f5567c78a4","1d290bb38614b7b08b8ad29a","de8efcb9471a8523870acecc","b84c2ed0d4e61f632ffbd39d","e6b7b2566a4663fbe53f8abc","0ec5593e6aaea7d17380a632","d995ecb292c7b6bb850b2ea7","d858088fd9ea5490d1791a1a","a200564d59b50651a19b47c7","1a7e372f2eaa270ec69f3e84","3c6601c3c83746a3efb9a846","e918fe7e51971ca1de6a9257","8d460fb24ff5d961e83552fc","1bee4b7bd8063b09d1084c61","de5a16e47af6f1aa4425ed65","3ab33b07d667d9069cb9a1fe","57b935ebd1de77042dd1ebc5","470f792b0ae1bc97e7f5fc9f","29daa7999b929c7d86612cac","ee0333e9289ceb06dd3c1285","fd8929766a9039d14723ffef","509a972c6a636521f96b76d2","ecd09203ce727e6c079d9aae","14c2fbfa0aa8ed90088ff194","8ed6ce9d2107d46fda6142fb","fba61b25ff932d0377642202","c19ad100bc38b3391d50ab77","d0ff0177bbed64e6fb0efe68","6f1ee7b32545c9eb37b66e1e","e801990a06c3184760dfe6e1","960db00beb0051e58c380017","925f18605d1eb38ca069c092","04a97ef187f71c49be84ec6b","4ea74d59bdeb046adb8cae92","dc9bc2887d5328567f657555","a37c68daa161c7775c31f05a","dbffc8763a2d0529bac125eb","d684671458eed818fb0c5177","092dcea75f893582967cf39b","0be57c5c557b88103f607061","6c46a2c8acbadb34d1e4b7d2","fb4a2cfec3943b1a68ba893a","94ce57454bb9dfee6ba190fb","2ebb2033d607b7d0c7590f67","18a6b321a771559de1c9e412","62584ffeb8faf29a3cbc76c0","13f4a7f96bd7535135e0c624","3c6f1ca9515f2e359821c791","8cd9ee7c722e0ea7d93cd5e7","5ed536e0db4c272e6305ccb7","8b8863cdc3078af98dfbc6b7","9a333274024a093d008c5b08","bcc695c6f71aa0956366af1f","e79b4c9775ae3fdec4d6278a","a5b1c04720785cd6f6c94e25","9a69a2a008c5105501c09d54","cc243c8411e02c3f27f8881f","eafe73f869efde9119da4aac","f6ae3555cb197efe3d700e93","ab4f910b25ca2bbac1678ca5","86c5970243d77f5676f8f841","bd729a9293573a31e43f6d29","dbcfb2173b2a031d153367fe","b910c38c1b2f790a14c3b6a0","8952031510f8466528e8d002","d81d41f4b26e258bca7a6a38","b7d93635b7c9f35970dda41f","8ca53c722543e4a88798a804","16532a416494444b390a9bb4","da60544ed15c3008d8e6b74c","f6d41d9a35dcbedaa68622c5","b42be31a90196bdfda78e464"];

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
