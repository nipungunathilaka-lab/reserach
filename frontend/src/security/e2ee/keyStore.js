// frontend/src/security/e2ee/keyStore.js
import { arrayBufferToBase64, base64ToArrayBuffer } from '../../utils/cryptoSigning';

const DB_NAME = 'upce-crypto-store';
const STORE_NAME = 'keys';

function openDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function saveKey(id, keyData) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, 'readwrite');
    const store = transaction.objectStore(STORE_NAME);
    const request = store.put(keyData, id);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

async function loadKey(id) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, 'readonly');
    const store = transaction.objectStore(STORE_NAME);
    const request = store.get(id);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

export async function deleteKey(id) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, 'readwrite');
    const store = transaction.objectStore(STORE_NAME);
    const request = store.delete(id);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

// Convert spki DER to PEM format (for backend compatibility)
export function spkiToPem(spkiBuffer) {
  const b64 = arrayBufferToBase64(spkiBuffer);
  let pem = '-----BEGIN PUBLIC KEY-----\n';
  for (let i = 0; i < b64.length; i += 64) {
    pem += b64.slice(i, i + 64) + '\n';
  }
  pem += '-----END PUBLIC KEY-----\n';
  return pem;
}

// Convert PEM to spki DER buffer
export function pemToSpki(pem) {
  const b64 = pem.replace(/(-----(BEGIN|END) PUBLIC KEY-----|\n|\r)/g, '');
  return base64ToArrayBuffer(b64);
}

// Generate an ECDH Prekey (P-256)
export async function generateECDHPrekey(userId) {
  const prekeyId = crypto.randomUUID();
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "ECDH",
      namedCurve: "P-256",
    },
    false, // Private key MUST NOT be extractable
    ["deriveKey", "deriveBits"]
  );

  // Store the private key in IndexedDB
  await saveKey(`ecdh_private_${userId}_${prekeyId}`, keyPair.privateKey);

  // Export public key to SPKI
  const exportedPublic = await window.crypto.subtle.exportKey(
    "spki",
    keyPair.publicKey
  );
  
  const publicPem = spkiToPem(exportedPublic);

  return {
    prekeyId,
    publicPem
  };
}

export async function getECDHPrivateKey(userId, prekeyId) {
  return await loadKey(`ecdh_private_${userId}_${prekeyId}`);
}

// Generate multiple prekeys and return their public components
export async function generatePrekeysBatch(userId, count = 10) {
  const prekeys = [];
  for (let i = 0; i < count; i++) {
    const prekey = await generateECDHPrekey(userId);
    prekeys.push(prekey);
  }
  return prekeys;
}
