// src/utils/cryptoSigning.js

const DB_NAME = 'upce-crypto-store';
const STORE_NAME = 'keys';

// Simple wrapper for IndexedDB to store the non-extractable CryptoKey
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

// Generate RSA-PSS 2048-bit key pair
export async function generateSigningKeyPair(userId) {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-PSS",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    false, // Private key MUST NOT be extractable
    ["sign", "verify"]
  );

  // Store the private key in IndexedDB linked to the user
  await saveKey(`signing_private_${userId}`, keyPair.privateKey);

  // Export the public key as SPKI (SubjectPublicKeyInfo) format
  const exportedPublic = await window.crypto.subtle.exportKey(
    "spki",
    keyPair.publicKey
  );

  const publicSpkiBase64 = arrayBufferToBase64(exportedPublic);
  const fingerprint = await calculateFingerprint(exportedPublic);

  // Store the public key in IndexedDB for easy access
  await saveKey(`signing_public_${userId}`, keyPair.publicKey);

  return {
    publicSpkiBase64,
    fingerprint
  };
}

// Convert ArrayBuffer to Base64
export function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

// Convert Base64 to ArrayBuffer
export function base64ToArrayBuffer(base64) {
  const binary_string = window.atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
}

// Calculate SHA-256 fingerprint of the SPKI DER public key
export async function calculateFingerprint(spkiBuffer) {
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', spkiBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Sign a challenge (for Proof of Possession)
export async function signChallenge(userId, nonce) {
  const privateKey = await loadKey(`signing_private_${userId}`);
  if (!privateKey) {
    throw new Error('Signing private key not found on this device');
  }

  const encoder = new TextEncoder();
  const data = encoder.encode(nonce);

  const signatureBuffer = await window.crypto.subtle.sign(
    {
      name: "RSA-PSS",
      saltLength: 32, // SHA-256 digest length
    },
    privateKey,
    data
  );

  return arrayBufferToBase64(signatureBuffer);
}

// Calculate SHA-256 of a File (streaming for large files)
export async function calculateFileHash(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const buffer = e.target.result;
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', buffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        resolve(hashHex);
      } catch (err) {
        reject(err);
      }
    };
    reader.onerror = (e) => reject(e);
    reader.readAsArrayBuffer(file);
  });
}

// Create Canonical Transfer Payload
export function createCanonicalTransferPayload(
  transferId,
  senderId,
  receiverId,
  fileSha256,
  fileSize,
  issuedAt,
  nonce
) {
  // Ensure strict formatting
  return `UPCE-TRANSFER-SIGNATURE-V1\n` +
    `transfer_id=${transferId}\n` +
    `sender_id=${senderId}\n` +
    `receiver_id=${receiverId}\n` +
    `file_sha256=${fileSha256}\n` +
    `file_size=${fileSize}\n` +
    `issued_at=${issuedAt}\n` +
    `nonce=${nonce}`;
}

// Sign Transfer Payload
export async function signTransferPayload(userId, payloadStr) {
  const privateKey = await loadKey(`signing_private_${userId}`);
  if (!privateKey) {
    throw new Error('Signing private key not found on this device');
  }

  const encoder = new TextEncoder();
  const data = encoder.encode(payloadStr);

  const signatureBuffer = await window.crypto.subtle.sign(
    {
      name: "RSA-PSS",
      saltLength: 32,
    },
    privateKey,
    data
  );

  return arrayBufferToBase64(signatureBuffer);
}

export async function hasSigningKey(userId) {
  const privateKey = await loadKey(`signing_private_${userId}`);
  return !!privateKey;
}
