// frontend/src/security/e2ee/cryptoWorker.js

self.onmessage = async (e) => {
  const { type, payload, id } = e.data;

  try {
    switch (type) {
      case 'ENCRYPT_CHUNK':
        const encrypted = await encryptChunk(payload.aesKeyBuffer, payload.iv, payload.chunk, payload.aad);
        self.postMessage({ id, result: encrypted, type: 'SUCCESS' }, [encrypted]);
        break;
      case 'DECRYPT_CHUNK':
        const decrypted = await decryptChunk(payload.aesKeyBuffer, payload.iv, payload.encryptedChunk, payload.aad);
        self.postMessage({ id, result: decrypted, type: 'SUCCESS' }, [decrypted]);
        break;
      case 'DERIVE_KEK_AND_WRAP':
        const wrapResult = await deriveKekAndWrap(
          payload.receiverPublicKeyPem,
          payload.transferId,
          payload.senderId,
          payload.receiverId
        );
        self.postMessage({ id, result: wrapResult, type: 'SUCCESS' });
        break;
      default:
        throw new Error('Unknown operation type');
    }
  } catch (error) {
    self.postMessage({ id, error: error.message, type: 'ERROR' });
  }
};

async function encryptChunk(aesKeyBuffer, iv, chunk, aad) {
  const key = await self.crypto.subtle.importKey(
    "raw",
    aesKeyBuffer,
    "AES-GCM",
    false,
    ["encrypt"]
  );

  const algorithm = {
    name: "AES-GCM",
    iv: new Uint8Array(iv),
    additionalData: aad ? new Uint8Array(aad) : undefined
  };

  const encrypted = await self.crypto.subtle.encrypt(algorithm, key, chunk);
  return encrypted;
}

async function decryptChunk(aesKeyBuffer, iv, encryptedChunk, aad) {
  const key = await self.crypto.subtle.importKey(
    "raw",
    aesKeyBuffer,
    "AES-GCM",
    false,
    ["decrypt"]
  );

  const algorithm = {
    name: "AES-GCM",
    iv: new Uint8Array(iv),
    additionalData: aad ? new Uint8Array(aad) : undefined
  };

  const decrypted = await self.crypto.subtle.decrypt(algorithm, key, encryptedChunk);
  return decrypted;
}

// Convert PEM to ArrayBuffer (SPKI format)
function pemToSpki(pem) {
  const b64 = pem.replace(/(-----(BEGIN|END) PUBLIC KEY-----|\n|\r)/g, '');
  const binary_string = self.atob(b64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
}

function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return self.btoa(binary);
}

// Generates an ephemeral ECDH key, derives KEK via HKDF, and wraps a new random AES-256 key
async function deriveKekAndWrap(receiverPublicKeyPem, transferId, senderId, receiverId) {
  // 1. Generate Ephemeral ECDH pair
  const ephemeralPair = await self.crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true, // Must extract public key
    ["deriveBits"]
  );

  // 2. Import receiver public key
  const receiverSpki = pemToSpki(receiverPublicKeyPem);
  const receiverPublicKey = await self.crypto.subtle.importKey(
    "spki",
    receiverSpki,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );

  // 3. Derive shared secret bits
  const sharedSecretBits = await self.crypto.subtle.deriveBits(
    { name: "ECDH", public: receiverPublicKey },
    ephemeralPair.privateKey,
    256
  );

  // 4. HKDF derivation
  // Replicating Python logic:
  // salt = sha256(f"UPCE-V1|{transfer_id}|{sender_id}|{receiver_id}|{sha256(ephemeral_public_pem)}")
  
  const ephemeralPublicSpki = await self.crypto.subtle.exportKey("spki", ephemeralPair.publicKey);
  const b64 = arrayBufferToBase64(ephemeralPublicSpki);
  let ephemeralPublicPem = '-----BEGIN PUBLIC KEY-----\n';
  for (let i = 0; i < b64.length; i += 64) {
    ephemeralPublicPem += b64.slice(i, i + 64) + '\n';
  }
  ephemeralPublicPem += '-----END PUBLIC KEY-----\n';

  const encoder = new TextEncoder();
  const pemHashBuffer = await self.crypto.subtle.digest("SHA-256", encoder.encode(ephemeralPublicPem));
  const pemHashArray = Array.from(new Uint8Array(pemHashBuffer));
  const pemHashHex = pemHashArray.map(b => b.toString(16).padStart(2, '0')).join('');

  const saltInputStr = `UPCE-V1|${transferId}|${senderId}|${receiverId}|${pemHashHex}`;
  const salt = await self.crypto.subtle.digest("SHA-256", encoder.encode(saltInputStr));

  // Import shared secret as HKDF material
  const hkdfMaterial = await self.crypto.subtle.importKey(
    "raw",
    sharedSecretBits,
    { name: "HKDF" },
    false,
    ["deriveKey"]
  );

  const kek = await self.crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(salt),
      info: encoder.encode("PFCE-FILE-KEK-v1")
    },
    hkdfMaterial,
    { name: "AES-GCM", length: 256 },
    false, // extractable
    ["encrypt"]
  );

  // 5. Generate random AES file key
  const aesKeyRaw = new Uint8Array(32);
  self.crypto.getRandomValues(aesKeyRaw);

  // 6. Wrap the AES key
  const wrapNonce = new Uint8Array(12);
  self.crypto.getRandomValues(wrapNonce);

  const wrappedKeyBuffer = await self.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: wrapNonce },
    kek,
    aesKeyRaw
  );

  return {
    ephemeralPublicKeyPem: ephemeralPublicPem,
    wrappedKeyBase64: arrayBufferToBase64(wrappedKeyBuffer),
    wrapNonceBase64: arrayBufferToBase64(wrapNonce),
    aesKeyRaw: aesKeyRaw.buffer
  };
}
