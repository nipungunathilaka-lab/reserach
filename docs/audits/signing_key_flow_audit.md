# Signing Key Flow Audit

**Date:** 2026-09-18
**Project:** AI Secure File Transfer System

## Phase 1 — Audit Current Signing Implementation

### Component Analysis

**Frontend (`cryptoSigning.js`, `keyStore.js`, `SigningSetup.jsx`, `SendFile.jsx`)**
- `cryptoSigning.js` generated RSA-PSS keys and stored the non-extractable private key in IndexedDB (`upce-crypto-store`, `keys` store).
- `SigningSetup.jsx` checked status using `api.get('/crypto/key-status')` (backend) and `hasSigningKey(user.id)` (frontend IndexedDB).
- `SendFile.jsx` generated the `canonicalPayload` and signed it by calling `signTransferPayload`. However, it did not strictly prevent the user from clicking the upload button without a valid key (it would simply throw an error during the process).

**Backend-Node (`fileController.js`, `cryptoController.js`)**
- `cryptoController.js` correctly handled the proof-of-possession challenge for registering a key.
- `fileController.js` processed file uploads. If `req.body.client_signature` was present, it appended it to the internal request to the Python backend. However, it did **not** enforce that the signature must be present. If omitted, the request proceeded.

**Backend-FastAPI (`internal_engine_routes.py`)**
- Handled the internal `/crypto/encrypt` route.
- Performed rigorous verification of the signature and payload canonicalization **if and only if** `client_signature` was provided.
- Allowed requests to proceed if `client_signature` was completely absent.

### Complete Flow Trace
1. **Generate Key**: `generateSigningKeyPair` creates RSA-PSS keys in WebCrypto.
2. **Store Private Key**: Stored in IndexedDB (`signing_private_{id}`).
3. **Export Public Key**: Exported as SPKI Base64.
4. **Bind Public Key**: Sent to server via `/crypto/register-key` after signing a proof-of-possession challenge.
5. **Sign File Transfer**: `SendFile.jsx` hashes file, creates canonical payload, signs with local private key.
6. **Send Signature**: Sent in `multipart/form-data` to Node.js backend. Node forwards to FastAPI.
7. **Verify Signature**: FastAPI reconstructs canonical payload and verifies RSA-PSS signature.
8. **Continue PFCE Encryption**: File is encrypted if verification passes (or if signature was omitted).

## Phase 2 — Determine Why Setup Banner Appears

The `SigningSetup.jsx` component displayed the "Generate & Bind Keys" banner based on the following logic:

```javascript
const hasBackendKey = res.has_active_key;
const hasLocalKey = await hasSigningKey(user.id);

if (hasBackendKey && hasLocalKey) {
  setStatus('registered');
} else {
  setStatus('setup_needed');
}
```

### State Findings

- `LOCAL_PRIVATE_KEY_EXISTS = TRUE/FALSE` (Depending on IndexedDB state)
- `SERVER_PUBLIC_KEY_BOUND = TRUE/FALSE` (Depending on MongoDB `SigningKey` state)
- `KEY_ID_MATCH = FALSE` (The UI did not check if the local key actually matched the server key, it only checked if *any* local key existed alongside *any* server key).
- `SIGNING_READY = TRUE/FALSE` (Loosely inferred from the existence of both keys, but prone to mismatch errors on new devices or cleared caches).

### Root Cause of Confusion
Because there was no fingerprint matching between the local IndexedDB key and the server's registered key, and because the UI did not distinguish between a missing local key (e.g., new device) vs a missing server key, the user was simply prompted to "Generate & Bind Keys" indiscriminately whenever either side was missing. This would overwrite the server state and cause confusion on other devices.
