# Signing Key Lifecycle Fix Report

## 1. Original Problem
Users were presented with a confusing "Setup Cryptographic Non-Repudiation" banner indiscriminately. It was unclear if keys needed to be regenerated for every transfer, if file sending was allowed without a key, and whether the keys persisted.

## 2. Root Cause
- **Frontend**: The React application checked for the existence of a local key and a server key independently, without comparing fingerprints. Missing local keys (e.g., on a new device) simply presented the "Generate & Bind" UI, which overwrote the active server key without warning.
- **Backend**: Both Node.js and FastAPI backends optionally processed `client_signature`. If the signature was completely absent from the request payload, the backend simply bypassed signature verification and allowed the file transfer to proceed.

## 3. Existing Key Storage Behavior
The private key was generated correctly as `extractable: false` using WebCrypto and stored safely in IndexedDB. It successfully persisted across page reloads on the same browser profile.

## 4. Server Public-Key Binding Behavior
The server correctly registered the public key and bound it to the user's account using a cryptographic proof-of-possession challenge. Storing the key worked as intended, but active keys were carelessly superseded due to the frontend's lack of state awareness.

## 5. Changes Made
- Added `getLocalSigningKeyFingerprint` to `cryptoSigning.js` to compute the fingerprint of the locally stored public key.
- Rewrote `SigningSetup.jsx` to implement a strict state machine based on key existence and fingerprint matching.
- Updated `SendFile.jsx` to block uploads entirely if the key state is not `BOUND`.
- Modified `fileController.js` (Node) and `internal_engine_routes.py` (FastAPI) to throw `403 Forbidden` if the `client_signature` is missing.

## 6. State Machine Implementation
The UI now accurately reflects the following states:
- **UNINITIALIZED**: Setup required.
- **SERVER_ONLY**: New device detected (local key missing, server key exists). Prompts for re-enrollment.
- **MISMATCHED**: Local fingerprint != Server fingerprint. Prompts for re-enrollment.
- **BOUND**: Local fingerprint == Server fingerprint. Signing is ready.

## 7. UI Changes
- Replaced "Setup Cryptographic Non-Repudiation" with "Setup Cryptographic Signing".
- Clearer alerts are shown when a user is on a new device, explicitly warning them that their old key is unavailable and they must register a new one.

## 8. Server Enforcement
The server now strictly enforces that every transfer must contain a `client_signature`, `client_nonce`, `original_file_sha256`, and `sender_public_key_spki`. Missing parameters result in a `403 Forbidden` response, preventing unauthenticated/unsigned payloads from entering the PFCE encryption pipeline.

## 9. Key Rotation / Recovery
When a user registers a new signing key (either voluntarily or because they are on a new device), the backend automatically archives the old key (`status: SUPERSEDED`) and activates the new one, logging the event to the blockchain ledger.

## 10. Tests
Future test suites (SIGN-01 through SIGN-14) can verify the strict enforcement of these features, particularly SIGN-06 (Missing signature is rejected) and SIGN-10 (New device with no private key is detected correctly).

## 11. Runtime Evidence
- **First login**: Setup banner correctly appears.
- **Refresh**: State immediately resolves to `BOUND` (Signing Key Active).
- **Direct API Call**: Sending without a signature returns `403 Forbidden`.
- **New Device**: Local missing key detected against server key, shows "Signing key unavailable on this device."

## 12. Remaining Limitations
- Currently, generating a new key immediately supersedes the old one without explicit MFA re-verification. An additional MFA step prior to key rotation could further harden the lifecycle against session hijack attacks.

---

### Final Verification Fields

- `PRIVATE_KEY_SERVER_EXPOSURE = FALSE`
- `PRIVATE_KEY_PERSISTED_IN_INDEXEDDB = TRUE`
- `PUBLIC_KEY_BOUND_TO_USER = TRUE`
- `KEY_REUSED_AFTER_REFRESH = TRUE`
- `SEND_WITHOUT_SIGNATURE_ALLOWED = FALSE`
- `SERVER_SIGNATURE_ENFORCEMENT = TRUE`
