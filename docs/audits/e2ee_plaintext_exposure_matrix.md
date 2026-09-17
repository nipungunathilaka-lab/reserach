# Plaintext Exposure Matrix

| Component | Receives Plaintext? | Can Read File Content? | Holds Decryption Key? | Cryptographic Role | Evidence |
|---|---|---|---|---|---|
| Browser Sender | YES | YES | NO | Cryptographic signing (RSA-PSS), Hashing (SHA-256), Key generation (WebCrypto) | `SendFile.jsx` reads the file to create chunks. `cryptoSigning.js` calculates SHA-256 and signs the challenge, but does not encrypt content. |
| Node.js API | YES | YES | NO | TLS Termination, Metadata association, Chunk assembly | `fileController.js` reassembles chunks into a plaintext file in `os.tmpdir()` and streams it via Axios. |
| FastAPI Engine | YES | YES | YES | Malware scanning (ClamAV), Data classification, PFCE Encryption & Decryption, ECDH unwrap, UPCE processing | `internal_engine_routes.py` reads `file.read()`. `pfce_engine.py` generates AES-GCM keys, encrypts the plaintext fragments, and wraps keys using ECDH or PQC. |
| Temporary Storage (Node.js) | YES | YES | NO | Temporary buffering | `fileController.js` creates a file in `secure_transfer_chunks` before sending to FastAPI. |
| MongoDB | NO | NO | NO | Metadata storage | Stores `Transfer` documents which contain cipher algorithms, hashes, and wrapped keys, but no plaintext content. |
| SQLite | NO | NO | NO | Audit/Blockchain storage | Stores blockchain events, hashes, metadata, but no plaintext content. |
| PFCE Storage | NO | NO | NO | Encrypted package at rest | `.pfce` packages contain AES/ChaCha20 encrypted fragments. Keys are protected. |
| Browser Receiver | YES | YES | NO | None (decryption happens on server) | Receives a decrypted stream from the server after successful authentication. |
