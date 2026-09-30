# Comprehensive Structural Report: Universal Polymorphic Cryptographic Engine (UPCE)

## 1. High-Level System Architecture
The Universal Polymorphic Cryptographic Engine (UPCE) implements a highly decoupled microservice architecture designed to isolate heavy cryptographic and machine learning workloads from standard web application operations. 

The architecture bridges the **MERN Stack** (MongoDB, Express, React, Node.js) with a dedicated **Python FastAPI Engine**:
*   **Decoupling Principle:** Standard web interactions (authentication, metadata querying, UI rendering) are handled by the Node.js/Express gateway. Intensive security tasks (Post-Quantum cryptography, AI anomaly detection, ledger anchoring, and large file chunking) are completely offloaded to the isolated Python FastAPI engine. 
*   **Zero-Trust Isolation:** The Python engine acts as an isolated security boundary. The Node.js application server does not have access to the cryptographic master keys or the AI training sets, preventing a compromise of the web tier from exposing the core cryptographic engine.

## 2. Component Breakdown

### 2.1 React Frontend
*   **Frameworks:** React, Vite, Tailwind CSS.
*   **Responsibility:** Provides a secure, responsive, and glassmorphic user interface. 
*   **Security Features:** Manages JWT storage, enforces Multi-Factor Authentication (MFA) flows, and uses defensive rendering patterns (optional-chaining) to prevent UI crashes during empty states or delayed network payloads. It also handles initial client-side cryptographic hashing for integrity checks.

### 2.2 Node.js API Gateway (Application Backend)
*   **Frameworks:** Node.js, Express, Mongoose.
*   **Responsibility:** Acts as the primary API router and orchestrator. 
*   **Key Functions:**
    *   **Authentication & Authorization:** Handles JWT issuance and validation, user login, and MFA (TOTP) verification.
    *   **Metadata Management:** Interfaces with MongoDB Atlas to store and retrieve non-sensitive file metadata (e.g., sender, receiver, threat scores) without touching the actual binary payload.
    *   **Routing:** Proxies file upload/download streams to the Python FastAPI engine for processing.

### 2.3 Python FastAPI Engine (Security & Processing Backend)
*   **Frameworks:** Python, FastAPI, Scikit-Learn, liboqs (Open Quantum Safe), Cryptography.
*   **Responsibility:** The core workhorse of the system, handling all heavy processing.
*   **Key Functions:**
    *   **PFCE Engine:** Handles bounded-memory chunking, streaming, and polymorphic encryption of large files.
    *   **Post-Quantum Crypto (PQC):** Integrates Kyber (ML-KEM-768) for quantum-resistant key encapsulation.
    *   **AI Threat Detection:** Runs the Isolation Forest model to detect behavioral anomalies mid-stream.
    *   **Blockchain Audit Ledger:** Anchors tamper-evident hashes into a local SQLite state linked to a Hyperledger Besu QBFT blockchain.

## 3. Core Data Flow & Workflows

**File Transfer Lifecycle:**
1.  **UI Upload (Frontend):** The sender selects a file. The React frontend computes an initial SHA-256 hash and initiates a multipart/form-data POST request to the Node.js Gateway.
2.  **Node.js Routing:** The gateway validates the sender's JWT session, generates a preliminary `Transfer` record in MongoDB, and proxies the raw file stream directly to the Python FastAPI engine via an internal HTTP request.
3.  **Python AI Scanning:** FastAPI receives the stream. An active `ContinuousTransferMonitor` evaluates the context (file size, time of day, transfer frequency, prior failed logins) using the Isolation Forest model. If malicious, the stream is hard-blocked and quarantined instantly.
4.  **Chunking & Encryption (PFCE):** The stream is dynamically chunked into true random sizes (1MB-5MB). Each chunk is polymorphically encrypted (AES-256-GCM / ChaCha20) and wrapped using a hybrid ML-KEM/RSA key encapsulation. The chunks are packaged into a `.pfce` zip file on the local disk.
5.  **MongoDB Storage:** FastAPI returns the processing results (threat score, storage path, chunk count) to Node.js. Node.js updates the MongoDB `Transfer` document. The actual binary never touches MongoDB.
6.  **Blockchain Audit:** The Python engine logs a `PFCE_SIGNATURE_CREATED` block into the tamper-evident SQLite ledger, cryptographically chained to the previous block.

## 4. Security & Cryptographic Engine (PFCE)
The Polymorphic File Cryptographic Engine (PFCE) is responsible for protecting data at rest.

*   **Polymorphic Encryption:** To disrupt cryptanalysis, PFCE dynamically switches between **AES-256-GCM** and **ChaCha20-Poly1305** for individual file fragments.
*   **Hybrid Key Encapsulation:** Symmetric chunk keys are wrapped using a hybrid mechanism. The engine uses **ECDH** (Elliptic Curve Diffie-Hellman) combined with **ML-KEM-768 (Kyber)** via the `liboqs-python` library. 
*   **Post-Quantum Defense:** ML-KEM ensures that even if an adversary harvests the encrypted `.pfce` chunks and waits for quantum computers capable of breaking RSA/ECDH (Shor's algorithm), the symmetric keys remain encapsulated by quantum-safe mathematics ("Store Now, Decrypt Later" defense).
*   **Digital Signatures:** All transfers require an RSA-PSS-SHA256 signature from the sender, bound to the file hash and transfer ID, preventing Man-in-the-Middle (MitM) identity substitution.

## 5. AI Threat Detection
The AI layer provides behavioral risk assessment and deterministic malware blocking.

*   **Isolation Forest Model:** A machine learning pipeline trained on synthetic enterprise transfer data (e.g., `file_size_mb`, `hour_of_day`, `transfers_last_hour`, `mfa_failed_attempts`). It calculates an `anomaly_score` based on the multidimensional distance of the current transfer from normal baselines.
*   **Differential Privacy:** Inputs to the AI model are protected via a Laplace mechanism with tracked privacy budgets, ensuring user behavior cannot be fully reverse-engineered from the model's output.
*   **Hard-Blocking Threshold:** If the Isolation Forest generates an anomaly score $\ge$ 0.40, or if deterministic security controls are violated (e.g., large high-risk file after multiple MFA failures), the `ContinuousTransferMonitor` throws a `TransferBlockedError`. This terminates the HTTP upload stream mid-flight, quarantines the data, and logs a critical audit event.

## 6. Database Schemas

### 6.1 User (MongoDB)
Stores application users and authentication states.
*   `email`: String (Unique, Indexed)
*   `password_hash`: String
*   `mfa_enabled`: Boolean (Default: true)
*   `totp_secret`: String
*   `failed_login_attempts`: Number
*   `locked_until`: Date

### 6.2 Transfer (MongoDB)
Stores metadata for file transfers. No binary data is stored here.
*   `file_name`, `stored_name`: String
*   `original_hash`, `encrypted_path`: String
*   `status`: String (Default: 'encrypted')
*   `sender_id`, `receiver_id`: ObjectId (Refs: User)
*   `anomaly_score`: Number
*   `is_anomaly`: Boolean
*   `cipher_algorithm`: String

### 6.3 AuditBlock (SQLite / Mongoose Representation)
Represents the local tamper-evident blockchain ledger.
*   `event_type`: String (e.g., 'PFCE_SIGNATURE_CREATED')
*   `details_json`: String (Serialized JSON of event data)
*   `previous_hash`: String (SHA-256 hash of the preceding block)
*   `block_hash`: String (SHA-256 hash of this block's contents + previous_hash)

## 7. Internal API Matrix

### 7.1 Frontend (React) -> Gateway (Node.js)
*   `POST /api/auth/login`: Authenticates user, triggers MFA if enabled.
*   `POST /api/auth/verify-mfa`: Verifies TOTP, returns JWT.
*   `POST /api/transfers/upload`: Multipart file upload from UI.
*   `GET /api/transfers/download/:id`: Initiates file download request.
*   `GET /api/transfers/dashboard`: Retrieves user's transfer history and metrics.

### 7.2 Gateway (Node.js) -> Security Engine (FastAPI)
All routes prefixed with `/internal/` and protected by an internal shared secret.
*   `POST /internal/crypto/encrypt`: Receives the raw file stream from Node.js. Performs AI monitoring, chunking, PQC encryption, and ledger logging. Returns storage path and threat metadata.
*   `POST /internal/crypto/decrypt`: Receives decapsulation request. Validates digital signatures, decapsulates ML-KEM keys, decrypts chunks, and streams the plaintext binary back to Node.js.
*   `GET /internal/audit/verify-ledger`: Triggers a cryptographic hash-chain verification of the entire local SQLite audit database.
*   `POST /internal/crypto/ensure_keys`: Triggers the generation of a new ML-KEM-768 keypair for a specific user.
