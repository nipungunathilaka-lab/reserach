# Architecture & Source Code Analysis: AI-Secure File Transfer System

## 1. System Overview
The **AI-Enhanced Secure File Transfer System** is a full-stack web application designed for the highly secure transmission, storage, and auditing of sensitive files. It combines traditional military-grade cryptography with advanced, zero-trust patterns like polymorphic chunking, AI anomaly detection, and blockchain-based audit logging.

## 2. Technology Stack
* **Frontend:** React 18, Vite, TailwindCSS, React Router (SPA architecture).
* **Backend:** Python 3.11+, FastAPI, SQLAlchemy (ORM).
* **Database:** SQLite (local dev) / PostgreSQL & Redis (Docker production).
* **Cryptography:** `cryptography` Python package (AES-GCM, RSA, ECDH, HKDF).
* **AI/ML:** Scikit-Learn (Isolation Forest for anomaly detection, Random Forest for malware detection).

---

## 3. Core Architectural Components

### 3.1 Authentication & Access Control (`auth_service.py`, `mfa_service.py`)
* **JWT-Based Sessions:** Employs short-lived JSON Web Tokens for API authorization.
* **Hardened Logins:** Enforces rate-limiting, lockout mechanisms after failed attempts, and password hashing.
* **MFA (Multi-Factor Authentication):** Enforces OTP validation (via email) for sensitive operations and user accounts.

### 3.2 Cryptography Engine (`crypto_service.py`)
The system employs **Adaptive Hybrid Cryptography**:
* **Symmetric Encryption (Data):** Uses AES-128-GCM (Normal files) or AES-256-GCM (Sensitive files) with 96-bit nonces.
* **Asymmetric Wrapping (Key Distribution):** 
  * AES keys are generated dynamically per transfer and wrapped using the receiver's **RSA-2048 Public Key**.
  * For "Sensitive" files, Perfect Forward Secrecy is added via **ECDH (SECP256R1)**. A shared secret is derived using ephemeral keys, passed through **HKDF (SHA-256)** to generate a wrap-key, which double-encrypts the AES key.

### 3.3 PFCE Streaming Engine (`pfce_engine.py`)
The **Polymorphic File Chunking Engine (PFCE)** is a zero-trust streaming mechanism designed to handle extremely large files (e.g., 5GB+) without exhausting RAM.
* **Chunking:** Files are streamed and split into random-sized (polymorphic) fragments.
* **Independent Encryption:** *Every single fragment* receives a completely new AES key, a new RSA wrap, and a new ECDH wrap.
* **Metadata Assembly:** A metadata file tracks the fragments and their respective key materials, and the whole package is zipped (`.pfce` format).

### 3.4 AI & Malware Detection (`ai_service.py`, `malware_service.py`)
* **Anomaly Detection:** An `IsolationForest` ML model analyzes transfer metadata (time of day, file size, frequency, IP heuristics) to detect unusual behavior and flag anomalous transfers.
* **Malware Detection:** Files undergo a heuristic/ML scan (using a pre-trained `malware_model.joblib`) to predict if the file contains malicious signatures or traits before the transfer is finalized.

### 3.5 Immutable Audit Trail (`blockchain_service.py`)
* Implements a localized blockchain ledger.
* Every file transfer, encryption event, and AI flag is hashed and linked to the previous block's hash.
* This guarantees that administrators or attackers cannot silently alter or delete the history of file transfers without breaking the cryptographic chain.

---

## 4. Security Assessment & Threat Modeling

### **Strengths**
1. **Zero-Trust Fragmentation:** The PFCE engine ensures that compromising a single chunk's key doesn't compromise the whole file.
2. **Forward Secrecy:** The use of ephemeral ECDH keys for sensitive files ensures past transfers cannot be decrypted even if the long-term RSA keys are stolen.
3. **Defense-in-Depth:** Combining AI anomaly detection, MFA, and Blockchain auditing provides excellent visibility and tamper resistance.

### **Current Vulnerabilities (Backend-heavy Architecture)**
The system currently performs encryption **Server-Side**. 
1. **Man-in-the-Middle (Internal):** The file travels from the React frontend to the FastAPI backend in plaintext.
2. **Server Compromise:** If an attacker gains root access to the backend server, they can dump the RAM to extract the AES keys before they are wrapped, or extract the plaintext file directly. They can also steal the users' RSA `.pem` private keys stored on the disk.

### **Recommended Security Upgrades**
1. **End-to-End Encryption (E2EE):** Move `crypto_service.py` logic into the browser using the WebCrypto API. The backend should only route ciphertext.
2. **Key Management System (KMS):** Do not store `.pem` private keys as plaintext on the server. They should be encrypted with a user-derived password (Argon2) or stored in an external HSM/KMS.
3. **Memory Protection:** Utilize Trusted Execution Environments (TEEs) like Intel SGX if server-side processing (like Malware scanning) is strictly required.
