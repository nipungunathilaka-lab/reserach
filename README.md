# Universal Polymorphic Cryptographic Engine (UPCE)
**A Highly Secure, Hybrid File Transfer System Utilizing Post-Quantum Cryptography (PQC), AI Threat Detection, and Permissioned Decentralized Blockchain-Backed Audit Ledgers.**

---

## 🚀 System Overview

The UPCE project is a cutting-edge, dual-engine microservices architecture designed to facilitate the secure transfer of highly sensitive files. By decoupling standard web application logic from intense cryptographic and machine-learning workloads, the system achieves maximum performance without compromising on zero-trust principles.

The application stack seamlessly blends the **MERN Stack** (MongoDB, Express, React, Node.js) with a **Python FastAPI Engine**, allowing for real-time dashboard analytics, bounded-memory large-file streaming, and quantum-resistant encryption.

> [!WARNING]
> The prototype evaluates a defined set of security controls and does not claim complete protection against all cyberattacks. The security evaluation was limited to the controls implemented within the research prototype.

**Architecture Note:** FastAPI is an **isolated security-processing service with dedicated persistent security state, including only the security metadata, telemetry, audit references, policy state, and cryptographic artifacts required by the implemented trust model.** Application API responsibilities and persistent security-engine state are isolated from each other. Persisted entities managed by FastAPI in SQLite include:
- `AuditBlock`: Blockchain audit references
- `PQCKey` & `TrustedClientKey`: Cryptographic artifacts
- `QuarantineItem` & `AIAlert`: Telemetry and policy state

MongoDB is the primary persistent datastore of the web application layer. The React frontend communicates with the Node.js/Express application layer, which manages application data in MongoDB and invokes the Python/FastAPI security engine for specialized security processing.

## ✨ Core Features

### 1. Hybrid Post-Quantum Cryptography (PQC)
- **Quantum-Safe Key Encapsulation (KEM)**: Protects against "Store Now, Decrypt Later" quantum attacks using the **Kyber** algorithm.
- **Polymorphic Encryption**: Dynamically alternates between **AES-256-GCM** and **ChaCha20-Poly1305** based on file characteristics, making cryptanalysis significantly harder.
- **Server-Mediated Cryptography**: Files are encrypted at rest using PFCE. The server evaluates plaintext for malware and AI policies within a trusted boundary prior to encryption.

### 2. AI-Powered Anomaly & Threat Detection
- **Real-Time Behavioral Analysis**: Uses an **Isolation Forest** machine learning model to analyze file sizes, transfer frequencies, login failures, and time-of-day access to detect malicious insider threats. 
  - *Note: The anomaly-detection model provides probabilistic behavioural risk detection and may produce both false positives and false negatives. Differential Privacy is integrated into the active behavioural-AI feature-processing pipeline using bounded feature values and a configurable Laplace mechanism with explicit privacy parameters and budget tracking.*
  - *Data Provenance: The Isolation Forest was evaluated on a synthetic laboratory secure-transfer dataset. A provenance-aware telemetry collection pipeline is available for future evaluation and retraining using authorized real application data.*
- **Malware Scanning**: Automatically intercepts and quarantines files exhibiting malicious byte-patterns before they can be decrypted by the receiver.

### 3. Permissioned Decentralized Blockchain Audit Ledger
- **Tamper-Evident Logs**: Every authentication event and file transfer generates a cryptographically hashed block.
- **Layer 2 Smart Contract Anchoring**: Off-chain database hashes are strictly anchored into a Hyperledger Besu QBFT blockchain using smart contracts (`AuditLedger.sol`). 
- **Strict Fail-Closed Enforcement**: If decentralized consensus is unavailable or tampering is detected on the local DB, the system strictly halts sensitive operations, preventing audit evasion.

### 4. Enterprise-Grade Architecture
- **Metadata-Only MongoDB**: MongoDB is strictly used for lightweight metadata. The large binary payloads never touch the database, circumventing storage limits and RAM exhaustion.
- **Chunked Disk-Streaming**: Uploads and downloads are heavily optimized using data stream generators (`fs.createReadStream`, `StreamingResponse`, and `PFCEEngine`), streaming massive files directly to the local disk in tiny 1MB memory footprints.
- **Defensive React UI**: The frontend employs deep optional-chaining and defensive rendering patterns, guaranteeing the UI never crashes due to empty data or missing network payloads.

---

## 📊 Situations & Use Cases

1. **Enterprise Intellectual Property Transfer**
   *Situation:* A research firm needs to send 50GB CAD files and source code securely across branches. 
   *Solution:* UPCE handles the massive file via chunked disk-streaming. Even if the database is compromised, the encrypted `.pfce` chunks are unreadable without the specific recipient's wrapped private keys.

2. **Preventing Insider Data Exfiltration**
   *Situation:* A compromised employee account begins downloading unusually large volumes of restricted files at 3:00 AM.
   *Solution:* The AI Threat Detection engine flags this as a critical anomaly based on the user's historical baseline, quarantining the transfer and logging an immutable high-risk alert to the Blockchain Ledger.

3. **Future-Proofing Against Quantum Computing**
   *Situation:* Nation-state actors intercept and store encrypted internet traffic, waiting for quantum computers to become viable to crack standard RSA/ECC encryption.
   *Solution:* The Kyber KEM integration ensures that the symmetric encryption keys wrapping the files cannot be cracked by Shor's algorithm, maintaining data confidentiality for decades.

---

## 🛠️ Technology Stack

| Domain | Technology | Purpose |
|---|---|---|
| **Frontend** | React, Vite, Tailwind CSS, Lucide | Glassmorphic UI, responsive dashboards, secure JWT storage. |
| **Backend API** | Node.js, Express, Mongoose | Orchestrates JWT auth, user management, and primary MongoDB interactions. |
| **Internal Engine**| Python, FastAPI, Scikit-Learn | Microservice executing AI models, PFCE streaming, Kyber crypto, and managing an isolated SQLite ledger. |
| **Primary Database** | MongoDB Atlas | Stores users, MFA tokens, transfer metadata, and UI-facing audit alerts. |
| **Security State DB** | SQLite | Local database strictly isolated for the Python engine to anchor the Hyperledger Besu audit chain and store PQC keys. |

---

## ⚙️ Local Development Setup

Thanks to a unified `package.json` utilizing `concurrently`, running the entire microservice stack is seamless.

### Prerequisites
- **Node.js** (v18+)
- **Python** (v3.9+)
- **MongoDB** cluster (connection string provided in `.env`)

### Installation & Execution

1. **Install Root Dependencies:**
   ```bash
   npm install
   ```

2. **Install Node.js Backend Dependencies:**
   ```bash
   cd backend-node && npm install && cd ..
   ```

3. **Install React Frontend Dependencies:**
   ```bash
   cd frontend && npm install && cd ..
   ```

4. **Install Python Microservice Dependencies:**
   ```bash
   cd backend
   python -m venv venv
   # On Windows:
   .\venv\Scripts\activate
   pip install -r requirements.txt
   cd ..
   ```

5. **Start the Application:**
   Run the following command from the root directory to spin up the Node API, Python API, and React Frontend simultaneously:
   ```bash
   npm run dev
   ```

   - **Frontend:** http://localhost:5173
   - **Node.js API:** http://localhost:5001
   - **Python Engine:** http://localhost:8000

---

## 📈 Performance Testing & Validation

The current implementation uses bounded-memory chunked/streaming processing and has been experimentally validated using a 10GB server-mediated transfer with matching source and reconstructed SHA-256 digests. Known whole-file memory bottlenecks have been removed.

* **Bounded Memory Constraints (Gained):** A true file streaming architecture is implemented natively across all bounds. File chunks flow via `hash-wasm` (browser UI), Node.js `Readable/Writable` streams, and FastAPI `StreamingResponse`. Complete file data is never fully loaded into memory.
* **100GB+ Validation Status:** Transfers exceeding 100GB remain an architectural design target and have not yet been experimentally validated due to the storage capacity of the present test environment.
* **Malware Scanning Limitations:** The currently integrated malware scanning engine does not support streaming validation for files exceeding 1GB. As such, full-file malware scanning on extremely large files is classified as an unresolved limitation and is skipped to prevent OOM errors. This is explicitly reported in the transfer audit. 

---
## 📝 License
Proprietary Software. All rights reserved.
