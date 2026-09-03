# Universal Polymorphic Cryptographic Engine (UPCE)
**A Highly Secure, Hybrid File Transfer System Utilizing Post-Quantum Cryptography (PQC), AI Threat Detection, and Blockchain-inspired Tamper-Evident Ledgers.**

---

## 🚀 System Overview

The UPCE project is a cutting-edge, dual-engine microservices architecture designed to facilitate the secure transfer of highly sensitive files. By decoupling standard web application logic from intense cryptographic and machine-learning workloads, the system achieves maximum performance without compromising on zero-trust principles.

The application stack seamlessly blends the **MERN Stack** (MongoDB, Express, React, Node.js) with a **Python FastAPI Engine**, allowing for real-time dashboard analytics, flawless 100GB+ file streaming, and quantum-resistant encryption.

---

## ✨ Core Features

### 1. Hybrid Post-Quantum Cryptography (PQC)
- **Quantum-Safe Key Encapsulation (KEM)**: Protects against "Store Now, Decrypt Later" quantum attacks using the **Kyber** algorithm.
- **Polymorphic Encryption**: Dynamically alternates between **AES-256-GCM** and **ChaCha20-Poly1305** based on file characteristics, making cryptanalysis significantly harder.
- **Zero-Knowledge Architecture**: Files are encrypted with keys that only the intended recipient can unwrap. The server never holds plain-text AES keys.

### 2. AI-Powered Anomaly & Threat Detection
- **Real-Time Behavioral Analysis**: Uses an **Isolation Forest** machine learning model to analyze file sizes, transfer frequencies, login failures, and time-of-day access to detect malicious insider threats.
- **Malware Scanning**: Automatically intercepts and quarantines files exhibiting malicious byte-patterns before they can be decrypted by the receiver.

### 3. Immutable Blockchain Audit Ledger
- **Tamper-Evident Logs**: Every authentication event and file transfer generates a cryptographically hashed block.
- **Cryptographic Chain Verification**: Each block relies on the hash of the previous block, ensuring that if a malicious actor alters a database entry, the entire audit chain instantly invalidates.

### 4. Enterprise-Grade Architecture
- **Metadata-Only MongoDB**: MongoDB is strictly used for lightweight metadata. The 100GB+ binary payloads never touch the database, circumventing storage limits and RAM exhaustion.
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
| **Backend API** | Node.js, Express, Mongoose | Orchestrates JWT auth, user management, and MongoDB interactions. |
| **Internal Engine**| Python, FastAPI, Scikit-Learn | Stateless microservice executing AI models, PFCE streaming, and Kyber crypto. |
| **Database** | MongoDB Atlas | Stores users, MFA tokens, transfer metadata, and blockchain ledger entries. |
| **Storage** | Local Server Disk (`/storage`) | Directly stores raw `.pfce` encrypted chunks via streaming streams. |

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
   - **Node.js API:** http://localhost:5000
   - **Python Engine:** http://localhost:8000

---
## 📝 License
Proprietary Software. All rights reserved.
