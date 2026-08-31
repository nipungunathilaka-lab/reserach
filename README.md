# Universal Polymorphic Cryptographic Engine (UPCE)

A highly secure, hybrid file transfer system utilizing Post-Quantum Cryptography (PQC), AI Threat Detection, and Blockchain-inspired Tamper-Evident Ledgers.

## 🚀 Architecture Overview

This project uses a decoupled, hybrid microservices architecture:

1. **Frontend (React + Vite + Tailwind CSS)**: 
   A modern, glassmorphic UI built with React. It provides real-time alerts, dashboard statistics, a file vault, and secure transfer logs. 

2. **Core API Backend (Node.js + Express + MongoDB)**:
   The primary application server. Handles user authentication (JWT), file metadata, MongoDB interactions, and orchestrates requests between the frontend and the AI/Crypto engine.

3. **Internal Engine (Python + FastAPI)**:
   A stateless microservice strictly responsible for heavy computational workloads:
   - **Hybrid Cryptography**: Post-Quantum Kyber Key Encapsulation Mechanism (KEM) combined with AES-256 and ChaCha20 for file encryption.
   - **AI Threat Detection**: An Isolation Forest machine learning model that analyzes transfer behavior in real-time to detect anomalous or malicious activity.
   - **Tamper-Evident Logs**: Blockchain-inspired hashing mechanisms that ensure audit logs cannot be secretly altered.

## 🛠️ Prerequisites

- **Node.js** (v18+)
- **Python** (v3.9+)
- **MongoDB** cluster (connection string provided in `.env`)

## ⚙️ Local Development Setup

Thanks to a unified `package.json`, running the entire stack is seamless.

1. **Install Root Dependencies:**
   ```bash
   npm install
   ```
   *(This installs `concurrently` for running the microservices together).*

2. **Install Node.js Backend Dependencies:**
   ```bash
   cd backend-node
   npm install
   cd ..
   ```

3. **Install React Frontend Dependencies:**
   ```bash
   cd frontend
   npm install
   cd ..
   ```

4. **Install Python Microservice Dependencies:**
   Ensure you have a virtual environment set up (`backend/venv`) and install the requirements:
   ```bash
   cd backend
   python -m venv venv
   # On Windows:
   .\venv\Scripts\activate
   pip install -r requirements.txt
   cd ..
   ```

5. **Start the Entire Application:**
   Run the following command from the root directory to spin up the Node API, Python API, and React Frontend simultaneously:
   ```bash
   npm run dev
   ```

   - **Frontend:** http://localhost:5173
   - **Node.js API:** http://localhost:5000
   - **Python Engine:** http://localhost:8000

## 🛡️ Key Features

- **Quantum-Safe Encryption**: Protects file transfers against future quantum computing attacks using Kyber.
- **AI-Powered Anomaly Detection**: Actively monitors transfers for unusual sizes, patterns, and frequencies to prevent breaches.
- **Cryptographic Audit Trails**: All login and transfer events are recorded into an immutable blockchain-style ledger.
- **Zero-Knowledge Architecture**: Files are encrypted before leaving the client-server boundary and can only be decrypted by the intended recipient's unique keys.

## 📝 License

Proprietary Software. All rights reserved.
