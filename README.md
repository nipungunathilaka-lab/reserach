<div align="center">
  
# 🛡️ AI-Enhanced Secure File Transfer System

**A next-generation, high-performance file transfer protocol leveraging Polymorphic Cryptography and AI-driven behavioral analysis.**

[![React](https://img.shields.io/badge/Frontend-React.js-61DAFB?style=for-the-badge&logo=react&logoColor=white)](https://reactjs.org/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Python](https://img.shields.io/badge/Language-Python_3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Database](https://img.shields.io/badge/Database-SQLite%20%7C%20PostgreSQL-336791?style=for-the-badge&logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![AI](https://img.shields.io/badge/AI_Engine-Scikit--Learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![Blockchain](https://img.shields.io/badge/Audit-Blockchain_Inspired-111111?style=for-the-badge&logo=web3.js&logoColor=white)](#)

</div>

<br />

## 📖 Project Overview

The **AI-Enhanced Secure File Transfer System** is an advanced research project designed to solve the critical challenges of data security and system scalability in modern networks. 

At its core lies the **9-block Polymorphic File Cryptography Engine (PFCE)** architecture. This custom-built engine balances strict, military-grade security with high system throughput, ensuring that massive file transfers remain both impenetrable and highly efficient. 

---

## ✨ Key Features

### 🧩 Dynamic Variable-Size Fragmentation
Optimizes system RAM and network bandwidth by dynamically splitting large payloads based on real-time system thresholds. Fragments are encrypted independently, preventing memory overflows during massive transfers.

### 🔐 Advanced Hybrid Cryptography
Utilizes a dual-layered cryptographic approach:
- **Payload Encryption**: Fast and secure symmetric encryption using **AES-256** and **ChaCha20**.
- **Key Exchange**: Asymmetric encryption utilizing **RSA-OAEP** and **ECDH** (Elliptic Curve Diffie-Hellman) to guarantee secure key exchange and perfect forward secrecy.

### 🧠 AI Context Analysis Engine
An intelligent behavioral analysis subsystem that evaluates transfer context in real-time. By monitoring variables such as **time of transfer anomalies** and **file size irregularities**, the engine generates a dynamic **'Context Vector C'** threat score to proactively block suspicious activities.

### 🔗 Blockchain-Inspired Audit Logging
Guarantees absolute non-repudiation and transparency. All transfer metadata, cryptographic proofs, and AI threat scores are logged into an immutable database structure, providing a tamper-proof trail for digital forensics.

---

## 🛠️ Tech Stack

### Frontend
- **React.js**: Modern, responsive, and glassmorphic user interface.
- **Tailwind CSS**: Rapid UI styling and layout management.

### Backend
- **Python 3.10+**
- **FastAPI**: High-performance asynchronous API routing.
- **SQLAlchemy**: Powerful Object Relational Mapping (ORM).
- **Pydantic**: Strict data validation and typing.

### Database & ML
- **SQLite / PostgreSQL**: Flexible deployment options for local development and production.
- **Scikit-Learn**: Machine learning models for behavioral anomaly detection.

---

## 🚀 Getting Started

Follow these instructions to set up the project locally for development and testing.

### Prerequisites
- Node.js (v16 or higher)
- Python (v3.10 or higher)
- pip and npm installed

### 1. Backend Setup (FastAPI)

Navigate to the backend directory and set up your Python environment:

```bash
# Clone the repository (if applicable)
# cd ai-secure-file-transfer-system

# Navigate to the backend folder
cd backend

# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install the required dependencies
pip install -r requirements.txt

# Start the FastAPI server using Uvicorn
uvicorn app.main:app --reload
```
*The backend will be available at `http://localhost:8000`. You can view the interactive API docs at `http://localhost:8000/docs`.*

### 2. Frontend Setup (React)

Open a new terminal window, navigate to the frontend directory, and start the development server:

```bash
# Navigate to the frontend folder (from the project root)
cd frontend

# Install Node.js dependencies
npm install

# Start the React development server
npm start
```
*The frontend will be available at `http://localhost:3000`.*

---

## 🔮 Future Enhancements

As the system evolves, the roadmap includes scaling the architecture into **Peer-to-Peer (P2P) Edge Computing**. 

By utilizing a crossover desktop architecture built on **Flutter** (for cross-platform UI) and **Python** (for heavy lifting), the next iteration aims to seamlessly handle extreme data pipelines, facilitating secure, decentralized transfers in excess of **100GB+** directly between edge nodes.

---
<div align="center">
  <i>Developed for Final Year Research Project.</i>
</div>
