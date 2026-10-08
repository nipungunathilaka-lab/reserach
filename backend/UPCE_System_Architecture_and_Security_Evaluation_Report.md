# System Architecture and Security Evaluation Report
**Project Name:** UPCE (Universal Polymorphic Cryptographic Engine)
**Context:** Final Year Undergraduate Research Project

## 1. Executive Summary
This report presents a comprehensive architectural and security evaluation of the Universal Polymorphic Cryptographic Engine (UPCE). UPCE is designed as a decoupled, zero-trust secure file transfer engine, providing robust defenses against modern and emerging cryptographic threats. This report details the system's structural components, core security mechanisms, internal hardening strategies, and experimental performance results based on rigorous empirical testing.

## 2. System Overview
UPCE operates on a strictly decoupled, zero-trust architectural paradigm. The application layers are modularized to ensure separation of concerns and defense-in-depth:

*   **Frontend Interface:** Developed using **React/Vite**, providing the user-facing interaction layer.
*   **API Gateway & Identity Management:** Powered by **Node.js/Express**. This component is responsible for TOTP-based Multi-Factor Authentication (MFA) and utilizes **MongoDB** for managing file metadata and user records.
*   **Security Engine:** Implemented in **Python FastAPI**. This core layer orchestrates cryptographic operations and threat detection, utilizing **SQLite** for managing internal state.
*   **Audit Layer:** Backed by **Hyperledger Besu**, a permissioned blockchain utilizing a **QBFT** (Quorum Byzantine Fault Tolerance) consensus mechanism.

**Deployment Strategy:** 
The system utilizes a host-level deployment model (explicitly avoiding Docker). To achieve strict internal isolation, all services and communication ports are exclusively bound to the local loopback interface (`127.0.0.1`).

## 3. Core Security Mechanisms

### 3.1. Polymorphic Encryption (PFCE)
UPCE employs classification-aware streaming chunking for file encryption. For enhanced crypto-agility, the engine implements polymorphic encryption, protecting file fragments using alternating symmetric ciphers: **AES-256-GCM** and **ChaCha20-Poly1305**.

### 3.2. Hybrid Post-Quantum Key Establishment
To mitigate "harvest now, decrypt later" strategies, the symmetric keys generated per-fragment are wrapped using a hybrid key encapsulation mechanism. This combines classical **ECDH** with the post-quantum **ML-KEM-768 (Kyber)** algorithm. Digital signatures for authentication and non-repudiation continue to utilize classical **RSA-PSS**.

### 3.3. AI Behavioral Threat Detection
The system integrates an unsupervised **Isolation Forest** machine learning model to detect anomalous transfer behaviors.
*   **Model Parameters:** Engineered with `n_estimators=350` and a dynamically adjusting `contamination` parameter bounded between `[0.01-0.49]`.
*   **Feature Set:** The model evaluates four primary features: file size, hour of transfer, transfer rate, and prior MFA failures.
*   **Privacy Preservation:** A privacy-aware Laplace noise injection layer is applied to the feature data (configured with per-query `ε=0.5` and total `ε=10.0`).
*   **Enforcement:** Transfers generating an anomaly score at or exceeding the hard block threshold of `≥ 0.40` are automatically terminated.

### 3.4. Blockchain Audit Ledger
A cryptographic, hash-chained ledger ensures the immutability of security-relevant events (e.g., `MALWARE_BLOCKED`). The ledger operates on a **fail-closed mechanism**; if the blockchain service is unreachable or down, all file transfers are hard-blocked to prevent unaudited operations.

## 4. Internal Trust & Network Hardening (Recent Updates)
Following recent security audits, several hardening measures have been applied to the internal network and API architecture:

*   **Zero-Trust Internal API:** Communication between the Node.js API Gateway and the Python FastAPI Security Engine is authenticated using short-lived (60 seconds) signed JWTs.
*   **FastAPI Statefulness:** Contrary to traditional stateless API designs, the FastAPI engine acts as a stateful component. It is responsible for actively managing persistent security states, including blockchain anchors, AI behavioral baselines, and Client keys.
*   **Cryptographic Identity:** The system enforces a **Trust On First Use (TOFU)** key pinning model to establish internal identity and aggressively prevent public-key substitution attacks.
*   **Network Monitoring:** A monitoring daemon utilizing **Scapy** analyzes the local loopback interface for TCP resets and sequence gaps. This serves strictly as a heuristic anomaly indicator, rather than absolute proof of a Man-in-the-Middle (MITM) attack.
*   **RPC Isolation:** The Hyperledger Besu RPC interface (default port `8545`) has been hard-bound to `127.0.0.1`, entirely preventing external exposure to the ledger's control plane.

## 5. Experimental Evaluation

Rigorous evaluation was conducted to validate the system's functional correctness, security resilience, and performance characteristics.

*   **Test Environment:** Testing was executed on a Windows 11 host equipped with a 12-core Intel i5 processor and 8GB of RAM.
*   **Functional & Security Validation:** A suite of 10 defined Functional and Security Test Cases (TC01 through TC10) were executed. The system achieved a 100% pass rate across all cases.
*   **Performance & Throughput:** The cryptographic engine scales dynamically based on payload size. Observed throughput ranges from **0.44 MB/s** (for 1MB files) up to a peak of **10.00 MB/s** (for 25MB files). The engine also successfully completed a sustained transfer of a 3GB real-world file without failure.
*   **Resource Utilization:** System memory usage remained flat and strictly bounded between **7.09 GB and 7.39 GB** throughout the testing lifecycle (this metric is inclusive of the development environment overhead).
*   **Concurrency:** The architecture was stress-tested and successfully supported up to **50 concurrent** operations without degradation of the core security constraints.

***
*End of Report*
