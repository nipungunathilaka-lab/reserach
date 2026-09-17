# Thesis Corrections: Cryptographic Architecture Terminology

## 1. Terms That Must Not Be Used
Because the trusted FastAPI security engine processes plaintext for malware scanning and policy enforcement during the upload lifecycle, the following terms are scientifically inaccurate and must be explicitly struck from the thesis:

- "Strict End-to-End Encryption"
- "Zero-Knowledge File Transfer"
- "Server-Blind File Encryption"
- "The server never sees plaintext"

## 2. Approved Thesis Terminology
Replace instances of the above prohibited terms with the following scientifically accurate description:

> "The developed prototype employs a server-mediated encrypted file-transfer architecture. Client-side cryptographic signing provides sender attribution, while the internal FastAPI security engine performs malware inspection, behavioural security analysis, PFCE processing, and receiver-specific cryptographic protection. Because the trusted security engine processes plaintext during selected stages of the transfer workflow, the architecture is not classified as strict end-to-end or zero-knowledge encryption."

## 3. Viva Answers

### 30-Second Answer
"The system is not strict E2EE because the trusted FastAPI security engine processes plaintext for malware scanning and policy enforcement. Instead, it uses a server-mediated encrypted-transfer model with client-side signing and receiver-specific cryptographic protection."

### 1-Minute Answer
"While the system employs advanced cryptographic features such as hybrid PQC, ECDH forward secrecy, and RSA-PSS signatures, it operates on a server-mediated trust model rather than strict Zero-Knowledge E2EE. When a file is uploaded, the sender's browser digitally signs it, but does not encrypt the content. The plaintext is transmitted over TLS to the FastAPI security enclave, where it is scanned by ClamAV and our AI behavioral models. Only after passing these checks is the data encrypted at rest into polymorphic PFCE fragments. This design prioritizes active threat mitigation over server blindness, which is a necessary trade-off for enterprise environments requiring centralized malware inspection."
