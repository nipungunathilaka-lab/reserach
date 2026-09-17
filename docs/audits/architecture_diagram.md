# Server-Mediated File Transfer Architecture

The following diagram explicitly models the flow of data through the AI Secure File Transfer System. It distinguishes between the transport boundaries (TLS), the trusted security boundary (FastAPI), and where data is encrypted at rest.

```mermaid
flowchart TD
    %% Entities
    Sender[Sender Browser\nCreates RSA-PSS Signature]
    Node[Node.js API Gateway\nAssembles Chunks]
    Receiver[Receiver Browser\nDownloads & Decrypts]
    Storage[(Encrypted .pfce Storage)]

    %% FastAPI Boundary
    subgraph FastAPI_Enclave [FastAPI TRUSTED SECURITY BOUNDARY]
        style FastAPI_Enclave fill:#f9f2f4,stroke:#333,stroke-width:2px,stroke-dasharray: 5 5
        
        direction TB
        Scanner[Malware Scan / ClamAV]
        AI[AI Behavioral / Data Classification]
        PFCE[PFCE Engine / UPCE Crypto]
        Audit[Blockchain Audit Logger]
        
        Scanner --> AI
        AI --> PFCE
        PFCE --> Audit
    end

    %% Data Flows
    Sender -- "HTTPS/TLS\n(PLAINTEXT FILE + SIGNATURE)" --> Node
    Node -- "Internal Network\n(PLAINTEXT FILE + SIGNATURE)" --> Scanner
    
    Audit -- "ENCRYPTED AT REST\n(PROTECTED OUTPUT)" --> Storage
    
    Storage -- "Encrypted Stream" --> PFCE_Decrypt[FastAPI Decryption]
    PFCE_Decrypt -- "HTTPS/TLS\n(PLAINTEXT FILE)" --> Receiver

    %% Annotations
    classDef boundaryLabel fill:#fbb,stroke:#f66,stroke-width:2px,color:#000,font-weight:bold;
    classDef protectedLabel fill:#bfb,stroke:#6f6,stroke-width:2px,color:#000,font-weight:bold;

    PLAINTEXT_PROCESSING_BOUNDARY:::boundaryLabel
    ENCRYPTED_AT_REST:::protectedLabel

    FastAPI_Enclave -.-> PLAINTEXT_PROCESSING_BOUNDARY
    Storage -.-> ENCRYPTED_AT_REST
```

### Explanatory Notes

- **PLAINTEXT PROCESSING BOUNDARY**: The Node.js and FastAPI services must temporarily process the raw, unencrypted bytes of the file in memory and/or temporary disk storage to perform necessary business logic (AI Classification, Malware Scanning).
- **ENCRYPTED AT REST**: Once the `PFCE Engine` encrypts the fragments and wraps the AES/ChaCha keys using ECDH or PQC, the file transitions into ciphertext. The storage volume only ever contains this ciphertext.
- **CLIENT-SIDE CRYPTOGRAPHY**: The Sender Browser performs cryptographic signing and hashing to prove origin and integrity, but does *not* encrypt the file content for confidentiality.
