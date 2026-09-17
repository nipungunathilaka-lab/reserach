# Security Evaluation Scope

The following table documents the actual security controls implemented and tested within the research prototype. The prototype does not claim complete protection against all cyberattacks. Resistance to state-actor level physical memory extraction was not established by the present evaluation. Memory analysis remains theoretically possible against unprotected deployments.

| Threat / Control              | Implemented | Tested | Evidence | Limitation |
| ----------------------------- | ----------- | ------ | -------- | ---------- |
| Authentication                | Yes         | Yes    | JWT validation, token expiry | Prototype uses mock DB or simplified MFA in some tests. |
| Authorization                 | Yes         | Yes    | Sender/receiver access checks | Scope limited to application-level roles. |
| MFA                           | Yes         | Yes    | Enforced on endpoints | - |
| File integrity                | Yes         | Yes    | SHA-256 mismatch rejection | - |
| Audit tampering               | Yes         | Yes    | Blockchain ledger, local DB hashes | Relies on consensus layer availability. |
| Malware scanning              | Yes         | Yes    | Quarantine of detected malicious bytes | Full-file scan skipped for >1GB files to prevent OOM. |
| AI anomaly detection          | Yes         | Yes    | Isolation Forest with DP | Probabilistic. Produces false positives/negatives. |
| MITM detection                | Yes         | Yes    | SPKI Fingerprint verification | Evaluates specific indicators; cannot detect all advanced MITM. |
| DDoS                          | No          | No     | -        | Out of scope for this prototype. |
| SQL/NoSQL injection           | Partially   | No     | ORM/Mongoose usage | Exhaustive injection testing not performed. |
| XSS                           | Partially   | No     | React DOM escaping | React provides baseline protection, but not exhaustively tested. |
| CSRF                          | Partially   | No     | Bearer tokens | Token storage vulnerabilities not fully evaluated. |
| Zero-days                     | No          | No     | -        | Cannot protect against unknown vulnerabilities. |
| Insider admin compromise      | Yes         | Partially | Trusted processing boundary | An admin with kernel access could dump memory before zeroization or intercept plaintext in FastAPI. |
| Side-channel attacks          | No          | No     | -        | Out of scope for this prototype. |
| Crypto implementation attacks | No          | No     | -        | Dependent on third-party cryptographic libraries. |
