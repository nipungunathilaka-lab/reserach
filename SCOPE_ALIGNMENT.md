# Proposal Scope Alignment

## Included in this project

- React frontend
- FastAPI backend
- SQLite database
- AES-256-GCM file encryption
- RSA-2048 OAEP key protection
- ECDH P-256 derived key wrapping/session metadata
- SHA-256 file integrity verification
- OTP-based multi-factor authentication with hashed OTP, expiry, resend cooldown, failed attempt control and alerting
- Strengthened AI anomaly detection for suspicious transfers, risky file types, transfer velocity, MFA failures and login patterns
- Blockchain-inspired tamper-evident audit logging
- Admin/user role management and monitoring
- Test data and system execution data
- Wireshark/network observation as evaluation evidence only

## Removed from the project scope

- Cloud deployment
- Digital signatures
- Python GUI / Tkinter
- Full blockchain network
- Mobile application
- Biometric authentication
- Production-scale deployment

## Correct title

```text
AI-Enhanced Secure File Transfer System with Hybrid Cryptography, Multi-Factor Authentication, AI Anomaly Detection and Blockchain-Inspired Audit Logging
```

## Correct system description

This project implements a web-based AI-enhanced secure file transfer prototype using React.js, FastAPI, and SQLite. It integrates AES-256-GCM encryption, RSA-2048 key protection, ECDH-based secure key exchange metadata, SHA-256 integrity verification, OTP-based multi-factor authentication with hashed OTP, expiry, resend cooldown, failed attempt control and alerting, AI anomaly detection, and blockchain-inspired tamper-evident audit logging. Cloud deployment, digital signatures, Python Tkinter GUI, mobile application development, biometric authentication, and full blockchain network integration are outside the scope of this project.


## Strengthened areas

The final cleaned system is stronger than a basic prototype because it now includes failed-password account lockout, local API rate limiting, MFA resend limits, expanded AI behavioural features, risky file-extension detection, login/MFA security alerts, and stronger real-data training support.
