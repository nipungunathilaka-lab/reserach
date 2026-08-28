# Testing Checklist

Use this checklist for project demonstration and proposal evaluation evidence.

## 1. Authentication + MFA

- Open frontend at `http://localhost:5173`.
- Login as `admin@secureft.com / admin12345`.
- Confirm the system asks for a 6-digit OTP.
- Check backend terminal or `backend/app/storage/mailbox/otp_emails.log` for the OTP.
- Enter wrong password several times and confirm security alert/account lockout behaviour.
- Enter wrong OTP several times and confirm attempt count error appears.
- Confirm repeated failed MFA attempts create an AI/Login alert.
- Click resend code and confirm cooldown/resend limit behaviour.
- Confirm a new OTP is generated after cooldown.
- Enter correct OTP and confirm dashboard opens.

Expected result: JWT session is created only after successful MFA verification.

## 2. Admin user management

- Login as admin.
- Open Users page.
- Create a new normal user.
- Confirm the user appears in the table/mobile cards.
- Change a user's role between `user` and `admin`.

Expected result: only admin can access the Users page and `/api/users` endpoint.

## 3. Secure file transfer

- Login as Alice.
- Send a file to Bob.
- Confirm result shows:
  - AES-256-GCM encryption
  - RSA-2048 key protection
  - ECDH metadata
  - SHA-256 hash
  - AI detection result
  - blockchain block hash

Expected result: transfer is saved and audit block is created.

## 4. Receiver decrypt/download

- Login as Bob.
- Open Received Files.
- Download/decrypt the file.
- Confirm integrity status becomes `verified`.

Expected result: receiver can decrypt only files sent to them. The backend streams the decrypted file and does not keep a permanent plaintext copy.

## 5. Access control

- Try to open Users page as normal user.
- Try to download another user's file by manually changing transfer ID.

Expected result: backend returns 403 Forbidden.

## 6. AI anomaly detection

- Send a large file, a risky extension such as `.ps1`, a night-time transfer, or several files quickly.
- Enter wrong MFA codes several times and failed passwords several times.
- Open AI Alerts page.

Expected result: suspicious transfer behaviour or repeated MFA failures create medium/high AI alerts.

## 7. Blockchain audit verification

- Open Blockchain Logs page.
- Click Verify Chain.

Expected result: chain returns valid if logs are not modified.

Optional tamper test:

- Open SQLite Viewer.
- Modify a transfer `original_hash` value.
- Click Verify Chain again.

Expected result: chain becomes invalid because the transfer data hash no longer matches the block.

## 8. SQLite database verification

Open `backend/secure_file_transfer.db` with SQLite Viewer and check:

- users
- mfa_challenges
- transfers
- ai_alerts
- blockchain_logs

## 9. Responsive frontend check

Test the UI using browser DevTools:

- Mobile width around 390px
- Tablet width around 768px
- Desktop width around 1366px

Expected result: navigation, forms, dashboards, logs, AI alerts, blockchain logs, and users page remain usable on mobile and desktop.

## 10. Optional Wireshark evidence

- Start Wireshark.
- Capture traffic on loopback/local network interface.
- Perform login and file transfer.
- Use screenshots as evaluation evidence.

Note: Wireshark is evaluation evidence only; it is not a system feature.
