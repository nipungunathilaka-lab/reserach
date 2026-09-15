import requests
import io
import hashlib

def simulate():
    url = "http://localhost:8000/internal/crypto/encrypt"
    
    file_content = b"Hello, World!"
    actual_hash = hashlib.sha256(file_content).hexdigest()
    
    files = {
        'file': ('test.txt', io.BytesIO(file_content), 'text/plain')
    }
    
    data = {
        'sender_id': '64b1f...sender',
        'receiver_id': '64b1f...receiver',
        'classification': 'standard',
        'transfers_last_hour': 0,
        'mfa_failed_attempts': 0,
        'failed_login_attempts': 0,
        'transfer_id': 'upload-123',
        'client_signature': 'test-sig',
        'signed_payload_version': 'UPCE-TRANSFER-SIGNATURE-V1',
        'client_nonce': 'test-nonce',
        'original_file_sha256': actual_hash,
        'issued_at': '2026-09-11T16:30:20.123Z',
        'sender_public_key_spki': 'test-spki'
    }
    
    res = requests.post(url, files=files, data=data)
    print("Status:", res.status_code)
    print("Response:", res.text)

if __name__ == "__main__":
    simulate()
