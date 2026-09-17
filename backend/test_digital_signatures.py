import pytest
pytestmark = [pytest.mark.unit]
import os
import io
import json
import zipfile
import pytest
import shutil
import tempfile
import base64
import hashlib
from datetime import datetime

os.environ["UPCE_REQUIRE_TEE"] = "false"

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from app.services.crypto_service import CryptoService
from app.services.pfce_engine import PFCEEngine

@pytest.fixture
def setup_users():
    sender_id = "test_sender_99"
    receiver_id = "test_receiver_99"
    CryptoService.ensure_user_keypair(receiver_id)
    return sender_id, receiver_id

@pytest.fixture
def client_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    spki_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    spki_b64 = base64.b64encode(spki_der).decode("utf-8")
    return private_key, public_key, spki_b64

@pytest.fixture
def pfce_engine():
    return PFCEEngine()

def generate_client_signature_metadata(private_key, spki_b64, sender_id, receiver_id, transfer_id, file_content, nonce):
    file_sha256 = hashlib.sha256(file_content).hexdigest()
    file_size = len(file_content)
    issued_at = datetime.utcnow().isoformat()
    
    canonical_payload = (
        f"UPCE-TRANSFER-SIGNATURE-V1\n"
        f"transfer_id={transfer_id}\n"
        f"sender_id={sender_id}\n"
        f"receiver_id={receiver_id}\n"
        f"file_sha256={file_sha256}\n"
        f"file_size={file_size}\n"
        f"issued_at={issued_at}\n"
        f"nonce={nonce}"
    ).encode("utf-8")
    
    signature = private_key.sign(
        canonical_payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=32
        ),
        hashes.SHA256()
    )
    
    return {
        "algorithm": "RSA-PSS-SHA256",
        "version": "UPCE-TRANSFER-SIGNATURE-V1",
        "signer_id": sender_id,
        "key_fingerprint": CryptoService.get_spki_fingerprint(spki_b64),
        "signature": base64.b64encode(signature).decode("utf-8"),
        "original_file_sha256": file_sha256,
        "signed_at": issued_at,
        "nonce": nonce,
        "transfer_id": transfer_id,
        "file_size": file_size,
        "verification_status": "VERIFIED"
    }

def test_valid_signature_flow(setup_users, client_keypair, pfce_engine):
    sender_id, receiver_id = setup_users
    private_key, _, spki_b64 = client_keypair
    
    file_content = b"This is a test file for digital signature verification."
    file_stream = io.BytesIO(file_content)
    transfer_id = "test_upload_id_123"
    
    temp_dir = tempfile.mkdtemp()
    pfce_path = os.path.join(temp_dir, f"{transfer_id}_test_file.pfce")
    
    sig_metadata = generate_client_signature_metadata(
        private_key, spki_b64, sender_id, receiver_id, transfer_id, file_content, "test_nonce"
    )
    
    try:
        # Create PFCE package (embeds signature)
        result = pfce_engine.process_upload(
            file_stream=file_stream,
            sender_id=sender_id,
            receiver_id=receiver_id,
            stored_name_prefix=f"{transfer_id}_test_file",
            classification="Standard",
            pfce_package_path=pfce_path,
            client_signature_metadata=sig_metadata
        )
        
        # Verify PFCE package can be read (verifies signature)
        chunks = list(pfce_engine.process_download_stream(pfce_path, receiver_id, sender_public_key_spki=spki_b64))
        decrypted_content = b"".join(chunks)
        
        assert decrypted_content == file_content
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def test_signature_missing(setup_users, client_keypair, pfce_engine):
    sender_id, receiver_id = setup_users
    _, _, spki_b64 = client_keypair
    file_content = b"Test file content"
    file_stream = io.BytesIO(file_content)
    transfer_id = "test_upload_id_missing"
    
    temp_dir = tempfile.mkdtemp()
    pfce_path = os.path.join(temp_dir, f"{transfer_id}_test_file.pfce")
    tampered_pfce_path = os.path.join(temp_dir, f"{transfer_id}_tampered.pfce")
    
    # Missing signature metadata entirely
    sig_metadata = {}
    
    try:
        pfce_engine.process_upload(
            file_stream=file_stream,
            sender_id=sender_id,
            receiver_id=receiver_id,
            stored_name_prefix=f"{transfer_id}_test_file",
            classification="Standard",
            pfce_package_path=pfce_path,
            client_signature_metadata=sig_metadata
        )
        
        # Verification should fail
        with pytest.raises(ValueError, match="Digital signature missing"):
            list(pfce_engine.process_download_stream(pfce_path, receiver_id, sender_public_key_spki=spki_b64))
            
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def test_signature_modified(setup_users, client_keypair, pfce_engine):
    sender_id, receiver_id = setup_users
    private_key, _, spki_b64 = client_keypair
    file_content = b"Test file content"
    file_stream = io.BytesIO(file_content)
    transfer_id = "test_upload_id_mod"
    
    temp_dir = tempfile.mkdtemp()
    pfce_path = os.path.join(temp_dir, f"{transfer_id}_test_file.pfce")
    tampered_pfce_path = os.path.join(temp_dir, f"{transfer_id}_tampered.pfce")
    
    sig_metadata = generate_client_signature_metadata(
        private_key, spki_b64, sender_id, receiver_id, transfer_id, file_content, "nonce"
    )
    
    try:
        pfce_engine.process_upload(
            file_stream=file_stream,
            sender_id=sender_id,
            receiver_id=receiver_id,
            stored_name_prefix=f"{transfer_id}_test_file",
            classification="Standard",
            pfce_package_path=pfce_path,
            client_signature_metadata=sig_metadata
        )
        
        # Unzip, modify signature, re-zip
        extract_dir = os.path.join(temp_dir, "extract")
        with zipfile.ZipFile(pfce_path, 'r') as zipf:
            zipf.extractall(extract_dir)
        
        metadata_path = os.path.join(extract_dir, "metadata.json")
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        # Modify the base64 signature slightly
        sig_val = metadata["signature"]["signature"]
        sig_bytes = bytearray(base64.b64decode(sig_val))
        sig_bytes[0] ^= 0xFF
        metadata["signature"]["signature"] = base64.b64encode(sig_bytes).decode('utf-8')
        
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f)
            
        with zipfile.ZipFile(tampered_pfce_path, 'w') as zipf:
            for root, _, files in os.walk(extract_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, extract_dir)
                    zipf.write(file_path, arcname=arcname)
                    
        # Verification should fail
        with pytest.raises(ValueError, match="Invalid RSA-PSS signature"):
            list(pfce_engine.process_download_stream(tampered_pfce_path, receiver_id, sender_public_key_spki=spki_b64))
            
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def test_wrong_trusted_public_key(setup_users, client_keypair, pfce_engine):
    sender_id, receiver_id = setup_users
    private_key, _, spki_b64 = client_keypair
    
    # generate attacker key
    att_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    att_public_key = att_private_key.public_key()
    att_spki_der = att_public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    att_spki_b64 = base64.b64encode(att_spki_der).decode("utf-8")
    
    file_content = b"Test file content"
    file_stream = io.BytesIO(file_content)
    transfer_id = "test_upload_id_wrong_key"
    temp_dir = tempfile.mkdtemp()
    pfce_path = os.path.join(temp_dir, f"{transfer_id}_test_file.pfce")
    
    # Sign with attacker key but pass sender_id
    sig_metadata = generate_client_signature_metadata(
        att_private_key, att_spki_b64, sender_id, receiver_id, transfer_id, file_content, "nonce"
    )
    
    try:
        pfce_engine.process_upload(
            file_stream=file_stream, 
            sender_id=sender_id, 
            receiver_id=receiver_id, 
            stored_name_prefix=f"{transfer_id}_test_file", 
            classification="Standard", 
            pfce_package_path=pfce_path,
            client_signature_metadata=sig_metadata
        )
        
        # During download, provide the REAL sender spki, not the attacker's
        with pytest.raises(ValueError, match="Signature key fingerprint mismatch"):
            list(pfce_engine.process_download_stream(pfce_path, receiver_id, sender_public_key_spki=spki_b64))
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
