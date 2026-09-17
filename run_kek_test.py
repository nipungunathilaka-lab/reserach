import base64
import os
from tests.integration.test_real_transfer import TestRealTransferIntegration
from app.services.upce_quantum_service import UniversalPolymorphicCryptoEngine

t = TestRealTransferIntegration("test_full_upload_download_success")
t.setUpClass()
t.setUp()

from app.services.crypto_service import CryptoService
transfer_id = "test.pfce"

prekey_pub = CryptoService.claim_prekey("test_receiver", transfer_id)
init_result = UniversalPolymorphicCryptoEngine.initialize_transfer_security(
    sender_id="test_sender",
    receiver_id="test_receiver",
    policy={"min_chunk_bytes": 1024, "max_chunk_bytes": 2048},
    prekey_public_pem=prekey_pub,
    transfer_id=transfer_id
)

hybrid_meta = init_result["metadata"]
kek1 = init_result["hybrid_kek"]

prekey_priv = CryptoService.get_and_delete_prekey("test_receiver", transfer_id)

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

priv_key = serialization.load_pem_private_key(prekey_priv.encode("utf-8"), password=None)
prekey_pub_str = priv_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("utf-8")

kek2 = UniversalPolymorphicCryptoEngine.recover_transfer_security(
    sender_id="test_sender",
    receiver_id="test_receiver",
    transfer_id=transfer_id,
    metadata=hybrid_meta,
    prekey_private_pem=prekey_priv,
    prekey_public_pem=prekey_pub_str
)

print("KEK1:", kek1.memory.hex())
print("KEK2:", kek2.memory.hex())
print("MATCH:", kek1.memory.hex() == kek2.memory.hex())

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
aes_key = os.urandom(32)
nonce = os.urandom(12)

wrapped = AESGCM(kek1.memory).encrypt(nonce, aes_key, None)
try:
    unwrapped = AESGCM(kek2.memory).decrypt(nonce, wrapped, None)
    print("UNWRAP MATCH:", aes_key == unwrapped)
except Exception as e:
    print("UNWRAP FAILED:", e)

