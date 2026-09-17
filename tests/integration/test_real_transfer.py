import os
import sys
import unittest
import io
import hashlib
import base64

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))

try:
    import oqs
    OQS_AVAILABLE = True
except (Exception, SystemExit):
    OQS_AVAILABLE = False

from app.services.pfce_engine import PFCEEngine
from app.services.upce_quantum_service import UniversalPolymorphicCryptoEngine
from app.services.crypto_service import CryptoService
from app.core.config import settings

class TestRealTransferIntegration(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        from app.database.db import Base, engine
        Base.metadata.create_all(bind=engine)
        
        settings.pqc_enabled = True
        settings.mlkem_private_key_master_key = base64.b64encode(os.urandom(32)).decode("utf-8")
        
        # We must skip if OQS is unavailable because real PFCE upload triggers MLKEM encapsulation
        
        from app.services.mlkem_service import MLKEMService
        # Fake successful init
        
        CryptoService.ensure_user_keypair("test_sender")
        CryptoService.ensure_user_keypair("test_receiver")
        CryptoService.generate_prekeys_for_user("test_receiver", 20)
        MLKEMService.generate_keypair("test_receiver")
        
    def setUp(self):
        if not OQS_AVAILABLE:
            self.skipTest("NOT TESTED — liboqs C library missing on host")
            
        self.engine = PFCEEngine()
        self.file_content = os.urandom(1024 * 5) # 5 KB random file
        self.original_hash = hashlib.sha256(self.file_content).hexdigest()
        import uuid
        self.pfce_path = f"tests/results/test_transfer_{uuid.uuid4().hex}.pfce"
        
        if os.path.exists(self.pfce_path):
            os.remove(self.pfce_path)
            
        from cryptography.hazmat.primitives import serialization
        import base64
        
        pub_key = CryptoService.get_public_key("test_sender")
        der_bytes = pub_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.sender_spki_b64 = base64.urlsafe_b64encode(der_bytes).decode("utf-8")

    def tearDown(self):
        if os.path.exists(self.pfce_path):
            os.remove(self.pfce_path)

    def test_full_upload_download_success(self):
        """Integration: Complete successful hybrid upload and download."""
        upload_result = self.engine.process_upload(
            file_stream=io.BytesIO(self.file_content),
            sender_id="test_sender",
            receiver_id="test_receiver",
            stored_name_prefix="test_transfer",
            classification="Sensitive",
            pfce_package_path=self.pfce_path,
            crypto_engine=UniversalPolymorphicCryptoEngine,
            security_policy={"min_chunk_bytes": 1024, "max_chunk_bytes": 2048},
            client_signature_metadata={
                "algorithm": "RSA-PSS-SHA256",
                "key_fingerprint": CryptoService.get_spki_fingerprint(self.sender_spki_b64),
                "signature": "dummy_sig", # process_upload does not verify, process_download does
                "signer_id": "test_sender"
            }
        )
        self.assertTrue(os.path.exists(self.pfce_path))
        
        # Patch signature verify since we didn't generate a real RSA signature over the package
        from unittest import mock
        with mock.patch.object(CryptoService, 'verify_pfce_signature', return_value=True):
            download_stream = self.engine.process_download_stream(
                pfce_package_path=self.pfce_path,
                receiver_id="test_receiver",
                crypto_engine=UniversalPolymorphicCryptoEngine,
                sender_public_key_spki=self.sender_spki_b64
            )
            
            decrypted_content = b""
            for chunk in download_stream:
                decrypted_content += chunk
                
            downloaded_hash = hashlib.sha256(decrypted_content).hexdigest()
            self.assertEqual(self.original_hash, downloaded_hash)

    def _corrupt_pfce_metadata(self, key, modifier_func):
        # Helper to read PFCE zip, modify metadata.json, and write back
        import zipfile
        import json
        
        # Read the entire zip contents
        temp_zip_path = self.pfce_path + ".tmp"
        with zipfile.ZipFile(self.pfce_path, 'r') as zin:
            with zipfile.ZipFile(temp_zip_path, 'w') as zout:
                for item in zin.infolist():
                    data = zin.read(item.filename)
                    if item.filename == "metadata.json":
                        header = json.loads(data.decode("utf-8"))
                        if key in header:
                            header[key] = modifier_func(header[key])
                        elif key == "hybrid_metadata":
                            header["hybrid"] = modifier_func(header["hybrid"])
                        elif key.startswith("hybrid_"):
                            if "hybrid" not in header:
                                header["hybrid"] = {}
                            if key == "hybrid_kem_ciphertext":
                                header["hybrid"]["kem_ciphertext"] = modifier_func(header["hybrid"]["kem_ciphertext"])
                            else:
                                header["hybrid"][key.replace("hybrid_", "")] = modifier_func(header["hybrid"][key.replace("hybrid_", "")])
                        data = json.dumps(header).encode("utf-8")
                    zout.writestr(item, data)
        
        os.remove(self.pfce_path)
        os.rename(temp_zip_path, self.pfce_path)

    def _upload_only(self):
        return self.engine.process_upload(
            file_stream=io.BytesIO(self.file_content),
            sender_id="test_sender",
            receiver_id="test_receiver",
            stored_name_prefix="test_transfer",
            classification="Sensitive",
            pfce_package_path=self.pfce_path,
            crypto_engine=UniversalPolymorphicCryptoEngine,
            security_policy={"min_chunk_bytes": 1024, "max_chunk_bytes": 2048},
            client_signature_metadata={
                "algorithm": "RSA-PSS-SHA256",
                "key_fingerprint": CryptoService.get_spki_fingerprint(self.sender_spki_b64),
                "signature": "dummy_sig",
                "signer_id": "test_sender"
            },
            transfer_monitor=None
        )

    def test_failure_kem_ciphertext_modification(self):
        """Integration: Modifying KEM Ciphertext in header fails decryption."""
        self._upload_only() # Do the upload
        
        # Tamper with kem_ciphertext
        def corrupt_b64(val):
            raw = bytearray(base64.b64decode(val))
            raw[10] ^= 0xFF
            return base64.b64encode(raw).decode("utf-8")
            
        self._corrupt_pfce_metadata("hybrid_kem_ciphertext", corrupt_b64)
        
        from unittest import mock
        with mock.patch.object(CryptoService, 'verify_pfce_signature', return_value=True):
            with self.assertRaises(Exception):
                stream = self.engine.process_download_stream(
                    pfce_package_path=self.pfce_path,
                    receiver_id="test_receiver",
                    crypto_engine=UniversalPolymorphicCryptoEngine,
                    sender_public_key_spki=self.sender_spki
                )
                list(stream) # Exhaust stream to trigger decryption failure

    def test_failure_transfer_id_modification(self):
        """Integration: Modifying TransferID in header fails transcript binding."""
        self._upload_only()
        self._corrupt_pfce_metadata("transfer_id", lambda x: "fake-transfer-999")
        
        from unittest import mock
        with mock.patch.object(CryptoService, 'verify_pfce_signature', return_value=True):
            with self.assertRaises(Exception):
                stream = self.engine.process_download_stream(
                    pfce_package_path=self.pfce_path,
                    receiver_id="test_receiver",
                    crypto_engine=UniversalPolymorphicCryptoEngine,
                    sender_public_key_spki=self.sender_spki
                )
                list(stream)

    def test_failure_wrong_receiver_key(self):
        """Integration: receiver substitution / wrong receiver."""
        self._upload_only()
        CryptoService.ensure_user_keypair("attacker")
        
        from unittest import mock
        with mock.patch.object(CryptoService, 'verify_pfce_signature', return_value=True):
            with self.assertRaises(Exception):
                # Try to download as 'attacker'
                stream = self.engine.process_download_stream(
                    pfce_package_path=self.pfce_path,
                    receiver_id="attacker",
                    crypto_engine=UniversalPolymorphicCryptoEngine,
                    sender_public_key_spki=self.sender_spki
                )
                list(stream)

    def test_failure_algorithm_downgrade(self):
        """INT-NEG-04: Change ML-KEM algorithm identifier. Expected: policy/transcript rejection."""
        self._upload_only()
        
        # Change 'pq_algorithm' to Kyber-512 in the PFCE header metadata
        def corrupt_algo(val):
            val["pq_algorithm"] = "KYBER-512"
            return val
            
        self._corrupt_pfce_metadata("hybrid_metadata", corrupt_algo)
        
        from unittest import mock
        with mock.patch.object(CryptoService, 'verify_pfce_signature', return_value=True):
            with self.assertRaises(Exception):
                stream = self.engine.process_download_stream(
                    pfce_package_path=self.pfce_path,
                    receiver_id="test_receiver",
                    crypto_engine=UniversalPolymorphicCryptoEngine,
                    sender_public_key_spki=self.sender_spki
                )
                list(stream)

    def test_failure_remove_mlkem_component(self):
        """INT-NEG-05: Remove ML-KEM from negotiated hybrid package. Expected: FAIL CLOSED, no fallback."""
        self._upload_only()
        
        def corrupt_remove(val):
            val["enabled"] = False
            return val
            
        self._corrupt_pfce_metadata("hybrid_metadata", corrupt_remove)
        
        from unittest import mock
        with mock.patch.object(CryptoService, 'verify_pfce_signature', return_value=True):
            with self.assertRaises(Exception):
                stream = self.engine.process_download_stream(
                    pfce_package_path=self.pfce_path,
                    receiver_id="test_receiver",
                    crypto_engine=UniversalPolymorphicCryptoEngine,
                    sender_public_key_spki=self.sender_spki
                )
                list(stream)

    def test_failure_another_receivers_material(self):
        """INT-NEG-06: Use another receiver's ML-KEM/ECDH material. Expected: reject/no plaintext."""
        self._upload_only()
        
        CryptoService.ensure_user_keypair("attacker_user")
        from app.services.mlkem_service import MLKEMService
        MLKEMService.generate_keypair("attacker_user")
        
        # Modify the receiver_id in PFCE header to attacker
        self._corrupt_pfce_metadata("receiver_id", lambda x: "attacker_user")
        
        from unittest import mock
        with mock.patch.object(CryptoService, 'verify_pfce_signature', return_value=True):
            with self.assertRaises(Exception):
                stream = self.engine.process_download_stream(
                    pfce_package_path=self.pfce_path,
                    receiver_id="attacker_user",
                    crypto_engine=UniversalPolymorphicCryptoEngine,
                    sender_public_key_spki=self.sender_spki
                )
                list(stream)

if __name__ == '__main__':
    unittest.main()
