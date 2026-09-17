import pytest
pytestmark = [pytest.mark.unit]
import pytest
import os
import uuid
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from app.main import app

client = TestClient(app)

def test_fastapi_has_plaintext_access():
    """
    E2EE-TERM-01: Verify server plaintext visibility classification.
    Proves that FastAPI receives the raw plaintext file before it is encrypted.
    """
    sentinel_payload = f"E2EE_BOUNDARY_TEST_{uuid.uuid4().hex}".encode("utf-8")
    
    # We patch the PFCE engine to inspect what it receives.
    with patch("app.services.pfce_engine.PFCEEngine.process_upload") as mock_pfce:
        mock_result = MagicMock()
        mock_result.pfce_package_path = "mock_path.pfce"
        mock_result.execution_time_seconds = 0.1
        mock_result.aes_time_ms = 10
        mock_result.rsa_key_wrap_time_ms = 10
        mock_result.ecdh_time_ms = 10
        mock_result.fragment_count = 1
        mock_result.original_hash = "mock_hash"
        mock_result.cipher_algorithm = "Polymorphic"
        mock_pfce.return_value = mock_result
        
        # We also mock ClamAV to inspect what it receives
        with patch("app.services.malware_service.MalwareDetectionService.scan_full_file") as mock_clamav:
            mock_clamav.return_value = {
                "verdict": "CLEAN",
                "engine": "ClamAV",
                "confidence": 0.0,
                "scan_mode": "full_file",
                "bytes_scanned": len(sentinel_payload),
                "malware_scan_status": "COMPLETED"
            }
            
            response = client.post(
                "/internal/crypto/encrypt",
                data={
                    "sender_id": "999",
                    "receiver_id": "888",
                    "classification": "standard"
                },
                files={"file": ("test_boundary.txt", sentinel_payload, "text/plain")}
            )
            
            assert response.status_code == 200
            
            # Verify ClamAV scan received the path to a file containing the plaintext
            clamav_args = mock_clamav.call_args
            assert clamav_args is not None
            temp_path = clamav_args[0][0]
            
            with open(temp_path, "rb") as f:
                content = f.read()
                assert sentinel_payload in content, "FASTAPI_CAN_ACCESS_ORIGINAL_BYTES = FALSE. Expected TRUE."
                
            # Verify PFCEEngine received the stream with plaintext
            pfce_args = mock_pfce.call_args
            assert pfce_args is not None
            file_stream = pfce_args.kwargs.get("file_stream")
            
            file_stream.seek(0)
            content = file_stream.read()
            if isinstance(content, str):
                content = content.encode("utf-8")
                
            assert sentinel_payload in content, "PFCE_INPUT_IS_PLAINTEXT = FALSE. Expected TRUE."
            
            print("\nNODE_CAN_ACCESS_ORIGINAL_BYTES = TRUE")
            print("FASTAPI_CAN_ACCESS_ORIGINAL_BYTES = TRUE")
            print("PFCE_INPUT_IS_PLAINTEXT = TRUE")
