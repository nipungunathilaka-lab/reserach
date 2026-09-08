import os
import io
import shutil
from app.services.pfce_engine import PFCEEngine
from app.services.crypto_service import CryptoService

def test_pfce_stream():
    engine = PFCEEngine()
    
    # Create dummy data
    data = b"Streaming PFCE test data! " * 1024 * 100 # ~2.6 MB
    file_stream = io.BytesIO(data)
    
    package_path = "test_stream.pfce"
    receiver_id = 999
    
    # Ensure receiver has actual keys
    CryptoService.ensure_user_keypair(receiver_id)
    
    print("Testing stream upload...")
    result = engine.process_upload(
        file_stream=file_stream, 
        receiver_id=receiver_id, 
        stored_name_prefix="test_pfce_stream", 
        classification="Sensitive", 
        pfce_package_path=package_path
    )
    
    print(f"Package saved to {result.pfce_package_path} in {result.execution_time_seconds:.2f}s")
    assert os.path.exists(package_path)
    
    print("Testing stream download...")
    reassembled_data = bytearray()
    
    for chunk in engine.process_download_stream(package_path, receiver_id):
        reassembled_data.extend(chunk)
        
    assert bytes(reassembled_data) == data
    print("Stream download successful! Data matches exactly.")
    
    # Cleanup
    if os.path.exists(package_path):
        os.remove(package_path)

if __name__ == "__main__":
    test_pfce_stream()
