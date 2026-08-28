import os
import io
from app.services.pfce_engine import PFCEEngine
from app.services.crypto_service import CryptoService

def test_pfce():
    engine = PFCEEngine(min_chunk_size_mb=1, max_chunk_size_mb=2)
    
    file_content = b"Hello, PFCE. " * 1000
    file_stream = io.BytesIO(file_content)
    
    package_path = "test_package.pfce"
    receiver_id = 888
    
    # Ensure receiver keys
    CryptoService.ensure_user_keypair(receiver_id)
    
    print("Testing upload...")
    result = engine.process_upload(
        file_stream=file_stream,
        receiver_id=receiver_id,
        stored_name_prefix="test_pfce",
        classification="Normal",
        pfce_package_path=package_path
    )
    
    print(f"Metadata generated. Package saved to {result.pfce_package_path}")
    assert os.path.exists(package_path)
    
    print("Testing download...")
    reassembled = bytearray()
    for chunk in engine.process_download_stream(package_path, receiver_id):
        reassembled.extend(chunk)
        
    assert bytes(reassembled) == file_content
    print("Download passed! Reassembly successful.")
    
    if os.path.exists(package_path):
        os.remove(package_path)

if __name__ == "__main__":
    test_pfce()
