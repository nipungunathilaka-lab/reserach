import os
import time
import requests
import statistics
import shutil

# 1. Constants for configuration
SIZES_TO_TEST = [
    1 * 1024 * 1024,      # 1MB
    10 * 1024 * 1024,     # 10MB
    50 * 1024 * 1024,     # 50MB
    100 * 1024 * 1024,    # 100MB
    1024 * 1024 * 1024    # 1GB
]
ITERATIONS = 5
UPLOAD_ENDPOINT = "http://localhost:5001/api/files/send"
TOKEN = "dummy_jwt_token"

def run_benchmark():
    temp_dir = "benchmark_files"
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
        
    print(f"Target Endpoint: {UPLOAD_ENDPOINT}")
    
    headers = {
        "Authorization": f"Bearer {TOKEN}"
    }

    data = {
        "receiver_id": "dummy_receiver_id", 
        "receiver_email": "test@example.com",
        "classification": "standard",
        "client_signature": "mock-signature",
        "client_nonce": "mock-nonce"
    }

    for file_size in SIZES_TO_TEST:
        execution_times = []
        category_mb = file_size // (1024 * 1024)
        print(f"\n--- Starting benchmark for {category_mb}MB ---")
        
        for i in range(ITERATIONS):
            file_path = os.path.join(temp_dir, f"dummy_file_{category_mb}MB_{i}.bin")
            
            # Generate dummy file
            with open(file_path, "wb") as f:
                # Write in chunks for large files
                written = 0
                while written < file_size:
                    chunk = min(1024 * 1024 * 10, file_size - written)
                    f.write(os.urandom(chunk))
                    written += chunk
                
            print(f"Iteration {i+1}/{ITERATIONS} in progress...")
            
            with open(file_path, "rb") as f:
                files = {
                    "file": (f"dummy_file_{category_mb}MB_{i}.bin", f, "application/octet-stream")
                }
                
                start_time = time.perf_counter()
                try:
                    response = requests.post(UPLOAD_ENDPOINT, headers=headers, files=files, data=data)
                    end_time = time.perf_counter()
                    
                    latency_ms = (end_time - start_time) * 1000
                    print(f" - Completed in {latency_ms:.2f} ms (Status: {response.status_code})")
                    
                    execution_times.append(latency_ms)
                except Exception as e:
                    print(f" - Request failed: {e}")
                    
            os.remove(file_path)

        if len(execution_times) > 0:
            mean_time = statistics.mean(execution_times)
            sd_time = statistics.stdev(execution_times) if len(execution_times) > 1 else 0.0
            print(f"Final Result ({category_mb}MB Category): {mean_time:.2f} ± {sd_time:.2f} ms")
        else:
            print(f"No requests completed for {category_mb}MB category.")

    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)

if __name__ == "__main__":
    run_benchmark()
