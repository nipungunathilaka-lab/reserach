import os
import time
import uuid
import hashlib
import json
import csv
import requests

def create_dummy_file(filename, size_mb):
    size_bytes = int(size_mb * 1024 * 1024)
    with open(filename, 'wb') as f:
        f.write(os.urandom(size_bytes))
    return size_bytes

def run_test(file_path):
    url = "http://localhost:8000/internal/crypto/encrypt"
    
    with open(file_path, "rb") as f:
        content = f.read()
        sha256 = hashlib.sha256(content).hexdigest()
        
    data = {
        'sender_id': 'sender_123',
        'receiver_id': 'receiver_456',
        'classification': 'standard',
        'transfers_last_hour': '0',
        'mfa_failed_attempts': '0',
        'failed_login_attempts': '0',
        'transfer_id': 'test_transfer',
        'client_signature': '',
        'signed_payload_version': '',
        'client_nonce': '',
        'original_file_sha256': sha256,
        'issued_at': ''
    }
    
    try:
        with open(file_path, 'rb') as f_upload:
            files = {
                'file': (os.path.basename(file_path), f_upload)
            }
            response = requests.post(url, files=files, data=data)
            
            if response.status_code == 200:
                return True, response.json()
            else:
                print(f"Error: {response.status_code} - {response.text}")
                return False, None
    except Exception as e:
        print(f"Connection error: {e}")
        return False, None

def main():
    sizes_mb = [1, 5, 10]
    results = []
    
    print("Running TC-08 and TC-09 Performance Telemetry Tests")
    
    os.makedirs('tests/results', exist_ok=True)
    
    for size in sizes_mb:
        filename = f"tc08_test_{size}MB.bin"
        print(f"\nCreating {filename}...")
        file_size = create_dummy_file(filename, size)
        
        # TC-09 wants 3 runs per size
        for run in range(3):
            print(f"Run {run+1} for {size} MB...")
            
            success, data = run_test(filename)
            
            if success:
                res = {
                    "test_case": "TC-08" if run == 0 else "TC-09",
                    "timestamp": time.time(),
                    "file_name": filename,
                    "file_size_bytes": file_size,
                    "file_size_mb": size,
                    "execution_time_ms": data.get("execution_time_ms", 0),
                    "cpu_usage_percent": data.get("cpu_usage_percent", 0),
                    "processing_throughput_mb_s": data.get("processing_throughput_mb_s", 0),
                    "processing_bandwidth_mbps": data.get("processing_bandwidth_mbps", 0),
                    "result": "success"
                }
                results.append(res)
            else:
                res = {
                    "test_case": "TC-08" if run == 0 else "TC-09",
                    "timestamp": time.time(),
                    "file_name": filename,
                    "file_size_bytes": file_size,
                    "file_size_mb": size,
                    "execution_time_ms": 0,
                    "cpu_usage_percent": 0,
                    "processing_throughput_mb_s": 0,
                    "processing_bandwidth_mbps": 0,
                    "result": "failed"
                }
                results.append(res)
                
            time.sleep(1) # cool down
            
        os.remove(filename)

    csv_file = 'tests/results/performance_telemetry_results.csv'
    with open(csv_file, 'w', newline='') as csvfile:
        fieldnames = ["test_case", "timestamp", "file_name", "file_size_bytes", "file_size_mb", 
                      "execution_time_ms", "cpu_usage_percent", "processing_throughput_mb_s", 
                      "processing_bandwidth_mbps", "result"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for r in results:
            writer.writerow(r)
            
    print(f"\nTests completed. Results saved to {csv_file}")
    
    with open('tests/results/performance_telemetry_results.json', 'w') as jsonfile:
        json.dump(results, jsonfile, indent=4)

if __name__ == "__main__":
    main()
