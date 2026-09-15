import os
import time
import uuid
import hashlib
import json
import csv
import psutil
import requests
import threading
from pathlib import Path

# Try to import requests_toolbelt for proper streaming of multipart/form-data
try:
    from requests_toolbelt import MultipartEncoder
    HAS_TOOLBELT = True
except ImportError:
    HAS_TOOLBELT = False

class MemoryMonitor(threading.Thread):
    def __init__(self, pid, interval=0.1):
        super().__init__()
        self.pid = pid
        self.interval = interval
        self.running = True
        self.peak_rss = 0
        try:
            self.process = psutil.Process(self.pid)
            self.baseline_rss = self.process.memory_info().rss
            self.peak_rss = self.baseline_rss
        except Exception as e:
            self.process = None
            self.baseline_rss = 0

    def run(self):
        if not self.process:
            return
        while self.running:
            try:
                current_rss = self.process.memory_info().rss
                if current_rss > self.peak_rss:
                    self.peak_rss = current_rss
            except Exception:
                pass
            time.sleep(self.interval)

    def stop(self):
        self.running = False
        
def find_backend_pid(port=8000):
    for conn in psutil.net_connections():
        if conn.laddr.port == port and conn.status == 'LISTEN':
            return conn.pid
    return None

def create_dummy_file(filename, size_mb):
    size_bytes = int(size_mb * 1024 * 1024)
    chunk_size = 10 * 1024 * 1024
    bytes_written = 0
    with open(filename, 'wb') as f:
        while bytes_written < size_bytes:
            write_size = min(chunk_size, size_bytes - bytes_written)
            f.write(os.urandom(write_size))
            bytes_written += write_size
    return size_bytes

def calculate_sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def run_test_streamed(file_path, file_size, pid):
    url = "http://localhost:8000/internal/crypto/encrypt"
    
    sha256 = calculate_sha256(file_path)
    
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
    
    monitor = MemoryMonitor(pid, interval=0.1)
    if pid:
        monitor.start()

    start_time = time.time()
    response = None
    try:
        if HAS_TOOLBELT:
            fields = {k: str(v) for k, v in data.items()}
            fields['file'] = (os.path.basename(file_path), open(file_path, 'rb'), 'application/octet-stream')
            m = MultipartEncoder(fields=fields)
            response = requests.post(url, data=m, headers={'Content-Type': m.content_type})
        else:
            with open(file_path, 'rb') as f_upload:
                files = {'file': (os.path.basename(file_path), f_upload)}
                response = requests.post(url, files=files, data=data)
                
        end_time = time.time()
    except Exception as e:
        end_time = time.time()
        print(f"Connection error: {e}")
    finally:
        if pid:
            monitor.stop()
            monitor.join()

    duration = end_time - start_time
    
    try:
        final_rss = psutil.Process(pid).memory_info().rss if pid else 0
    except:
        final_rss = 0

    if response and response.status_code == 200:
        return True, response.json(), duration, monitor.baseline_rss, monitor.peak_rss, final_rss
    else:
        if response:
            print(f"Error: {response.status_code} - {response.text}")
        return False, None, duration, monitor.baseline_rss, monitor.peak_rss, final_rss

def main():
    sizes_mb = [100, 500, 1000, 2000, 5000, 10000]
    
    disk_usage = psutil.disk_usage('.')
    free_mb = disk_usage.free / (1024 * 1024)
    print(f"Free disk space: {free_mb:.2f} MB")
    
    pid = find_backend_pid(8000)
    if not pid:
        print("Warning: Backend process not found on port 8000. Process-level memory will not be measured.")
    else:
        print(f"Found backend process PID: {pid}")

    results = []
    
    print("=" * 60)
    print("TC-09 LARGE FILE MEMORY VALIDATION TEST")
    print("=" * 60)
    
    os.makedirs('tests/results', exist_ok=True)
    
    for size in sizes_mb:
        # Require enough space for dummy file (1x) + encrypted file (approx 1x) + temp copies
        if size * 3 > free_mb:
            print(f"Skipping {size} MB test due to insufficient disk space.")
            results.append({
                "test_case": "TC-09",
                "timestamp": time.time(),
                "file_name": f"tc09_test_{size}MB.bin",
                "file_size_bytes": size * 1024 * 1024,
                "file_size_mb": size,
                "chunk_size_bytes": 1048576, # PFCE read chunk is 1MB
                "baseline_process_rss_mb": "NA",
                "peak_process_rss_mb": "NA",
                "final_process_rss_mb": "NA",
                "peak_process_delta_mb": "NA",
                "duration_seconds": "NA",
                "throughput_mb_s": "NA",
                "status": "NOT TESTED",
                "notes": "Insufficient disk space"
            })
            continue
            
        filename = f"tc09_test_{size}MB.bin"
        print(f"\nCreating {filename} ({size} MB)...")
        file_size = create_dummy_file(filename, size)
        
        print(f"Running TC-09 transfer for {size} MB...")
        success, data, duration, baseline_rss, peak_rss, final_rss = run_test_streamed(filename, file_size, pid)
        
        baseline_mb = baseline_rss / (1024 * 1024) if baseline_rss else 0
        peak_mb = peak_rss / (1024 * 1024) if peak_rss else 0
        final_mb = final_rss / (1024 * 1024) if final_rss else 0
        delta_mb = peak_mb - baseline_mb
        throughput = size / duration if duration > 0 else 0
        
        status = "PASS" if success else "FAIL"
        
        print(f"Result: {status}")
        print(f"Baseline RSS: {baseline_mb:.2f} MB")
        print(f"Peak RSS: {peak_mb:.2f} MB")
        print(f"Peak Delta: {delta_mb:.2f} MB")
        print(f"Throughput: {throughput:.2f} MB/s")
        
        res = {
            "test_case": "TC-09",
            "timestamp": time.time(),
            "file_name": filename,
            "file_size_bytes": file_size,
            "file_size_mb": size,
            "chunk_size_bytes": 1048576, # Known FastAPI/PFCE chunk
            "baseline_process_rss_mb": round(baseline_mb, 2) if baseline_mb else "NA",
            "peak_process_rss_mb": round(peak_mb, 2) if peak_mb else "NA",
            "final_process_rss_mb": round(final_mb, 2) if final_mb else "NA",
            "peak_process_delta_mb": round(delta_mb, 2) if delta_mb else "NA",
            "node_peak_rss_mb": "NA", 
            "container_baseline_mb": "NA",
            "container_peak_mb": "NA",
            "container_delta_mb": "NA",
            "host_memory_before_mb": "NA",
            "host_memory_peak_mb": "NA",
            "duration_seconds": round(duration, 2),
            "throughput_mb_s": round(throughput, 2),
            "status": status,
            "notes": ""
        }
        results.append(res)
        
        try:
            os.remove(filename)
        except:
            pass

    csv_file = 'tests/results/tc09_memory_results.csv'
    with open(csv_file, 'w', newline='') as csvfile:
        fieldnames = ["test_case", "timestamp", "file_name", "file_size_bytes", "file_size_mb", 
                      "chunk_size_bytes", "baseline_process_rss_mb", "peak_process_rss_mb", 
                      "final_process_rss_mb", "peak_process_delta_mb", "node_peak_rss_mb", 
                      "container_baseline_mb", "container_peak_mb", "container_delta_mb", 
                      "host_memory_before_mb", "host_memory_peak_mb", "duration_seconds", 
                      "throughput_mb_s", "status", "notes"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for r in results:
            writer.writerow(r)
            
    print(f"\nTests completed. Results saved to {csv_file}")
    
    with open('tests/results/tc09_memory_results.json', 'w') as jsonfile:
        json.dump(results, jsonfile, indent=4)

if __name__ == "__main__":
    if not HAS_TOOLBELT:
        print("WARNING: requests_toolbelt is not installed. python-requests may buffer the upload in RAM!")
    main()
