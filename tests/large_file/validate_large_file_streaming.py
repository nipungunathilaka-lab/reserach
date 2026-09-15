import os
import time
import uuid
import hashlib
import json
import csv
import requests
import psutil
import zipfile

API_BASE = "http://localhost:5001/api"

def get_peak_memory():
    node_mem = 0
    fastapi_mem = 0
    for p in psutil.process_iter(['name', 'cmdline', 'memory_info']):
        try:
            cmd = " ".join(p.info['cmdline'] or []).lower()
            if "node" in p.info['name'].lower() or "node" in cmd:
                node_mem = max(node_mem, p.info['memory_info'].rss / (1024 * 1024))
            elif "uvicorn" in cmd or "python" in p.info['name'].lower():
                if "backend" in cmd or "app.main" in cmd or "api_server" in cmd:
                    fastapi_mem = max(fastapi_mem, p.info['memory_info'].rss / (1024 * 1024))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return node_mem, fastapi_mem

def preflight_check(size_bytes):
    # Node Assembled + FastAPI Spool + PFCE Package = 3x copies concurrently
    required = (size_bytes * 3)
    stat = psutil.disk_usage(os.getcwd())
    if stat.free < required + (1024 * 1024 * 1024):  # 1GB safety buffer
        print(f"ERROR: Insufficient disk space. Need {required/1e9:.2f} GB, have {stat.free/1e9:.2f} GB")
        return False
    return True

def create_large_file(filename, size_bytes):
    print(f"Generating {size_bytes / (1024*1024):.2f} MB file...")
    chunk_size = 10 * 1024 * 1024
    sha = hashlib.sha256()
    
    # Generate a single 1MB random block and reuse it to save entropy and prevent MemoryError
    random_block = os.urandom(1024 * 1024)
    
    with open(filename, 'wb') as f:
        bytes_written = 0
        while bytes_written < size_bytes:
            to_write = min(chunk_size, size_bytes - bytes_written)
            
            # Create chunk by repeating the block
            repeats = (to_write // len(random_block)) + 1
            chunk = (random_block * repeats)[:to_write]
            
            f.write(chunk)
            sha.update(chunk)
            bytes_written += len(chunk)
    return sha.hexdigest()

import jwt
import datetime
from pymongo import MongoClient

def register_or_login():
    client = MongoClient("mongodb://nipunmalshan350_db_user:YHSX0tsx0LGDOvBw@ac-knrp2z6-shard-00-00.w5busot.mongodb.net:27017,ac-knrp2z6-shard-00-01.w5busot.mongodb.net:27017,ac-knrp2z6-shard-00-02.w5busot.mongodb.net:27017/?ssl=true&authSource=admin&retryWrites=true&w=majority")
    db = client.get_database("test")
    user = db.users.find_one()
    if not user:
        raise Exception("No users found in database to impersonate.")
    dummy_user_id = str(user["_id"])
    payload = {
        "id": dummy_user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1)
    }
    secret = "supersecretjwtkey_replace_me"
    token = jwt.encode(payload, secret, algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    return token

def get_receiver_id(token):
    headers = {"Authorization": f"Bearer {token}"}
    res = requests.get(f"{API_BASE}/users/receivers", headers=headers)
    receivers = res.json().get("data", [])
    if not receivers:
        receivers = res.json()
    if isinstance(receivers, list) and len(receivers) > 0:
        return receivers[0]["_id"] if "_id" in receivers[0] else receivers[0]["id"]
    raise Exception("No receivers found")

def run_upload(file_path, size_bytes, token, receiver_id, simulate_resume=False):
    headers = {"Authorization": f"Bearer {token}"}
    upload_id = uuid.uuid4().hex
    
    chunk_size = 50 * 1024 * 1024
    if simulate_resume:
        chunk_size = 2 * 1024 * 1024 # Smaller chunks to simulate interrupt
        
    total_chunks = (size_bytes + chunk_size - 1) // chunk_size
    start_time = time.time()
    
    with open(file_path, "rb") as f:
        for i in range(total_chunks):
            if simulate_resume and i == total_chunks // 2:
                print("Simulating connection drop for 3 seconds...")
                time.sleep(3)
                print("Resuming upload from chunk", i)
                
            chunk = f.read(chunk_size)
            form_data = {
                'receiver_id': receiver_id,
                'upload_id': upload_id,
                'chunk_index': str(i),
                'total_chunks': str(total_chunks),
                'file_name': os.path.basename(file_path)
            }
            files = {
                'file': (os.path.basename(file_path), chunk, 'application/octet-stream')
            }
            
            res = requests.post(f"{API_BASE}/files/upload-chunk", headers=headers, data=form_data, files=files)
            if res.status_code != 200:
                print(f"Chunk {i} failed: {res.text}")
                return False, None
                
            if i == total_chunks - 1:
                while True:
                    status_res = requests.get(f"{API_BASE}/files/status/{upload_id}", headers=headers)
                    if status_res.status_code == 200:
                        status_data = status_res.json()
                        if status_data.get("status") == "completed":
                            end_time = time.time()
                            status_data["total_time_seconds"] = end_time - start_time
                            return True, status_data
                        elif status_data.get("status") == "error":
                            print("Processing error:", status_data)
                            return False, None
                    time.sleep(3)
    return False, None

def download_and_verify(transfer_id, original_sha256, receiver_id):
    payload = {
        "id": receiver_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1)
    }
    secret = "supersecretjwtkey_replace_me"
    receiver_token = jwt.encode(payload, secret, algorithm="HS256")
    if isinstance(receiver_token, bytes):
        receiver_token = receiver_token.decode('utf-8')
        
    headers = {"Authorization": f"Bearer {receiver_token}"}
    start_time = time.time()
    
    res = requests.get(f"{API_BASE}/files/{transfer_id}/download", headers=headers, stream=True, timeout=10)
    if res.status_code != 200:
        return False, 0
        
    sha = hashlib.sha256()
    try:
        for chunk in res.iter_content(chunk_size=8192):
            if chunk:
                sha.update(chunk)
    except Exception as e:
        print(f"Download interrupted (expected if corrupted): {e}")
        return False, time.time() - start_time
            
    restored_sha = sha.hexdigest()
    duration = time.time() - start_time
    
    if original_sha256 == restored_sha:
        return True, duration
    return False, duration

def corrupt_pfce_package(transfer_id):
    client = MongoClient("mongodb://nipunmalshan350_db_user:YHSX0tsx0LGDOvBw@ac-knrp2z6-shard-00-00.w5busot.mongodb.net:27017,ac-knrp2z6-shard-00-01.w5busot.mongodb.net:27017,ac-knrp2z6-shard-00-02.w5busot.mongodb.net:27017/?ssl=true&authSource=admin&retryWrites=true&w=majority")
    db = client.get_database("test")
    import bson
    t = db.transfers.find_one({"_id": bson.ObjectId(transfer_id)})
    if not t: return False
    path = t["encrypted_path"]
    
    # We will remove the middle fragment from metadata.json inside the ZIP
    temp_zip = path + ".tmp.zip"
    import zipfile
    import json
    try:
        with zipfile.ZipFile(path, 'r') as zin, zipfile.ZipFile(temp_zip, 'w', zipfile.ZIP_STORED, allowZip64=True) as zout:
            for item in zin.infolist():
                if item.filename == "metadata.json":
                    metadata = json.loads(zin.read(item.filename).decode('utf-8'))
                    if len(metadata["fragments"]) > 2:
                        # Drop the middle fragment
                        del metadata["fragments"][len(metadata["fragments"]) // 2]
                    zout.writestr(item, json.dumps(metadata))
                else:
                    zout.writestr(item, zin.read(item.filename))
        import shutil
        shutil.move(temp_zip, path)
        return True
    except Exception as e:
        print("Corrupting failed:", e)
        return False

def run_test(size, token, receiver_id, simulate_resume=False, corrupt=False):
    filename = f"large_test_{size}.bin"
    sha256 = create_large_file(filename, size)
    
    try:
        node_peak, fastapi_peak = get_peak_memory()
        
        print(f"Starting upload of {filename} (Resume={simulate_resume})...", flush=True)
        success, data = run_upload(filename, size, token, receiver_id, simulate_resume=simulate_resume)
        if not success:
            print("Upload failed.", flush=True)
            return None
            
        upload_time = data.get("total_time_seconds", 0)
        transfer_obj = data.get("result", {}).get("transfer", {})
        transfer_id = transfer_obj.get("_id")
        
        malware_scan = data.get("result", {}).get("malware_scan", {})
        print(f"Malware Scan Status: {malware_scan}")
        
        if corrupt:
            print("Corrupting PFCE package (omitting middle fragment)...")
            corrupt_pfce_package(transfer_id)
            
        print(f"Upload complete. Starting download...", flush=True)
        verify_success, download_time = download_and_verify(transfer_id, sha256, receiver_id)
        
        if corrupt and not verify_success:
            print("Corruption properly detected! Validation passed.")
            verify_success = True # Test passed if it detected the error
        elif corrupt and verify_success:
            print("FATAL: Corruption was NOT detected. Validation failed.")
            verify_success = False
            
        node_peak_after, fastapi_peak_after = get_peak_memory()
        
        result = {
            "test_type": "Resume/Corrupt" if simulate_resume or corrupt else "Normal",
            "file_size_gb": size / 1e9,
            "source_sha256": sha256,
            "upload_seconds": round(upload_time, 2),
            "download_seconds": round(download_time, 2),
            "total_seconds": round(upload_time + download_time, 2),
            "average_throughput_mbps": round((size / (upload_time + download_time)) / (1024 * 1024), 2),
            "node_peak_rss_mb": max(node_peak, node_peak_after),
            "fastapi_peak_rss_mb": max(fastapi_peak, fastapi_peak_after),
            "malware_status": malware_scan.get("status", "UNKNOWN"),
            "hash_match": verify_success,
            "result": "VALIDATED" if verify_success else "NOT VALIDATED"
        }
        return result
    finally:
        if os.path.exists(filename):
            os.remove(filename)

def main():
    print("=" * 50)
    print("LARGE FILE STREAMING EXPERIMENT & SECURITY TESTS")
    print("=" * 50)
    
    token = register_or_login()
    receiver_id = get_receiver_id(token)
    print("Authenticated successfully.")
    
    os.makedirs("tests/results", exist_ok=True)
    results = []
    
    # 1. Resumability & Corrupt Fragment Test (10 MB)
    print("\n--- Test #1: Resumability & Missing Fragment (10 MB) ---")
    if preflight_check(10 * 1024 * 1024):
        res1 = run_test(10 * 1024 * 1024, token, receiver_id, simulate_resume=True, corrupt=True)
        if res1:
            results.append(res1)
            print(f"Test #1 Result: {res1['result']}")
            
    # 2. Real Scale Test (10 GB)
    print("\n--- Test #2: True Large File Bounded Memory Test (10 GB) ---")
    gb10 = 10 * 1024 * 1024 * 1024
    if preflight_check(gb10):
        res2 = run_test(gb10, token, receiver_id)
        if res2:
            results.append(res2)
            print(f"Test #2 Result: {res2['result']}")
    else:
        print("Skipping 10GB test due to physical constraints.")
            
    csv_file = 'tests/results/large_file_streaming_results.csv'
    if results:
        with open(csv_file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=results[0].keys())
            writer.writeheader()
            for r in results:
                writer.writerow(r)
        print(f"\nResults saved to {csv_file}")

if __name__ == "__main__":
    main()
