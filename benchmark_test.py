import os
import time
import requests
import statistics
import shutil
import csv

# 1. Constants for configuration
SIZES_MB = [1, 10, 25, 50, 100, 300]
SIZES_TO_TEST = [size * 1024 * 1024 for size in SIZES_MB]
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

    results = []

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
            print(f"Category {category_mb}MB: {mean_time:.2f} ± {sd_time:.2f} ms")
            results.append({
                "File Size (MB)": category_mb,
                "Mean Latency (ms)": round(mean_time, 2),
                "Standard Deviation (ms)": round(sd_time, 2)
            })
        else:
            print(f"No requests completed for {category_mb}MB category.")
            results.append({
                "File Size (MB)": category_mb,
                "Mean Latency (ms)": "N/A",
                "Standard Deviation (ms)": "N/A"
            })

    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
        
    # Print consolidated report
    print("\n" + "="*60)
    print("CONSOLIDATED FINAL REPORT")
    print("="*60)
    print(f"{'File Size (MB)':<18} | {'Mean Latency (ms)':<20} | {'Std Dev (ms)':<15}")
    print("-" * 60)
    for res in results:
        print(f"{res['File Size (MB)']:<18} | {str(res['Mean Latency (ms)']):<20} | {str(res['Standard Deviation (ms)']):<15}")
    print("="*60)

    # Export to CSV
    csv_file = "benchmark_results.csv"
    with open(csv_file, mode="w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=["File Size (MB)", "Mean Latency (ms)", "Standard Deviation (ms)"])
        writer.writeheader()
        writer.writerows(results)
    
    print(f"\nResults successfully exported to {csv_file}")

if __name__ == "__main__":
    run_benchmark()
