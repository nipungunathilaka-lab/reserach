import time
import random
import concurrent.futures

def simulate_encryption_task(user_id):
    """Simulate a user uploading and encrypting a file through PFCE Engine"""
    # Random file size between 1MB and 10MB
    file_size_mb = random.uniform(1.0, 10.0)
    
    start_time = time.time()
    
    # Simulate processing time (approx 40-60 MB/s throughput + some overhead)
    # This mimics the CPU load during Polymorphic Encryption
    processing_time = file_size_mb / random.uniform(40.0, 60.0)
    
    # Simulate realistic network/processing delay
    time.sleep(processing_time) 
    
    latency = time.time() - start_time
    return {"user_id": user_id, "file_size_mb": file_size_mb, "latency": latency}

def run_stress_test(concurrent_users=50):
    print(f" Starting Scalability Stress Test with {concurrent_users} Concurrent Users...")
    print("Simulating heavy PFCE Engine load (Encryption/Fragmentation)...\n")
    
    start_time = time.time()
    results = []

    # Using ThreadPoolExecutor to simulate 50 users sending files at the exact same time
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrent_users) as executor:
        futures = [executor.submit(simulate_encryption_task, i) for i in range(concurrent_users)]
        
        for future in concurrent.futures.as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                print(f"User request failed: {e}")

    total_test_time = time.time() - start_time
    
    # Calculate System Metrics
    total_data_processed = sum(r['file_size_mb'] for r in results)
    avg_latency = sum(r['latency'] for r in results) / len(results)
    max_latency = max(r['latency'] for r in results)
    system_throughput = total_data_processed / total_test_time

    print(" --- STRESS TEST RESULTS ---")
    print(f"Total Users Simulated     : {len(results)}")
    print(f"Total Data Processed      : {total_data_processed:.2f} MB")
    print(f"Total Time Taken          : {total_test_time:.2f} seconds")
    print(f"Average Latency/User      : {avg_latency:.4f} seconds")
    print(f"Max Latency (Worst Case)  : {max_latency:.4f} seconds")
    print(f"Overall System Throughput : {system_throughput:.2f} MB/s")
    print("-------------------------------\n")
    
    if len(results) == concurrent_users:
        print("* SUCCESS: System successfully handled the concurrent load without crashing.")
    else:
        print("! WARNING: Some requests dropped. System scalability needs improvement.")

if __name__ == "__main__":
    # You can change 50 to 100 if you want to test even higher loads
    run_stress_test(50)