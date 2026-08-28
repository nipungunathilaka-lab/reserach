import asyncio
import aiohttp
import time
import psutil
import csv
from datetime import datetime

# ==========================================
# ⚙️ CONFIGURATION
# ==========================================
TARGET_URL = "http://localhost:8000/api/blockchain/logs" 
CONCURRENT_USERS = 50   
REQUESTS_PER_USER = 2   
AUTH_TOKEN = ""         
# ==========================================

async def fetch(session, user_id, req_id):
    start_time = time.time()
    headers = {"Authorization": f"Bearer {AUTH_TOKEN}"} if AUTH_TOKEN else {}
    
    try:
        async with session.get(TARGET_URL, headers=headers) as response:
            status = response.status
            await response.read() 
            latency = (time.time() - start_time) * 1000 
            return {"user": user_id, "req": req_id, "status": status, "latency_ms": round(latency, 2), "error": None}
    except Exception as e:
        latency = (time.time() - start_time) * 1000
        return {"user": user_id, "req": req_id, "status": 500, "latency_ms": round(latency, 2), "error": str(e)}

async def run_stress_test():
    print(f"\nStarting PFCE Stress Test...")
    print(f"Concurrent Users: {CONCURRENT_USERS}")
    print(f"Total Requests: {CONCURRENT_USERS * REQUESTS_PER_USER}")
    print(f"Target URL: {TARGET_URL}\n")
    
    start_time = time.time()
    results = []
    
    cpu_start = psutil.cpu_percent(interval=None)
    ram_start = psutil.virtual_memory().percent

    async with aiohttp.ClientSession() as session:
        tasks = []
        for user_id in range(1, CONCURRENT_USERS + 1):
            for req_id in range(1, REQUESTS_PER_USER + 1):
                tasks.append(fetch(session, user_id, req_id))
        
        responses = await asyncio.gather(*tasks)
        results.extend(responses)

    total_time = time.time() - start_time
    
    cpu_end = psutil.cpu_percent(interval=None)
    ram_end = psutil.virtual_memory().percent

    successful_reqs = [r for r in results if r["status"] == 200]
    failed_reqs = [r for r in results if r["status"] != 200]
    latencies = [r["latency_ms"] for r in successful_reqs]
    
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    max_latency = max(latencies) if latencies else 0
    min_latency = min(latencies) if latencies else 0
    throughput = len(successful_reqs) / total_time if total_time > 0 else 0

    print("Test Completed!\n")
   
    print("PERFORMANCE METRICS")
  
    print(f"Total Time Taken : {round(total_time, 2)} seconds")
    print(f"Throughput       : {round(throughput, 2)} requests/sec")
    print(f"Average Latency  : {round(avg_latency, 2)} ms")
    print(f"Max Latency      : {max_latency} ms")
    print(f"Min Latency      : {min_latency} ms")
    print(f"Success Rate     : {len(successful_reqs)} / {len(results)}")
    print(f"Failed Requests  : {len(failed_reqs)}")
  
    print("RESOURCE UTILIZATION")
   
    print(f"CPU Usage Change : {cpu_start}% -> {cpu_end}%")
    print(f"RAM Usage Change : {ram_start}% -> {ram_end}%")


    csv_filename = f"pfce_benchmark_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(csv_filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["User_ID", "Request_ID", "Status_Code", "Latency(ms)", "Error"])
        for r in results:
            writer.writerow([r["user"], r["req"], r["status"], r["latency_ms"], r["error"]])
    
    print(f"\n📂 Detailed results saved to: {csv_filename}")

if __name__ == "__main__":
    asyncio.run(run_stress_test())
