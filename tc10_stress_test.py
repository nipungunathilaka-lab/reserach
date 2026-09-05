import requests
import time
import statistics
import getpass
from concurrent.futures import ThreadPoolExecutor, as_completed

URL = "http://localhost:5000/api/files/received"

# JWT token is entered at runtime and is not saved in the file
TOKEN = input("Paste Bearer JWT token: ").strip()

HEADERS = {
    "Authorization": f"Bearer {TOKEN}"
}

# Concurrent-user levels to test
LEVELS = [1, 5, 10, 25, 50]

# Same number of total requests for each level
TOTAL_REQUESTS = 100


def make_request():
    start = time.perf_counter()

    try:
        response = requests.get(
            URL,
            headers=HEADERS,
            timeout=30
        )

        latency_ms = (time.perf_counter() - start) * 1000

        return {
            "success": 200 <= response.status_code < 300,
            "status": response.status_code,
            "latency": latency_ms
        }

    except Exception:
        latency_ms = (time.perf_counter() - start) * 1000

        return {
            "success": False,
            "status": "ERROR",
            "latency": latency_ms
        }


def run_test(concurrent_users):

    print("\n" + "=" * 65)
    print(f"TC-10 TEST — CONCURRENT USERS: {concurrent_users}")
    print("=" * 65)

    results = []

    test_start = time.perf_counter()

    with ThreadPoolExecutor(max_workers=concurrent_users) as executor:

        futures = [
            executor.submit(make_request)
            for _ in range(TOTAL_REQUESTS)
        ]

        for future in as_completed(futures):
            results.append(future.result())

    total_time = time.perf_counter() - test_start

    successes = sum(1 for r in results if r["success"])
    failures = TOTAL_REQUESTS - successes

    latencies = [r["latency"] for r in results]

    avg_latency = statistics.mean(latencies)
    max_latency = max(latencies)

    requests_per_second = TOTAL_REQUESTS / total_time

    print(f"Total Requests      : {TOTAL_REQUESTS}")
    print(f"Successful Requests : {successes}")
    print(f"Failed Requests     : {failures}")
    print(f"Average Latency     : {avg_latency:.2f} ms")
    print(f"Maximum Latency     : {max_latency:.2f} ms")
    print(f"Requests / Second   : {requests_per_second:.2f}")

    return {
        "users": concurrent_users,
        "requests": TOTAL_REQUESTS,
        "success": successes,
        "failed": failures,
        "avg_latency": avg_latency,
        "max_latency": max_latency,
        "rps": requests_per_second
    }


print("\nUPCE TC-10 CONCURRENT LOAD TEST")
print(f"Target: {URL}")

all_results = []

for users in LEVELS:

    result = run_test(users)
    all_results.append(result)

    # Avoid immediately jumping to heavier load if the system becomes unstable
    if result["failed"] > TOTAL_REQUESTS * 0.20:
        print("\nMore than 20% requests failed.")
        print("Stopping higher-concurrency tests for safety.")
        break

    time.sleep(3)


print("\n\nFINAL TC-10 SUMMARY")
print("=" * 100)

print(
    f"{'Users':<10}"
    f"{'Requests':<12}"
    f"{'Success':<12}"
    f"{'Failed':<10}"
    f"{'Avg Latency':<18}"
    f"{'Max Latency':<18}"
    f"{'Req/s':<10}"
)

for r in all_results:
    print(
        f"{r['users']:<10}"
        f"{r['requests']:<12}"
        f"{r['success']:<12}"
        f"{r['failed']:<10}"
        f"{r['avg_latency']:<18.2f}"
        f"{r['max_latency']:<18.2f}"
        f"{r['rps']:<10.2f}"
    )