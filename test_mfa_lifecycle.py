import requests
import time

BASE_URL = "http://localhost:5000/api"

def run_tests():
    print("Testing MFA Lifecycle...")
    
    # Pre-MFA Protected Endpoint Attempt
    print("Testing pre-MFA protected endpoint...")
    res = requests.get(f"{BASE_URL}/users/me")
    if res.status_code == 401:
        print("PASS: Protected endpoint rejected without JWT")
    else:
        print("FAIL")

    # Assuming a dev environment where DEV_SHOW_OTP is true
    print("Simulating Login...")
    res = requests.post(f"{BASE_URL}/auth/login", json={"email": "test@example.com", "password": "password123"})
    if res.status_code != 200:
        print("FAIL: Could not log in. Ensure test user exists.")
        return
        
    data = res.json()
    challenge_id = data.get("challenge_id")
    otp = data.get("dev_otp") # Exposed for testing
    
    if not challenge_id or not otp:
        print("FAIL: MFA challenge not returned properly")
        return
        
    print("Testing Wrong OTP...")
    res = requests.post(f"{BASE_URL}/auth/verify-mfa", json={"challenge_id": challenge_id, "otp": "000000"})
    if res.status_code == 401:
        print("PASS: Wrong OTP rejected")
    else:
        print("FAIL")
        
    print("Testing Correct OTP...")
    res = requests.post(f"{BASE_URL}/auth/verify-mfa", json={"challenge_id": challenge_id, "otp": otp})
    if res.status_code == 200 and "access_token" in res.json():
        print("PASS: Correct OTP issued JWT")
        token = res.json()["access_token"]
    else:
        print("FAIL")
        return
        
    print("Testing Reused Challenge...")
    res = requests.post(f"{BASE_URL}/auth/verify-mfa", json={"challenge_id": challenge_id, "otp": otp})
    if res.status_code == 400 and "consumed" in res.text:
        print("PASS: Reused challenge rejected")
    else:
        print("FAIL")

    print("Testing Protected Endpoint After MFA...")
    res = requests.get(f"{BASE_URL}/users/me", headers={"Authorization": f"Bearer {token}"})
    if res.status_code == 200:
        print("PASS: Protected endpoint accepted valid JWT")
    else:
        print("FAIL")

if __name__ == "__main__":
    try:
        run_tests()
    except requests.exceptions.ConnectionError:
        print("NOT TESTED: Node.js server not running (Docker unavailable).")
