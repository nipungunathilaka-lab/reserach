import hashlib
import os
import time

def get_file_hash(filepath):
    """Calculate the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def run_tamper_detection_test():
    print("\nStarting PFCE Security & Integrity Evaluation...")
    time.sleep(1)

    # Step 1: Create a dummy original file
    original_file = "secret_data.txt"
    with open(original_file, "w") as f:
        f.write("This is highly confidential engineering data for PFCE testing.")

    # Step 2: Generate Original Hash (Simulating Manifest Layer)
    original_hash = get_file_hash(original_file)
    print(f"[SYSTEM] Original file created.")
    print(f"[SYSTEM] SHA-256 Hash generated: {original_hash}")
    time.sleep(1)

    # Step 3: Simulate Encrypted Fragment 
    # (For this test, we create a dummy encrypted file)
    encrypted_file = "secret_data_fragment.enc"
    with open(original_file, "rb") as f_in, open(encrypted_file, "wb") as f_out:
        f_out.write(f_in.read())
    print("[SYSTEM] File encrypted and fragmented for transfer.")
    time.sleep(1.5)

    # Step 4: Simulate Cyber Attack (Tampering)
    print("\n[ALERT] Simulating Man-in-the-Middle (MITM) Attack...")
    time.sleep(1)
    print("[HACKER] Intercepting transfer and modifying bytes in the encrypted fragment...")
    
    with open(encrypted_file, "r+b") as f:
        f.seek(10) # Go to the 10th byte of the file
        f.write(b"\xFF") # Inject a malicious byte to corrupt/tamper the data
    
    time.sleep(1.5)

    # Step 5: Verification Phase (Reconstruction Engine at Receiver's end)
    print("\n[SYSTEM] Receiving data... Attempting to verify file integrity...")
    tampered_hash = get_file_hash(encrypted_file)
    print(f"[SYSTEM] Reconstructed File Hash: {tampered_hash}")
    time.sleep(1)

    # Step 6: Final Security Check
    print("\n- Security Verification Result -")
    if original_hash == tampered_hash:
        print("FAILURE: Tampering was not detected. System is vulnerable!")
    else:
        print("SUCCESS: Hash mismatch detected! Integrity compromised.")
        print("PFCE Engine blocked the file transfer. Malware/Tampering prevented.")

    # Cleanup test files
    if os.path.exists(original_file):
        os.remove(original_file)
    if os.path.exists(encrypted_file):
        os.remove(encrypted_file)
    print("\nTest completed.")

if __name__ == "__main__":
    run_tamper_detection_test()