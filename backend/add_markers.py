import os

markers_map = {
    "pqc": [
        "test_crypto_roundtrip.py",
        "test_forward_secrecy.py",
        "test_mlkem.py",
        "test_pfce.py",
        "test_pfce_stream.py",
        "test_secure_memory.py",
        "test_pqc_required.py",
        "test_continuous_monitor.py" # it loads UPCE which uses PQC
    ],
    "besu": [
        "test_blockchain_audit.py",
        "test_audit_chain_rewrite.py",
        "test_audit_chain_rewrite_script.py",
        "test_audit_immutability.py",
        "test_audit_immutability_script.py",
        "test_audit_chain.py"
    ],
    "clamav": [
        "test_malware_fail_closed.py",
        "test_full_file_scan.py",
        "test_quarantine_lifecycle.py"
    ],
    "network": [
        "test_scapy_visibility.py"
    ]
}

def add_marker(filepath, marker):
    if not os.path.exists(filepath):
        print(f"File {filepath} not found.")
        return
        
    with open(filepath, "r") as f:
        content = f.read()
        
    if "pytestmark =" in content:
        print(f"{filepath} already has pytestmark")
        return
        
    marker_line = f"import pytest\npytestmark = [pytest.mark.integration, pytest.mark.{marker}]\n"
    
    with open(filepath, "w") as f:
        f.write(marker_line + content)
    print(f"Added {marker} marker to {filepath}")

for marker, files in markers_map.items():
    for file in files:
        add_marker(file, marker)
