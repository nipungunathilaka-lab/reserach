import os
import shutil
from pathlib import Path

# Data directory for quarantine
QUARANTINE_DIR = Path("data/quarantine")

def ensure_quarantine_storage():
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    # Ensure it's not publicly accessible
    # Permissions are handled typically by OS, but we can do a simple check
    try:
        if os.name != 'nt':
            QUARANTINE_DIR.chmod(0o700)
    except Exception:
        pass

def save_to_quarantine(safe_id: str, file_bytes: bytes) -> str:
    ensure_quarantine_storage()
    # Path traversal protection
    safe_id = Path(safe_id).name
    filepath = QUARANTINE_DIR / safe_id
    
    with open(filepath, "wb") as f:
        f.write(file_bytes)
    return str(filepath)

def load_from_quarantine(safe_id: str) -> bytes:
    safe_id = Path(safe_id).name
    filepath = QUARANTINE_DIR / safe_id
    if not filepath.exists():
        raise FileNotFoundError("Quarantined file not found.")
        
    with open(filepath, "rb") as f:
        return f.read()

def delete_from_quarantine(safe_id: str):
    safe_id = Path(safe_id).name
    filepath = QUARANTINE_DIR / safe_id
    if filepath.exists():
        os.remove(filepath)
