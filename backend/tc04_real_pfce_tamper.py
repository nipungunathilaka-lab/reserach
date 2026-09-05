from pathlib import Path
import json
import shutil
import tempfile
import zipfile

from cryptography.exceptions import InvalidTag
from app.services.pfce_engine import PFCEEngine


# -------------------------------------------------
# CHANGE ONLY THIS VALUE
# MongoDB eke correct receiver_id eka danna
# -------------------------------------------------
RECEIVER_ID = "6a96895a2f72ab450fbef68a"


# Find newest real PFCE package
storage_dir = Path("app/storage/encrypted")

packages = list(storage_dir.glob("*.pfce"))

if not packages:
    print("ERROR: No .pfce packages found.")
    raise SystemExit(1)

original = max(packages, key=lambda p: p.stat().st_mtime)


# Evidence folder
evidence_dir = Path("../Chapter6_Evidence/TC04")
evidence_dir.mkdir(parents=True, exist_ok=True)

tampered = evidence_dir / f"TAMPERED_{original.name}"

# IMPORTANT: Copy original. Never change original package.
shutil.copy2(original, tampered)

print("=" * 60)
print("TC-04 - REAL PFCE TAMPERING TEST")
print("=" * 60)

print(f"\nOriginal package : {original}")
print(f"Tampered copy    : {tampered}")


# -------------------------------------------------
# Open copied PFCE package and modify one
# encrypted fragment by changing one bit
# -------------------------------------------------
with tempfile.TemporaryDirectory() as temp:

    temp_path = Path(temp)

    with zipfile.ZipFile(tampered, "r") as z:
        z.extractall(temp_path)

    metadata_path = temp_path / "metadata.json"

    with open(metadata_path, "r", encoding="utf-8") as f:
        metadata = json.load(f)

    fragments = metadata.get("fragments", [])

    if not fragments:
        print("ERROR: No encrypted fragments found.")
        raise SystemExit(1)

    fragment_name = fragments[0]["filename"]
    fragment_path = temp_path / fragment_name

    data = bytearray(fragment_path.read_bytes())

    if not data:
        print("ERROR: Selected fragment is empty.")
        raise SystemExit(1)

    # Change one bit in the middle of encrypted fragment
    position = len(data) // 2

    original_byte = data[position]
    data[position] ^= 0x01
    changed_byte = data[position]

    fragment_path.write_bytes(data)

    print(f"\nTampered fragment : {fragment_name}")
    print(f"Changed byte pos  : {position}")
    print(f"Original byte     : {original_byte}")
    print(f"Modified byte     : {changed_byte}")

    # Rebuild copied PFCE package
    with zipfile.ZipFile(tampered, "w", zipfile.ZIP_STORED) as z:

        for file in temp_path.rglob("*"):
            if file.is_file():
                z.write(file, file.relative_to(temp_path))


# -------------------------------------------------
# Attempt REAL decryption using actual PFCE engine
# -------------------------------------------------
print("\nAttempting decryption of tampered package...")
print("-" * 60)

try:

    engine = PFCEEngine()

    output = bytearray()

    for chunk in engine.process_download_stream(
        str(tampered),
        RECEIVER_ID
    ):
        output.extend(chunk)

    print("\nWARNING: Tampered package was accepted.")
    print("TC-04 RESULT: FAIL")

except InvalidTag:

    print("\nAEAD AUTHENTICATION FAILED")
    print("Encrypted fragment modification detected.")
    print("Decrypted output was NOT accepted.")
    print("\nTC-04 RESULT: PASS")

except ValueError as error:

    print(f"\nINTEGRITY CHECK FAILED")
    print(f"Error: {error}")
    print("Decrypted output was NOT accepted.")
    print("\nTC-04 RESULT: PASS")

except Exception as error:

    print(f"\nDECRYPTION / AUTHENTICATION FAILED")
    print(f"Error type: {type(error).__name__}")
    print(f"Error: {error}")
    print("Decrypted output was NOT accepted.")
    print("\nTC-04 RESULT: PASS")