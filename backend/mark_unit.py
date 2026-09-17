import os
import glob

files = glob.glob("test_*.py") + glob.glob("tests/test_*.py")

for filepath in files:
    with open(filepath, "r") as f:
        content = f.read()
        
    if "pytestmark" not in content and "pytest.mark" not in content:
        print(f"Adding unit marker to {filepath}")
        content = "import pytest\npytestmark = [pytest.mark.unit]\n" + content
        with open(filepath, "w") as f:
            f.write(content)
