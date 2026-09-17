import glob
import importlib
import sys
import os

files = glob.glob("test_*.py") + glob.glob("tests/test_*.py")
for f in files:
    if f == "test_mlkem.py" or f == "tests\\test_mlkem.py": continue
    mod_name = f.replace(".py", "").replace("\\", ".").replace("/", ".")
    print(f"Importing {mod_name}...")
    try:
        importlib.import_module(mod_name)
        print(f"Successfully imported {mod_name}")
    except Exception as e:
        print(f"Failed to import {mod_name}: {e}")
