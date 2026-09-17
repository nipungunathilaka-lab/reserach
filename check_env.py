import os, sys, platform, subprocess
print(f'OS: {platform.system()} {platform.release()}')
print(f'Python: {sys.version}')
print(f'Arch: {platform.architecture()}')
try:
    import oqs
    print('oqs imported successfully')
except Exception as e:
    print(f'oqs import failed: {type(e).__name__}: {e}')

try:
    print(f'CMake: {subprocess.run(["cmake", "--version"], capture_output=True, text=True).stdout.splitlines()[0]}')
except Exception:
    print('CMake: Not Found')
    
try:
    print(f'Git: {subprocess.run(["git", "--version"], capture_output=True, text=True).stdout.splitlines()[0]}')
except Exception:
    print('Git: Not Found')
